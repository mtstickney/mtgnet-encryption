(defpackage #:mtgnet.encryption
  (:use #:cl #:mtgnet.crypto)
  (:export #:encrypted-rpc-connection
           #:make-encrypted-connection))

(in-package #:mtgnet.encryption)

;; Encrypting/decrypting connection for mtgnet.
(defclass encrypted-rpc-connection (mtgnet-sys:rpc-connection)
  ((local-nonce :accessor local-nonce)
   (remote-nonce :accessor remote-nonce)
   (secret-key :initarg :secret-key :accessor secret-key)
   (public-key :initarg :public-key :accessor public-key)
   (key :accessor session-key)
   (authorized-keys :initarg :authorized-keys :accessor authorized-keys))
  (:default-initargs :authorized-keys '())
  (:documentation "An MTGNET connection class that encrypts data during transmission."))

(defmethod initialize-instance :after ((con encrypted-rpc-connection) &rest args)
  (declare (ignore args))
  ;; These don't actually need to be shareable, as we compute the
  ;; shared nonce in a new buffer on {en,de}cryption.
  (setf (local-nonce con) (cffi:make-shareable-byte-vector +nonce-bytes+)
        (remote-nonce con) (cffi:make-shareable-byte-vector +nonce-bytes+)))

(defun make-encrypted-connection (framer transport public-key secret-key &optional (authorized-keys '(t)))
  (check-type framer mtgnet-sys:data-framer)
  (check-type transport mtgnet-sys:transport)
  (check-type public-key (vector (unsigned-byte 8)))
  (check-type secret-key cffi:foreign-pointer)
  (check-type authorized-keys list)
  (make-instance 'encrypted-rpc-connection
                 :framer framer
                 :transport transport
                 :public-key public-key
                 :secret-key secret-key
                 :authorized-keys authorized-keys))

(defgeneric encrypt-data (con data)
  (:documentation "Encrypt DATA to send over CON. Returns a byte array
  suitable for decrypting with DECRYPT-DATA."))

(defgeneric decrypt-data (con bytes)
  (:documentation "Decrypt data that has been sent over CON. BYTES
  should be a byte array of the form returned by ENCRYPT-DATA. Methods
  of this function may return other data as additional values."))

;; TODO: Add condition types.


(defmethod encrypt-data ((con encrypted-rpc-connection) data)
  "Encrypt DATA for sending over CON. Returns a byte array of the DATA
  encrypted with the session key and the shared nonce (local XOR
  remote). Note that the local nonce needs to be prepended before
  transmitting this."
  (check-type data (vector (unsigned-byte 8)))
  ;; TODO: we could just maintain the shared nonce in the connection
  ;; with some state tracking instead of creating a new buffer every
  ;; time we encrypt something.
  (let ((buf (cffi:make-shareable-byte-vector (+ +nonce-bytes+
                                                 (secretbox-macbytes)
                                                 (length data))))
        (data-buf (cffi:make-shareable-byte-vector (length data))))
    ;; FIXME: we don't know that the input is shareable, so we have to
    ;; copy here. Might be able to be tricky and encrypt it in-place
    ;; in the result buffer instead of creating a separate one here.
    (replace data-buf data)

    ;; Compute the shared nonce. Note that we're going to reuse part
    ;; of the output buffer to hold the shared nonce, and later
    ;; replace it with the local one. Kind of icky, but it avoids
    ;; consing up a temporary array.
    (map-into buf #'logxor (local-nonce con) (remote-nonce con))

    (cffi:with-pointer-to-vector-data (key (session-key con))
      (cffi:with-pointer-to-vector-data (data-buf-ptr data-buf)
        (cffi:with-pointer-to-vector-data (nonce-ptr buf)
          (let* ((buf-ptr (cffi:make-pointer (+ (cffi:pointer-address nonce-ptr)
                                                +nonce-bytes+)))
                 (res (cr:crypto-secretbox-easy buf-ptr
                                                data-buf-ptr
                                                (length data-buf)
                                                nonce-ptr
                                                key)))
            (unless (= res 0)
              (error "Error encrypting data, return code ~S." res))
            ;; Now that we're done encrypting, replace the shared
            ;; nonce with the local one for transmission.
            (replace buf (local-nonce con))))))
    buf))

(defmethod decrypt-data ((con encrypted-rpc-connection) bytes)
  "Decrypt BYTES as sent over CON. If BYTES is valid, it will be a
byte array of the remote nonce used to encrypt the data followed by
the encrypted data. Note that this means DECRYPT-DATA can't process
the output of ENCRYPT-DATA directly."
  (assert (>= (length bytes) (+ +nonce-bytes+ (secretbox-macbytes)))
          ()
          "Invalid encrypted data (too short).")
  (let ((nonce-buf (cffi:make-shareable-byte-vector +nonce-bytes+))
        (data-buf (cffi:make-shareable-byte-vector (- (length bytes) +nonce-bytes+ (secretbox-macbytes))))
        (bytes-buf (cffi:make-shareable-byte-vector (length bytes))))
    ;; FIXME: we have to copy here because we don't know that the
    ;; input is shareable.
    (replace bytes-buf bytes)

    ;; TODO: This should probably be maintained in the connection, not
    ;; consed up every time we decrypt.
    ;; Compute the shared nonce from the input and our local nonce.
    (map-into nonce-buf #'logxor bytes (local-nonce con))

    (cffi:with-pointer-to-vector-data (key (session-key con))
      (cffi:with-pointer-to-vector-data (nonce nonce-buf)
        (cffi:with-pointer-to-vector-data (bytes-buf-ptr bytes-buf)
          (cffi:with-pointer-to-vector-data (data-ptr data-buf)
            (let* ((new-ptr (cffi:make-pointer (+ (cffi:pointer-address bytes-buf-ptr) +nonce-bytes+)))
                   (res (cr:crypto-secretbox-open-easy data-ptr new-ptr (- (length bytes) +nonce-bytes+) nonce key)))
              (unless (= res 0)
                (error "Error decrypting data, error code ~S." res)))))))

    ;; Note that the reference to the nonce buf should be dropped
    ;; quickly so that the whole response isn't held in memory.
    (values data-buf (make-array +nonce-bytes+
                                 :element-type (array-element-type bytes)
                                 :displaced-to bytes))))

(defmethod generate-nonce-into! (buf)
  "Generate a new nonce and store the data in BUF."
  (assert (>= (length buf) +nonce-bytes+) ()  "Buffer is too short to store nonce data.")
  (cffi:with-pointer-to-vector-data (buf-ptr buf)
    ;; A pointer, because size_t gets translated as a pointer in
    ;; cl-sodium. Not actually a pointer, just a type wrapper.
    (let ((ptr (cffi:make-pointer +nonce-bytes+)))
      (cr:randombytes-buf buf-ptr ptr)
      (values))))

(defmethod mtgnet-sys:connect :before ((con encrypted-rpc-connection))
  ;; Generate a new nonce before connecting.
  (generate-nonce-into! (local-nonce con)))

(declaim (inline send-handshake-data))
(defun send-handshake-data (con nonce public-key)
  "Send the handshake data (local nonce and public key) over CON."
  (mtgnet-sys:send-frame con nonce public-key))

(defun read-handshake-data (con)
  "Read handshake data from the remote end of CON, and return the
remote nonce and public key as multiple values."
  (blackbird:multiple-promise-bind (data) (mtgnet-sys:receive-frame con)
    (let ((expected-size (+ +nonce-bytes+ (box-publickey-bytes))))
      (assert (= (length data) expected-size)
              ()
              "Data is the wrong size for a handshake (~S, expected ~S)"
              (length data)
              expected-size)
      (let ((remote-public-key (cffi:make-shareable-byte-vector (box-publickey-bytes)))
            (nonce (make-array +nonce-bytes+
                               :element-type (array-element-type data)
                               :displaced-to data)))
        (replace remote-public-key data :start2 +nonce-bytes+)
        (values nonce remote-public-key)))))

(defun generate-session-key (con secret public-key)
  "Generate a new session key for CON using the local SECRET and the remote PUBLIC-KEY."
  ;; FIXME: this is kind of weird typing just to use the memory
  ;; locking business.
  (check-type secret (cffi:foreign-pointer))
  (with-secret (secret)
    (cffi:with-pointer-to-vector-data (pk-data public-key)
      (ecdh-session-key secret pk-data (local-nonce con) (remote-nonce con)))))

(define-condition client-not-authorized (error)
  ((key :initarg :key :accessor public-key)))

(defun perform-handshake (con)
  (check-type con encrypted-rpc-connection)
  (blackbird:chain (send-handshake-data con (local-nonce con) (public-key con))
    (:attach ()
             (read-handshake-data con))
    (:attach (nonce key)
             (unless (or (member t (authorized-keys con))
                         (member key (authorized-keys con) :test #'equalp))
               (error 'client-not-authorized :key key))
             (replace (remote-nonce con) nonce)
             (setf (session-key con) (generate-session-key con (secret-key con) key)))))

(defmethod mtgnet-sys:connect :around ((con encrypted-rpc-connection))
  (blackbird:multiple-promise-bind (socket) (call-next-method)
    (perform-handshake con)
    socket))

(defmethod mtgnet-sys:send-response ((con encrypted-rpc-connection) response)
  (check-type response mtgnet-sys:rpc-response)
  (let* ((response-message (with-output-to-string (json:*json-output*)
                             (mtgnet-sys:marshall-rpc-response response)))
         (response-data (trivial-utf-8:string-to-utf-8-bytes response-message))
         (bytes (encrypt-data con response-data)))
    (mtgnet-sys:send-frame con bytes)))

(defmethod mtgnet-sys:read-response ((con encrypted-rpc-connection))
  (blackbird:multiple-promise-bind (bytes) (mtgnet-sys:receive-frame con)
    (multiple-value-bind (data remote-nonce) (decrypt-data con bytes)
      ;; Save the remote nonce
      (replace (remote-nonce con) remote-nonce)
      (mtgnet-sys:unmarshall-rpc-response (trivial-utf-8:utf-8-bytes-to-string data)))))

(defmethod mtgnet-sys:send-request ((con encrypted-rpc-connection) request)
  (check-type request mtgnet-sys:rpc-request)
  (let* ((request-message (with-output-to-string (json:*json-output*)
                            (mtgnet-sys:marshall-rpc-request request)))
         (request-data (trivial-utf-8:string-to-utf-8-bytes request-message))
         (bytes (encrypt-data con request-data)))
    (mtgnet-sys:send-frame con bytes)))

(defmethod mtgnet-sys:read-request ((con encrypted-rpc-connection))
  (blackbird:multiple-promise-bind (bytes) (mtgnet-sys:receive-frame con)
    (multiple-value-bind (data remote-nonce) (decrypt-data con bytes)
      ;; Save the remote nonce
      (replace (remote-nonce con) remote-nonce)
      (mtgnet-sys:unmarshall-rpc-request (trivial-utf-8:utf-8-bytes-to-string data)))))

;;; INVARIANT: A send syncs the local resource's nonce with the remote
;; end, which will use it to send data back to us. Therefore, a
;; resource's nonce must not change between a send and a subsequent
;; receive (unless the original is saved).

;; Client generates a new nonce BEFORE sending a request.
(defmethod mtgnet-sys:send-request :before ((con encrypted-rpc-connection) request)
  (declare (ignore request))
  (generate-nonce-into! (local-nonce con)))

;; Server generates a new nonce BEFORE sending a response.
(defmethod mtgnet-sys:send-response :before ((con encrypted-rpc-connection) response)
  (declare (ignore response))
  (generate-nonce-into! (local-nonce con)))

;;;;
