(defpackage #:mtgnet.encryption
  (:use #:cl #:mtgnet.crypto)
  (:import-from #:mtgnet.crypto
                #:free-secret)
  (:export #:+secret-size+
           #:+publickey-size+
           #:free-secret
           #:generate-secret
           #:generate-encoded-secret
           #:decode-secret-key
           #:compute-public-key)
  (:export #:encrypted-rpc-connection
           #:make-encrypted-connection
           #:remote-key
           #:perform-handshake))

(in-package #:mtgnet.encryption)

(defconstant +secret-size+ (mtgnet.crypto:sign-secretkey-bytes))
(defconstant +publickey-size+ (mtgnet.crypto:sign-publickey-bytes))

(defun generate-secret ()
  (mtgnet.crypto:generate-signing-secret))

(defun generate-encoded-secret ()
  (mtgnet.crypto:generate-encoded-signing-secret))

(defun decode-secret-key (secret)
  (check-type secret string)
  (flet ((base64-length (byte-count)
           (* 4 (ceiling byte-count 3))))
    (unless (= (length secret)
               (base64-length +secret-size+))
      (error "Encoded key ~S (~S bytes) is not of the right size to be a secret key (expected ~S bytes)."
             secret
             (length secret)
             (base64-length +secret-size+)))
    (decode-secret secret)))

(defun compute-public-key (secret)
  (mtgnet.crypto:compute-signing-public-key secret))

;; Encrypting/decrypting connection for mtgnet.
(defclass encrypted-rpc-connection (mtgnet-sys:rpc-connection)
  ((secret-key :initarg :secret-key :accessor secret-key)
   (public-key :initarg :public-key :accessor public-key)
   (ephemeral-keypair :initform nil :accessor ephemeral-keypair)
   (key :initform nil :accessor session-key)
   (authorized-keys :initarg :authorized-keys :accessor authorized-keys)
   (server-key :initform nil :accessor remote-key))
  (:default-initargs :authorized-keys '())
  (:documentation "An MTGNET connection class that encrypts data during transmission."))

(defun make-encrypted-connection (framer transport secret-key &optional (authorized-keys '(t)))
  (check-type framer mtgnet-sys:data-framer)
  (check-type transport mtgnet-sys:transport)
  (check-type secret-key (or string cffi:foreign-pointer))
  (check-type authorized-keys list)
  (let ((secret (etypecase secret-key
                  (string (decode-secret-key secret-key))
                  (cffi:foreign-pointer secret-key))))
    (make-instance 'encrypted-rpc-connection
                   :framer framer
                   :transport transport
                   :public-key (compute-signing-public-key secret)
                   :secret-key secret
                   :authorized-keys authorized-keys)))

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
  encrypted with the session key and prepended with a nonce."
  (check-type data (vector (unsigned-byte 8)))
  (let ((buf (cffi:make-shareable-byte-vector (+ (box-noncebytes)
                                                 (box-macbytes)
                                                 (length data)))))
    ;; Store the message in the output buffer (will be overwritten
    ;; with the encrypted data).
    (replace buf data :start1 (box-noncebytes))
    (cffi:with-pointer-to-vector-data (buf-ptr buf)
      (let ((output-ptr (cffi:inc-pointer buf-ptr (box-noncebytes)))
            (key (session-key con)))
        ;; Generate a nonce to use for the encryption.
        (cr:randombytes-buf buf-ptr (cr:crypto-box-noncebytes))
        (with-secret (key)
          (let ((res (crypto-box-easy-afternm output-ptr
                                              output-ptr
                                              (length data)
                                              buf-ptr
                                              key)))
            (unless (= res 0)
              (error "Error encrypting data (code ~A)." res))))))
    buf))

(defmethod decrypt-data ((con encrypted-rpc-connection) bytes)
  "Decrypt BYTES as sent over CON. If BYTES is valid, it will be a
byte array of the remote nonce used to encrypt the data followed by
the encrypted data."
  (assert (>= (length bytes) (+ (box-noncebytes)
                                (box-macbytes)))
          ()
          "Invalid encrypted data (too short).")
  (let ((bytes-buf (cffi:make-shareable-byte-vector (length bytes))))
    ;; FIXME: need to copy here because we don't know that the input
    ;; is shareable.
    (replace bytes-buf bytes)
    (cffi:with-pointer-to-vector-data (nonce-ptr bytes-buf)
      (let ((data-ptr (cffi:inc-pointer nonce-ptr (box-noncebytes)))
            (key (session-key con)))
        (with-secret (key)
          ;; Decrtypt the data in-place.
          (let ((res (crypto-box-open-easy-afternm data-ptr
                                                   data-ptr
                                                   (- (length bytes)
                                                      (box-noncebytes))
                                                   nonce-ptr
                                                   key)))
            (unless (= res 0)
              (error "Error decrypting data (code ~A)." res))))))
    ;; Mehhhh, more copying (need to ignore the nonce and any trailing
    ;; junk from decrypting in-place.
    (subseq bytes-buf
            (box-noncebytes)
            (- (length bytes)
               (box-macbytes)))))

(defmethod mtgnet-sys:disconnect :before ((con encrypted-rpc-connection) &key abort)
  (declare (ignore abort))
  (when (ephemeral-keypair con)
    (destroy-keypair! (ephemeral-keypair con))
    (setf (ephemeral-keypair con) nil))
  (when (session-key con)
    (free-secret (session-key con))
    (setf (session-key con) nil))
  (when (remote-key con)
    (setf (remote-key con) nil)))

(declaim (inline send-handshake-data))
(defun send-handshake-data (con)
  "Send the handshake data (signing key and (signed) ephemeral public key) over CON."
  (let ((signed-data (signed-bytes (secret-key con) (keypair-public (ephemeral-keypair con)))))
    (mtgnet-sys:send-frame con (public-key con) signed-data)))

(defun read-handshake-data (con)
  "Read handshake data from the remote end of CON, and return the
remote nonce and public key as multiple values."
  (blackbird:multiple-promise-bind (data) (mtgnet-sys:receive-frame con)
    (let ((expected-size (+ (sign-publickey-bytes) (box-publickey-bytes) (signature-bytes))))
      (assert (= (length data) expected-size)
              ()
              "Data is the wrong size for a handshake (~S, expected ~S)"
              (length data)
              expected-size)
      (let ((signing-key (make-array (sign-publickey-bytes)
                                     :element-type (array-element-type data)
                                     :displaced-to data))
            (signed-data (make-array (+ (box-publickey-bytes) (signature-bytes))
                                     :element-type (array-element-type data)
                                     :displaced-to data
                                     :displaced-index-offset (sign-publickey-bytes))))
        (values signing-key (extract-signed-bytes signing-key signed-data))))))

(defun generate-session-key (con secret public-key)
  "Generate a new session key for CON using the local SECRET and the remote PUBLIC-KEY."
  (declare (ignore con))
  ;; FIXME: this is kind of weird typing just to use the memory
  ;; locking business.
  (check-type secret (cffi:foreign-pointer))
  (ecdh-session-key secret public-key))

(define-condition client-not-authorized (error)
  ((key :initarg :key :accessor public-key)))

(defun perform-handshake (con)
  (check-type con encrypted-rpc-connection)
  ;; Generate a new ephemeral keypair for the session. Servers don't
  ;; call CONNECT, so we need to do this here.
  (setf (ephemeral-keypair con) (generate-ecdh-keypair))
  (blackbird:chain (send-handshake-data con)
    (:attach ()
             (read-handshake-data con))
    (:attach (signing-key key)
             (unless (or (member t (authorized-keys con))
                         (member signing-key (authorized-keys con) :test #'equalp))
               (error 'client-not-authorized :key signing-key))
             (setf (session-key con) (generate-session-key con
                                                           (keypair-secret (ephemeral-keypair con))
                                                           key)
                   (remote-key con) signing-key))))

(defmethod mtgnet-sys:connect :around ((con encrypted-rpc-connection))
  (blackbird:chain (call-next-method)
    (:attach (socket)
             (blackbird:chain (perform-handshake con)
               (:attach () socket)))))

(defmethod mtgnet-sys:send-response ((con encrypted-rpc-connection) response)
  (check-type response mtgnet-sys:rpc-response)
  (let* ((response-message (with-output-to-string (json:*json-output*)
                             (mtgnet-sys:marshall-rpc-response response)))
         (response-data (trivial-utf-8:string-to-utf-8-bytes response-message))
         (bytes (encrypt-data con response-data)))
    (mtgnet-sys:send-frame con bytes)))

(defmethod mtgnet-sys:read-response ((con encrypted-rpc-connection))
  (blackbird:multiple-promise-bind (bytes) (mtgnet-sys:receive-frame con)
    (multiple-value-bind (data) (decrypt-data con bytes)
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
    (multiple-value-bind (data) (decrypt-data con bytes)
      (mtgnet-sys:unmarshall-rpc-request (trivial-utf-8:utf-8-bytes-to-string data)))))
