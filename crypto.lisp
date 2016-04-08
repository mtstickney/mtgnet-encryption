(defpackage #:mtgnet.crypto
  (:use #:cl)
  ;; Wrappers for sodium functions
  (:export #:box-publickey-bytes
           #:box-noncebytes
           #:box-macbytes
           #:crypto-box-easy-afternm
           #:crypto-box-open-easy-afternm)
  (:export #:with-secret
           #:sign-publickey-bytes
           #:sign-secretkey-bytes
           #:signature-bytes
           #:ecdh-session-key
           #:generate-ecdh-secret
           #:compute-ecdh-public-key
           #:generate-ecdh-keypair
           #:generate-signing-secret
           #:compute-signing-public-key
           #:generate-signing-keypair
           #:destroy-keypair!
           #:keypair-secret
           #:keypair-public
           #:generate-encoded-signing-secret
           #:free-secret
           #:decode-secret-key
           #:signed-bytes
           #:invalid-signature-error
           #:extract-signed-bytes))

(in-package #:mtgnet.crypto)

;; Wrappers for cl-sodium functions, because why would we have
;; reasonable return types?

(defun scalarmult-bytes ()
  (cffi:pointer-address (cr:crypto-scalarmult-bytes)))

(defun box-publickey-bytes ()
  (cffi:pointer-address (cr:crypto-box-publickeybytes)))

(defun box-secretkey-bytes ()
  (cffi:pointer-address (cr:crypto-box-secretkeybytes)))

(defun box-noncebytes ()
  (cffi:pointer-address (cr:crypto-box-noncebytes)))

(defun box-macbytes ()
  (cffi:pointer-address (cr:crypto-box-macbytes)))

(cffi:defcfun ("crypto_box_easy_afternm" #.(sodium::lispify "crypto_box_easy_afternm" 'function)) :int
  (c :pointer)
  (m :pointer)
  (mlen :ullong)
  (n :pointer)
  (k :pointer))

(cffi:defcfun ("crypto_box_open_easy_afternm" #.(sodium::lispify "crypto_box_open_easy_afternm" 'function)) :int
  (m :pointer)
  (c :pointer)
  (clen :ullong)
  (n :pointer)
  (k :pointer))

(defun sign-publickey-bytes ()
  (cffi:pointer-address (cr:crypto-sign-publickeybytes)))

(defun sign-secretkey-bytes ()
  (cffi:pointer-address (cr:crypto-sign-secretkeybytes)))

(defun signature-bytes ()
  (cffi:pointer-address (cr:crypto-sign-bytes)))

(cffi:defcfun ("crypto_sign_ed25519_sk_to_pk" #. (sodium::lispify "crypto_sign_ed25519_sk_to_pk" 'function)) :int
  (public :pointer)
  (secret :pointer))

(cffi:defcfun ("sodium_malloc" #.(sodium::lispify "cr_sodium_malloc" 'function)) :pointer
  (size :pointer) ;; sigh....
  )

(defun sodium-malloc (size)
  (cr-sodium-malloc (cffi:make-pointer size)))

(cffi:defcfun ("sodium_free" #.(sodium::lispify "sodium_free" 'function)) :void
  (ptr :pointer))

(cffi:defcfun ("sodium_mprotect_noaccess" #.(sodium::lispify "sodium_mprotect_noaccess" 'function)) :int
  (ptr :pointer))

(cffi:defcfun ("sodium_mprotect_readonly" #.(sodium::lispify "sodium_mprotect_readonly" 'function)) :int
  (ptr :pointer))

(defmacro with-secret ((secret) &body body)
  (let ((secret-var (gensym "SECRET")))
    `(let ((,secret-var ,secret))
       (check-type ,secret-var cffi:foreign-pointer)
       (unwind-protect
            (progn
              (sodium-mprotect-readonly ,secret-var)
              ,@body)
         (sodium-mprotect-noaccess ,secret-var)))))

(defun call-with-secret-buffer (size thunk)
  (let* ((size-ptr (cffi:make-pointer size))
         (ptr (sodium-malloc size))
         (ok nil))
    (unwind-protect
         (progn
           (when (cffi:null-pointer-p ptr)
             (error "Unable to allocate secure memory for secret key."))
           (cr:randombytes-buf ptr size-ptr)
           (funcall thunk ptr)
           (sodium-mprotect-noaccess ptr)
           (setf ok t))
      (unless ok
        (sodium-free ptr)
        (setf ptr (cffi:null-pointer))))
    ptr))

(defmacro with-new-secret-buffer ((ptr-var size) &body body)
  `(call-with-secret-buffer ,size (lambda (,ptr-var) ,@body)))

(defun free-secret (secret)
  (check-type secret cffi:foreign-pointer)
  (sodium-free secret))

(defun destroy-keypair! (keypair)
  "Deallocate KEYPAIR and set both components to NIL to avoid accidental use after freeing."
  (free-secret (car keypair))
  (setf (car keypair) nil
        (cdr keypair) nil))

(defun keypair-secret (keypair)
  (car keypair))

(defun keypair-public (keypair)
  (cdr keypair))

(defun generate-ecdh-secret ()
  (let* ((size-ptr (cr:crypto-box-secretkeybytes))
         (size (cffi:pointer-address size-ptr)))
    (with-new-secret-buffer (ptr size)
      (cr:randombytes-buf ptr size-ptr))))

(defun compute-ecdh-public-key (ecdh-secret)
  (check-type ecdh-secret cffi:foreign-pointer)
  (assert (= (box-publickey-bytes) (scalarmult-bytes)) ())
  (let ((public-key (cffi:make-shareable-byte-vector (scalarmult-bytes))))
    (cffi:with-pointer-to-vector-data (public-key-ptr public-key)
      (with-secret (ecdh-secret)
        (cr:crypto-scalarmult-base public-key-ptr ecdh-secret)))
    public-key))

(defun generate-ecdh-keypair ()
  "Return an ECDH keypair as a CONS whose first element is the secret
and whose CDR is the public key.

The secret is represented as a memory-protected secret object suitable
for use with WITH-SECRET, and the public key is a byte vector."
  (let ((secret (generate-ecdh-secret)))
    (cons secret (compute-ecdh-public-key secret))))

(defun generate-signing-keypair ()
  (let* ((size (sign-secretkey-bytes))
         (public-key (cffi:make-shareable-byte-vector (sign-publickey-bytes))))
    (cffi:with-pointer-to-vector-data (public-key-ptr public-key)
      (cons (with-new-secret-buffer (secret-ptr size)
              (unless (= 0 (cr:crypto-sign-keypair public-key-ptr secret-ptr))
                (error "Error generating crypto-box keypair.")))
            public-key))))

(defun generate-signing-secret ()
  (keypair-secret (generate-signing-keypair)))

(defun compute-signing-public-key (signing-secret)
  (check-type signing-secret cffi:foreign-pointer)
  (let ((public-key (cffi:make-shareable-byte-vector (sign-publickey-bytes))))
    (cffi:with-pointer-to-vector-data (public-key-ptr public-key)
      (with-secret (signing-secret)
        (unless (= 0 (crypto-sign-ed-25519-sk-to-pk public-key-ptr signing-secret))
          (error "Error deriving public key from signing secret."))))
    public-key))

(defun ecdh-session-key (secret public)
  "Return a precomputed session key based on an ECDH exchange."
  (check-type secret cffi:foreign-pointer)
  (let* ((size-ptr (cr:crypto-box-beforenmbytes))
         (size (cffi:pointer-address size-ptr)))
    (cffi:with-pointer-to-vector-data (public-ptr public)
      (with-new-secret-buffer (key-ptr size)
        (with-secret (secret)
          (unless (= 0 (cr:crypto-box-beforenm key-ptr public-ptr secret))
            (error "Error precomputing shared crypto-box key.")))))))

(defun generate-encoded-signing-secret ()
  (let ((buf (cffi:make-shareable-byte-vector (sign-secretkey-bytes)))
        (secret (generate-signing-secret)))
    (with-secret (secret)
      (dotimes (i (length buf))
        (setf (aref buf i)
              (cffi:mem-aref secret :uchar i)))
      (prog1 (base64:usb8-array-to-base64-string buf)
        ;; At least attempt to scrub intermediate data.
        (dotimes (i (length buf))
          (setf (aref buf i) 0))))))

(defun decode-secret-key (encoded-key)
  "Decode and return a new secret key from the base64-encoded string ENCODED-KEY."
  (check-type encoded-key string)
  (let* ((data (base64:base64-string-to-usb8-array encoded-key)))
    (with-new-secret-buffer (ptr (length data))
      (loop for byte across data
         for i from 0
         do (setf (cffi:mem-aref ptr :uchar i) byte
                  ;; Clear the data in-memory. Imperfect protection,
                  ;; but better than nothing.
                  (aref data i) 0)))))

(defun signed-bytes (signing-secret msg)
  (check-type signing-secret cffi:foreign-pointer)
  (let ((msg-buf (cffi:make-shareable-byte-vector (length msg)))
        (signed-buf (cffi:make-shareable-byte-vector (+ (length msg) (signature-bytes)))))
    (replace msg-buf msg)
    (cffi:with-pointer-to-vector-data (msg-ptr msg-buf)
      (cffi:with-pointer-to-vector-data (signed-ptr signed-buf)
        (with-secret (signing-secret)
          (unless (= (cr:crypto-sign signed-ptr (cffi:null-pointer)
                                     msg-ptr (length msg-buf)
                                     signing-secret)
                     0)
            (error "Error signing data.")))))
    signed-buf))

(define-condition invalid-signature-error (error)
  ()
  (:report (lambda (c s)
             (declare (ignore c))
             (format s "Signature is invalid."))))

(defun extract-signed-bytes (signing-key signed-bytes)
  (let ((buf (cffi:make-shareable-byte-vector (- (length signed-bytes)
                                                 (signature-bytes))))
        (signed-buf (cffi:make-shareable-byte-vector (length signed-bytes)))
        (key-buf (cffi:make-shareable-byte-vector (length signing-key))))
    (replace signed-buf signed-bytes)
    ;; The key will be read off the wire during a handshake, so we
    ;; need to copy this to a shareable buffer.
    (replace key-buf signing-key)
    (cffi:with-pointer-to-vector-data (data-ptr buf)
      (cffi:with-pointer-to-vector-data (key-ptr key-buf)
        (cffi:with-pointer-to-vector-data (signed-ptr signed-buf)
          (unless (= 0 (cr:crypto-sign-open data-ptr (cffi:null-pointer)
                                            signed-ptr (length signed-buf)
                                            key-ptr))
            (error 'invalid-signature-error)))))
    buf))
