(defpackage #:mtgnet.crypto
  (:use #:cl)
  ;; Wrappers for sodium functions
  (:export #:box-publickey-bytes
           #:secretbox-macbytes)
  (:export #:with-secret
           #:+nonce-bytes+
           #:ecdh-session-key
           #:generate-secret-key
           #:generate-encoded-secret
           #:free-secret
           #:decode-secret-key
           #:compute-public-key))

(in-package #:mtgnet.crypto)

;; Wrappers for cl-sodium functions, because why would we have
;; reasonable return types?
(defun generichash-keybytes-min ()
  (cffi:pointer-address (cr:crypto-generichash-keybytes-min)))

(defun generichash-keybytes-max ()
  (cffi:pointer-address (cr:crypto-generichash-keybytes-max)))

(eval-when (:load-toplevel :compile-toplevel)
  (defun secretbox-noncebytes ()
    (cffi:pointer-address (cr:crypto-secretbox-noncebytes))))

(defun scalarmult-bytes ()
  (cffi:pointer-address (cr:crypto-scalarmult-bytes)))

(defun secretbox-macbytes ()
  (cffi:pointer-address (cr:crypto-secretbox-macbytes)))

(defun secretbox-keybytes ()
  (cffi:pointer-address (cr:crypto-secretbox-keybytes)))

(defun box-publickey-bytes ()
  (cffi:pointer-address (cr:crypto-box-publickeybytes)))

(defun box-secretkey-bytes ()
  (cffi:pointer-address (cr:crypto-box-secretkeybytes)))

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

(defmacro with-sodium-buffer ((var size) &body body)
  `(let ((,var (sodium-malloc ,size)))
     (unwind-protect
          (progn
            ,@body)
       (sodium-free ,var))))

(defmacro with-secret ((secret) &body body)
  (let ((secret-var (gensym "SECRET")))
    `(let ((,secret-var ,secret))
       (check-type ,secret-var cffi:foreign-pointer)
       (unwind-protect
            (progn
              (sodium-mprotect-readonly ,secret-var)
              ,@body)
         (sodium-mprotect-noaccess ,secret-var)))))

;; We're using the same size nonces everywhere, just for consistency.
(defconstant +nonce-bytes+ (secretbox-noncebytes))

(defun %hash-key (secret secret-size nonce nonce-size)
  (check-type secret-size (integer 0))
  (check-type nonce-size (integer 0))
  (assert (<= (generichash-keybytes-min)
              secret-size
              (generichash-keybytes-max))
          ()
          "Invalid key size ~S for generic hash."
          secret-size)
  (let* ((size (secretbox-keybytes))
         (newkey (cffi:make-shareable-byte-vector size))
         res)
    (cffi:with-pointer-to-vector-data (newkey-ptr newkey)
      (setf res (cr:crypto-generichash newkey-ptr (cffi:make-pointer size)
                                       nonce nonce-size
                                       secret (cffi:make-pointer secret-size))))
    (unless (= res 0)
      (error "Error deriving shared key, error code ~S" res))
    newkey))

(defun ecdh-session-key (secret public our-nonce their-nonce)
  "Return a new session key based on an ECDH exchange. Note that this
is an augmented ECDH session key: the ECDH key is used to hash the
XORed nonces, and the result is returned as the new key. This is
designed to make the session key less durable even with fixed secret
keys."
  (check-type secret cffi:foreign-pointer)
  (check-type public (vector (unsigned-byte 8)))
  (check-type our-nonce (vector (unsigned-byte 8) 24))
  (check-type their-nonce (vector (unsigned-byte 8) 24))
  ;; TODO: you'd get better performance (depending on the
  ;; implementation) using the raw SAP object instead of a shareable
  ;; byte vector. Just sayin'.
  (let ((shared-secret-buf (cffi:make-shareable-byte-vector (scalarmult-bytes))))
    (cffi:with-pointer-to-vector-data (shared-secret shared-secret-buf)
      (let ((res (cr:crypto-scalarmult shared-secret secret public)))
        (unless (= res 0)
          (error "Error completing Diffie-Hellman exchange, error code ~S" res))
        (let ((shared-nonce (cffi:make-shareable-byte-vector (secretbox-noncebytes))))
          (map-into shared-nonce #'logxor our-nonce their-nonce)
          (cffi:with-pointer-to-vector-data (nonce shared-nonce)
            (%hash-key shared-secret (scalarmult-bytes)
                   nonce +nonce-bytes+)))))))

(defun call-with-secret-buffer (thunk)
  (let* ((size-ptr (cr:crypto-box-secretkeybytes))
         (size (cffi:pointer-address size-ptr))
         (ptr (sodium-malloc size))
         (ok nil))
    (unwind-protect
         (progn
           (when (cffi:null-pointer-p ptr)
             (error "Unable to allocate secure memory for secret key."))
           (cr:randombytes-buf ptr size-ptr)
           (funcall thunk ptr size-ptr)
           (sodium-mprotect-noaccess ptr)
           (setf ok t))
      (unless ok
        (sodium-free ptr)
        (setf ptr (cffi:null-pointer))))
    ptr))

(defmacro with-new-secret-buffer ((ptr-var size-ptr-var) &body body)
  `(call-with-secret-buffer (lambda (,ptr-var ,size-ptr-var) ,@body)))

(defun generate-secret-key ()
  (with-new-secret-buffer (ptr size-ptr)
    (cr:randombytes-buf ptr size-ptr)))

(defun free-secret (secret)
  (check-type secret cffi:foreign-pointer)
  (sodium-free secret))

(defun generate-encoded-secret ()
  (let ((buf (cffi:make-shareable-byte-vector (box-secretkey-bytes))))
    (cffi:with-pointer-to-vector-data (buf-ptr buf)
      (cr:randombytes-buf buf-ptr (cr:crypto-box-secretkeybytes)))
    (prog1 (base64:usb8-array-to-base64-string buf)
      (loop for i from 0 to (1- (length buf))
         ;; At least attempt to scrub intermediate data.
         do (setf (aref buf i) 0)))))

(defun decode-secret-key (encoded-key)
  "Decode and return a new secret key from the base64-encoded string ENCODED-KEY."
  (check-type encoded-key string)
  (let ((data (base64:base64-string-to-usb8-array encoded-key)))
    (with-new-secret-buffer (ptr size-ptr)
      (unless (= (cffi:pointer-address size-ptr)
                 (length data))
        (error "Encoded key ~S (~S bytes) is not of the right size to be a secret key (expected ~S bytes)."
               data
               (length data)
               (cffi:pointer-address size-ptr)))
      (loop for byte across data
         for i from 0
         do (setf (cffi:mem-aref ptr :uchar i) byte
                  ;; Clear the data in-memory. Imperfect protection,
                  ;; but better than nothing.
                  (aref data i) 0)))))

(defun compute-public-key (secret-key)
  (check-type secret-key cffi:foreign-pointer)
  (assert (= (box-publickey-bytes) (scalarmult-bytes)) ())
  (let ((public-key (cffi:make-shareable-byte-vector (scalarmult-bytes))))
    (cffi:with-pointer-to-vector-data (public-key-ptr public-key)
      (with-secret (secret-key)
        (cr:crypto-scalarmult-base public-key-ptr secret-key)))
    public-key))
