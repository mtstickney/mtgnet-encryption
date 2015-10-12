(defpackage #:mtgnet.crypto
  (:use #:cl)
  ;; Wrappers for cl-sodium functions
  (:export #:generichash-keybytes-min
           #:generichash-keybytes-max
           #:secretbox-noncebytes
           #:scalarmult-bytes
           #:secretbox-macbytes
           #:secretbox-keybytes
           #:box-publickey-bytes
           #:box-secretkey-bytes
           #:with-sodium-buffer
           #:with-secret)
  ;; mtgnet-specific functions
  (:export #:+nonce-bytes+
           #:ecdh-session-key
           #:generate-secret-key))

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

(defun generate-secret-key ()
  (let* ((size-ptr (cr:crypto-box-secretkeybytes))
         (size (cffi:pointer-address size-ptr))
         (ptr (sodium-malloc size))
         (ok nil))
    (unwind-protect
         (progn
           (when (cffi:null-pointer-p ptr)
             (error "Unable to allocate secure memory for secret key."))
           (cr:randombytes-buf ptr size-ptr)
           (sodium-mprotect-noaccess ptr)
           (setf ok t)
           ptr)
      (unless ok
        (sodium-free ptr)
        (setf ptr (cffi:null-pointer))))))
