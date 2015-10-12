(asdf:defsystem #:mtgnet-encryption
  :serial t
  :description "Encrypted connections for the MTGNet client library."
  :author "Matthew Stickney <mtstickney@gmail.com>"
  :license "MIT"
  :depends-on (#:cl-mtgnet
               #:cl-sodium
               #:cl-base64)
  :components ((:file "crypto")
               (:file "encrypted-rpc")))
