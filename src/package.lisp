;;;; package.lisp

(defpackage :witness
  (:use :common-lisp)
  (:local-nicknames (:ev :cl-nostr.event) (:keys :cl-nostr.keys)
                    (:u :cl-nostr.util) (:b32 :cl-nostr.bech32))
  (:export
   ;; statements
   #:+kind+ #:+methods+
   #:statement #:statement-p #:statement-method #:statement-body #:statement-event
   #:statement-id #:statement-signer #:statement-created-at #:statement-block
   #:statement-subject #:statement-key #:make-statement-event #:event->statement #:statement-field
   #:measurement-key #:obj
   ;; keys
   #:load-or-create-key #:key-npub
   ;; store
   #:store-add #:store-load #:store-save #:store-statements
   ;; policy
   #:policy #:make-policy #:policy-trusted #:policy-statements #:policy-rejected #:follow-edges
   #:trusted-signer-p #:signer-depth
   #:supporting-signers #:accepted-p #:conflicts
   #:reproduced-measurements #:attested-measurements #:routed-providers
   #:witness-error #:*evidence-checkers*
   ;; evidence (witness/evidence)
   #:nitro-attested-body #:check-attested-evidence))
