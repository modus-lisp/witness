;;;; witness.asd -- a web of trust for facts about remote machines and their keys.
;;;;
;;;; :witness           signed statements (DEP-14 attestation events, kind 55502), a local
;;;;                    store, and the trust policy -- follows plus proclaims, terminal
;;;;                    revocation, no clock -- that decides which statements count.
;;;; :witness/evidence  checks the documents an `attested` statement carries (AWS Nitro,
;;;;                    via cl-sev-snp), so a witness's claim is never taken on its word.
;;;; :witness/tests     offline tests.

(asdf:defsystem :witness
  :description "Signed statements (DEP-14 attestations) about keys, releases, reproductions and enclave attestations, and a follow-graph web-of-trust policy over them."
  :author "ynniv"
  :license "MIT"
  :depends-on (:cl-nostr :json-simple :sb-posix)
  :in-order-to ((test-op (test-op :witness/tests)))
  :serial t
  :components ((:module "src"
                :components ((:file "package")
                             (:file "statement")
                             (:file "store")
                             (:file "policy")))))

(asdf:defsystem :witness/evidence
  :description "Verify the attestation documents embedded in witness statements."
  :license "MIT"
  :depends-on (:witness :cl-sev-snp)
  :serial t
  :components ((:module "src" :components ((:file "evidence")))))

(asdf:defsystem :witness/tests
  :description "Offline tests for witness."
  :license "MIT"
  :depends-on (:witness :witness/evidence)
  :serial t
  :components ((:module "t" :components ((:file "tests"))))
  :perform (test-op (o c) (unless (uiop:symbol-call :witness.tests :run)
                            (error "witness tests failed"))))
