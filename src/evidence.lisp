;;;; evidence.lisp -- check what an `attested' statement carries.
;;;;
;;;; A witness's `attested' statement embeds the vendor-signed document it fetched.
;;;; This file verifies that document against the roots pinned in cl-sev-snp and checks
;;;; that the statement's claims (measurement, attested key, nonce) are what the document
;;;; actually says.  A statement whose claims the document does not support is rejected
;;;; whoever signed it.
;;;;
;;;; For a reader other than the witness, the nonce proves nothing about freshness (the
;;;; witness chose it); what remains is the vendor-signed timestamp and measurement:
;;;; dated evidence that this measurement ran at this endpoint.

(in-package :witness)

(defun %hex (octets) (string-downcase (cl-sev-snp:hex-string octets)))

(defun nitro-attested-body (document-octets &key endpoint fetched-at nonce-octets vantage note)
  "Build the body of an `attested' statement from a Nitro document fetched by us.
Verifies the document first; refuses to describe one that does not verify."
  ;; Nitro's instance and leaf certificates live for hours, so a statement is judged at
  ;; the document's own AWS-signed timestamp, not at the moment someone reads it.  (Live
  ;; use checks freshness separately, against the clock, with its own nonce.)  The
  ;; residual risk is a leaf key leaking after it expires and back-dating documents;
  ;; those keys live in AWS's hypervisor and are never exported.
  (multiple-value-bind (doc ok checks)
      (cl-sev-snp:verify-nitro-doc document-octets
                                   :nonce-hex (and nonce-octets (%hex nonce-octets))
                                   :now (floor (cl-sev-snp:nitro-doc-timestamp
                                                (cl-sev-snp:parse-nitro-doc document-octets))
                                               1000))
    (unless ok
      (%fail "Nitro document does not verify: ~{~a~^; ~}"
             (loop for (name . passed) in checks unless passed collect name)))
    (apply #'obj
           (append
            (list "method" "attested" "platform" "aws-nitro" "endpoint" endpoint
                  "fetched_at" fetched-at
                  "doc_timestamp_ms" (cl-sev-snp::nitro-doc-timestamp doc)
                  "module_id" (cl-sev-snp::nitro-doc-module-id doc)
                  "nonce_hex" (and (cl-sev-snp::nitro-doc-nonce doc) (%hex (cl-sev-snp::nitro-doc-nonce doc)))
                  "attested_key_hex" (and (cl-sev-snp::nitro-doc-public-key doc)
                                          (%hex (cl-sev-snp::nitro-doc-public-key doc)))
                  "measurement" (obj "PCR0" (%hex (cl-sev-snp:nitro-doc-pcr doc 0))
                                     "PCR1" (%hex (cl-sev-snp:nitro-doc-pcr doc 1))
                                     "PCR2" (%hex (cl-sev-snp:nitro-doc-pcr doc 2)))
                  "document_b64" (cl-sev-snp:base64-encode document-octets))
            (and vantage (list "vantage" vantage))
            (and note (list "note" note))))))

(defun check-attested-evidence (statement)
  "Verify the document inside an `attested' STATEMENT and that its claims match.
Returns T, or signals WITNESS-ERROR naming the first mismatch."
  (unless (equal (statement-method statement) "attested") (%fail "not an attested statement"))
  (let ((platform (statement-field statement "platform")))
    (unless (equal platform "aws-nitro") (%fail "no evidence checker for platform ~s yet" platform))
    (let* ((octets (coerce (cl-sev-snp:base64-decode (statement-field statement "document_b64"))
                           '(simple-array (unsigned-byte 8) (*))))
           (body (nitro-attested-body octets :endpoint (statement-field statement "endpoint")
                                             :fetched-at (statement-field statement "fetched_at"))))
      (flet ((same (k)
               (unless (equal (%get body k) (statement-field statement k))
                 (%fail "statement's ~a does not match its document" k))))
        (same "nonce_hex") (same "attested_key_hex") (same "doc_timestamp_ms") (same "module_id"))
      (unless (equal (measurement-key (%get body "measurement"))
                     (measurement-key (statement-field statement "measurement")))
        (%fail "statement's measurement does not match its document"))
      ;; A document from long before the witness says it fetched it is a replayed one.
      (let ((doc-s (floor (%get body "doc_timestamp_ms") 1000))
            (fetched (statement-field statement "fetched_at")))
        (when (and (integerp fetched) (> (abs (- fetched doc-s)) 600))
          (%fail "document timestamp ~a is not within 10 minutes of fetched_at ~a" doc-s fetched)))
      t)))

(setf *evidence-checkers*
      (cons (cons "attested" #'check-attested-evidence)
            (remove "attested" *evidence-checkers* :key #'car :test #'equal)))
