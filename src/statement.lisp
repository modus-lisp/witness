;;;; statement.lisp -- signed facts, carried as DEP-14 attestation events (kind 55502).
;;;;
;;;; witness speaks the event shape of DEP-14 (bitcoin-deposits/deposits): a regular
;;;; kind-55502 event whose JSON content carries a `method', signed by whoever stands
;;;; behind it.  DEP-14's own methods (nip05, challenge, proclaim, ringsig) are identity
;;;; checks of a pubkey; witness adds facts about things that are not pubkeys -- an
;;;; endpoint, a source tree, a measurement.  A DEP-14 consumer ignores methods it does
;;;; not know, so the two share relays and readers without stepping on each other.
;;;;
;;;; Methods:
;;;;   attested    a witness fetched a vendor-signed attestation document from an endpoint
;;;;               and publishes the document itself; it verifies without trusting the witness.
;;;;   reproduced  the signer built REPO at COMMIT with TOOLCHAIN and got ARTIFACT, whose
;;;;               measurement is MEASUREMENT.
;;;;   observed    a value the witness saw that carries no vendor signature.  Its word only.
;;;;   endorsed    the signer accepts a release (after audit) for use.
;;;;   proclaim    (DEP-14) the signer vouches for the key NPUB: a trust edge.
;;;;   revoked     (DEP-14) the signer withdraws one of its own events, named by id.
;;;;   nip05, challenge, ringsig   (DEP-14) read, never written here.
;;;;
;;;; Subjects are tags so relays can index them: a pubkey is `p'; anything else is an `i'
;;;; tag (`endpoint:HOST', `source:REPO@COMMIT[:TARGET]', `measurement:KEY').
;;;;
;;;; TIME IS NOT TRUSTED.  `created_at' and `verified_at' are values the signer chose, so
;;;; nothing here expires and nothing is ordered by them.  Revocation names the event it
;;;; voids and is terminal.  Where a bound in time matters, a statement may carry a
;;;; Bitcoin anchor, ["block" HEIGHT HASH] ("not before"), for a caller that can check
;;;; it against its own view of the chain.

(in-package :witness)

(defconstant +kind+ 55502 "DEP-14 attestation kind: regular, so every statement is kept.")

(defparameter +methods+
  '("attested" "reproduced" "observed" "endorsed" "proclaim" "revoked" "nip05" "challenge" "ringsig")
  "Methods this library reads.  It writes all but the DEP-14 identity checks.")

(defparameter +written-methods+ '("attested" "reproduced" "observed" "endorsed" "proclaim" "revoked"))

(define-condition witness-error (error)
  ((reason :initarg :reason :reader witness-error-reason))
  (:report (lambda (c s) (format s "witness: ~a" (witness-error-reason c)))))

(defun %fail (fmt &rest args)
  (error 'witness-error :reason (apply #'format nil fmt args)))

(defun obj (&rest kv)
  "A JSON object (EQUAL hash table) from alternating keys and values."
  (let ((h (make-hash-table :test 'equal)))
    (loop for (k v) on kv by #'cddr do (setf (gethash k h) v))
    h))

(defun %get (h k) (and (hash-table-p h) (gethash k h)))

(defun statement-field (statement &rest path)
  "The value at PATH inside STATEMENT's body, e.g. (statement-field s \"measurement\" \"PCR0\")."
  (let ((v (statement-body statement)))
    (dolist (k path v) (setf v (%get v k)))))

;;; ---------------------------------------------------------------------------
;;; Subjects and measurement keys.
;;; ---------------------------------------------------------------------------

(defun measurement-key (measurement)
  "A canonical string for a measurement object, so two statements can be compared:
PCR0|PCR1|PCR2 for Nitro, or the register list for SEV-SNP/TDX."
  (cond ((null measurement) nil)
        ((%get measurement "PCR0")
         (format nil "~(~a|~a|~a~)" (%get measurement "PCR0") (or (%get measurement "PCR1") "")
                 (or (%get measurement "PCR2") "")))
        ((%get measurement "registers")
         (format nil "~(~{~a~^|~}~)" (coerce (%get measurement "registers") 'list)))
        (t nil)))

(defun %key-subject (body)
  "The pubkey a statement is about (hex, lowercase), or NIL."
  (let ((n (%get body "npub")))
    (and (stringp n) (string-downcase (b32:pubkey-hex n)))))

(defun %subject (body)
  "What a statement is about, as one string: a pubkey, an endpoint, REPO@COMMIT[:TARGET],
or for a revocation the id it voids."
  (let ((method (%get body "method")))
    (cond ((member method '("attested" "observed") :test #'equal) (%get body "endpoint"))
          ((equal method "reproduced")
           (format nil "~a@~a~@[:~a~]" (%get body "repo") (%get body "commit") (%get body "target")))
          ((equal method "endorsed") (or (%key-subject body) (%get body "subject")))
          ((equal method "revoked") (%get body "revokes"))
          (t (%key-subject body)))))

(defun %index-tags (body)
  "The `i' tags a statement's non-pubkey subjects are indexed under."
  (let ((method (%get body "method")) (m (measurement-key (%get body "measurement"))) (out '()))
    (when (member method '("attested" "observed") :test #'equal)
      (push (list "i" (format nil "endpoint:~a" (%get body "endpoint"))) out))
    (when (equal method "reproduced") (push (list "i" (format nil "source:~a" (%subject body))) out))
    (when (and (equal method "endorsed") (null (%key-subject body)))
      (push (list "i" (format nil "subject:~a" (%get body "subject"))) out))
    (when m (push (list "i" (format nil "measurement:~a" m)) out))
    (nreverse out)))

(defun %validate-body (body &key writing)
  (unless (hash-table-p body) (%fail "statement content is not a JSON object"))
  (let ((method (%get body "method")))
    (unless (member method (if writing +written-methods+ +methods+) :test #'equal)
      (%fail "unrecognised method ~s" method))
    (flet ((need (&rest keys)
             (dolist (k keys) (unless (%get body k) (%fail "~a statement lacks ~s" method k)))))
      (cond ((equal method "attested") (need "platform" "endpoint" "fetched_at" "document_b64" "measurement"))
            ((equal method "reproduced") (need "repo" "commit" "artifact_sha256" "measurement" "toolchain"))
            ((equal method "observed") (need "endpoint" "what" "value"))
            ((equal method "endorsed") (unless (or (%get body "npub") (%get body "subject"))
                                         (%fail "endorsed statement names neither npub nor subject")))
            ((equal method "revoked") (need "revokes"))
            (t (need "npub"))))
    (when (%get body "measurement")
      (unless (measurement-key (%get body "measurement"))
        (%fail "~a statement's measurement has neither PCRs nor registers" method))))
  body)

;;; ---------------------------------------------------------------------------
;;; Statement <-> event.
;;; ---------------------------------------------------------------------------

(defstruct (statement (:constructor %make-statement))
  event method body subject key signer id created-at block)

(defun %iso-now ()
  (multiple-value-bind (s mi h d mo y) (decode-universal-time (get-universal-time) 0)
    (format nil "~d-~2,'0d-~2,'0dT~2,'0d:~2,'0d:~2,'0dZ" y mo d h mi s)))

(defun make-statement-event (keypair body &key block (created-at (ev::now)))
  "Sign BODY (a JSON object with a `method') as a DEP-14 attestation by KEYPAIR.
Returns the EVENT.  BLOCK, a list (HEIGHT HASH), anchors it after that block."
  (%validate-body body :writing t)
  (unless (%get body "verified_at") (setf (gethash "verified_at" body) (%iso-now)))   ; informational
  (let* ((key (%key-subject body))
         (tags (append (and key (list (list "p" key)))
                       (and (equal (%get body "method") "revoked") (list (list "e" (%get body "revokes"))))
                       (%index-tags body)
                       (and block (list (list "block" (princ-to-string (first block)) (second block)))))))
    (ev:build-event keypair +kind+ (json-simple:stringify body) :tags tags :created-at created-at)))

(defun event->statement (event)
  "Check EVENT's id and signature and parse its statement.  Signals WITNESS-ERROR on
anything wrong: a bad signature, the wrong kind, an unrecognised method, malformed
content, or tags that disagree with the signed content."
  (unless (eql (ev:event-kind event) +kind+) (%fail "event kind ~a is not ~a" (ev:event-kind event) +kind+))
  (unless (ev:valid-event-p event) (%fail "event ~a: id or signature does not verify" (ev:event-id event)))
  (let* ((body (%validate-body (handler-case (json-simple:parse (ev:event-content event))
                                 (error () (%fail "event ~a content is not JSON" (ev:event-id event))))))
         (key (%key-subject body))
         (p (ev:first-tag-value event "p")))
    ;; Tags are for relay queries only; the content is the statement.  A tag that
    ;; contradicts the content is a malformed (or forged-looking) statement.
    (when (and key (not (equal (and p (string-downcase p)) key)))
      (%fail "event ~a: p tag disagrees with npub" (ev:event-id event)))
    (when (equal (%get body "method") "revoked")
      (unless (equal (ev:first-tag-value event "e") (%get body "revokes"))
        (%fail "event ~a: e tag disagrees with revokes" (ev:event-id event))))
    (let ((block (find "block" (ev:event-tags event) :key #'first :test #'equal)))
      (%make-statement :event event :method (%get body "method") :body body :subject (%subject body)
                       :key key :signer (ev:event-pubkey event) :id (ev:event-id event)
                       :created-at (ev:event-created-at event)
                       :block (and block (cddr block)
                                   (list (parse-integer (second block) :junk-allowed t) (third block)))))))

;;; ---------------------------------------------------------------------------
;;; Machine keys.  A key file holds 64 hex characters, mode 0600.  Never a user's own
;;; root key: that stays in the user's own client and signs only `proclaim' statements.
;;; ---------------------------------------------------------------------------

(defun load-or-create-key (path)
  "The keypair stored at PATH, creating a fresh one (mode 0600) if there is none."
  (let ((path (pathname path)))
    (if (probe-file path)
        ;; The hex text goes into fixed memory, then the heap copies of it are overwritten.
        (let* ((line (with-open-file (s path) (read-line s)))
               (hex (string-trim '(#\Space #\Newline #\Return #\Tab) line)))
          (unwind-protect (keys:keypair-from-secret hex)
            (fill hex #\0) (fill line #\0)))
        (let ((kp (keys:generate-keypair)))
          (ensure-directories-exist path)
          ;; Created 0600 in one step (O_EXCL), so the secret is never briefly readable.
          (let* ((fd (sb-posix:open (namestring path)
                                    (logior sb-posix:o-wronly sb-posix:o-creat sb-posix:o-excl) #o600))
                 (s (sb-sys:make-fd-stream fd :output t :external-format :latin-1 :auto-close t)))
            (let ((hex (keys:secret-hex kp)))             ; the explicit export, to the file
              (unwind-protect (write-string hex s) (close s) (fill hex #\0))))
          kp))))

(defun key-npub (keypair-or-hex)
  (b32:npub-encode (if (stringp keypair-or-hex) keypair-or-hex (keys:public-hex keypair-or-hex))))
