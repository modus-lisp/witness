;;;; tests.lisp -- offline tests for witness.  Run with:
;;;;   sbcl --non-interactive --eval '(asdf:test-system :witness)' or load run-tests.lisp

(defpackage :witness.tests
  (:use :common-lisp)
  (:local-nicknames (:w :witness) (:ev :cl-nostr.event) (:keys :cl-nostr.keys))
  (:export #:run))

(in-package :witness.tests)

(defvar *pass* 0)
(defvar *fail* '())

(defmacro check (name form)
  `(if (ignore-errors ,form)
       (incf *pass*)
       (progn (push ,name *fail*) (format t "~&FAIL: ~a~%" ,name))))

(defmacro signals-witness-error (form)
  `(handler-case (progn ,form nil) (w:witness-error () t)))

(defparameter *pcr-a* (w:obj "PCR0" (make-string 96 :initial-element #\a) "PCR1" "11" "PCR2" "22"))
(defparameter *pcr-b* (w:obj "PCR0" (make-string 96 :initial-element #\b) "PCR1" "11" "PCR2" "22"))

(defun reproduced (kp measurement &key (commit "7820f27c8035cf1f7d1755a707dbc37a42c6771d") (created-at 1700000000))
  (w:event->statement
   (w:make-statement-event kp (w:obj "method" "reproduced" "repo" "MaplePrivacyLabs/Maple" "commit" commit
                                     "target" "eif-prod" "artifact_sha256" "00" "measurement" measurement
                                     "toolchain" (w:obj "image" "nixos/nix:2.28.3" "sandbox" t))
                           :created-at created-at)))

(defun vouch (kp key &key depth)
  (w:event->statement
   (w:make-statement-event kp (apply #'w:obj "method" "proclaim" "npub" (keys:public-hex key)
                                     (and depth (list "depth" depth))))))

(defun revoke (kp st &key (created-at 1700000000))
  (w:event->statement (w:make-statement-event kp (w:obj "method" "revoked" "revokes" (w:statement-id st))
                                              :created-at created-at)))

(defun contacts (kp &rest followed)
  "A kind-3 contact list by KP following FOLLOWED."
  (ev:build-event kp 3 "" :tags (mapcar (lambda (f) (list "p" (keys:public-hex f))) followed)))

(defun pub (kp) (keys:public-hex kp))

(defun test-statements ()
  (let* ((a (keys:generate-keypair))
         (ev (w:make-statement-event a (w:obj "method" "observed" "endpoint" "x.example" "what" "tls-fp" "value" "ab")))
         (st (w:event->statement ev)))
    (check "kind is DEP-14's 55502" (eql (ev:event-kind ev) 55502))
    (check "roundtrip: method" (equal (w:statement-method st) "observed"))
    (check "subject indexed as an i tag"
           (find '("i" "endpoint:x.example") (ev:event-tags ev) :test #'equal))
    (check "verified_at filled in (informational)" (stringp (w:statement-field st "verified_at")))
    (check "roundtrip: signer" (equal (w:statement-signer st) (pub a)))
    (check "roundtrip: via JSON" (equal (w:statement-id (w:event->statement (ev:json->event (ev:event->json ev))))
                                        (w:statement-id st)))
    ;; tampering with the content breaks the id/signature
    (let ((bad (ev:json->event (ev:event->json ev))))
      (setf (ev:event-content bad) (substitute #\c #\b (ev:event-content bad)))
      (check "tampered content rejected" (signals-witness-error (w:event->statement bad))))
    (check "unknown method refused at signing"
           (signals-witness-error (w:make-statement-event a (w:obj "method" "rumour"))))
    (check "a DEP-14 identity method is read, not written here"
           (signals-witness-error (w:make-statement-event a (w:obj "method" "nip05" "npub" (pub a)))))
    (check "missing field refused at signing"
           (signals-witness-error (w:make-statement-event a (w:obj "method" "reproduced" "repo" "r"))))
    ;; a correctly signed event whose p tag contradicts its npub
    (let* ((b (keys:generate-keypair))
           (liar (ev:build-event a w:+kind+ (json-simple:stringify (w:obj "method" "proclaim" "npub" (pub b)))
                                 :tags (list (list "p" (pub a))))))
      (check "p tag / npub disagreement rejected" (signals-witness-error (w:event->statement liar))))
    ;; DEP-14 interop: an identity attestation as the deposits verifier writes it
    (let* ((subject (keys:generate-keypair))
           (dep14 (ev:build-event a w:+kind+
                                  (json-simple:stringify (w:obj "npub" (pub subject) "method" "nip05"
                                                                "verified_at" "2026-10-23T00:00:00Z"
                                                                "lightning_address" "alice@example.com"))
                                  :tags (list (list "p" (pub subject)))))
           (s14 (w:event->statement dep14)))
      (check "a DEP-14 nip05 attestation parses" (equal (w:statement-method s14) "nip05"))
      (check "its subject is the attested key" (equal (w:statement-key s14) (pub subject))))
    (check "a method no one knows is refused on read"
           (signals-witness-error
            (w:event->statement (ev:build-event a w:+kind+ (json-simple:stringify (w:obj "method" "future-thing"))))))
    ;; a Bitcoin anchor rides along
    (let ((anchored (w:event->statement
                     (w:make-statement-event a (w:obj "method" "observed" "endpoint" "x" "what" "w" "value" "1")
                                             :block (list 917000 "00000000000000000001abc")))))
      (check "block anchor parsed" (equal (w:statement-block anchored) '(917000 "00000000000000000001abc"))))
    (check "wrong kind rejected"
           (signals-witness-error (w:event->statement (ev:build-event a 1 (ev:event-content ev)))))))

(defun test-policy ()
  (let* ((root (keys:generate-keypair)) (b (keys:generate-keypair)) (c (keys:generate-keypair))
         (d (keys:generate-keypair)) (stranger (keys:generate-keypair))
         (sts (list (vouch root b) (vouch b c) (vouch c d)
                    (reproduced b *pcr-a*) (reproduced b *pcr-a*) (reproduced c *pcr-a*)
                    (reproduced d *pcr-a*) (reproduced stranger *pcr-a*)))
         (p (w:make-policy sts :roots (list (pub root)) :max-depth 2))
         (subj "MaplePrivacyLabs/Maple@7820f27c8035cf1f7d1755a707dbc37a42c6771d:eif-prod"))
    (check "root trusted at 0" (eql (w:signer-depth p (pub root)) 0))
    (check "proclaimed key trusted at 1" (eql (w:signer-depth p (pub b)) 1))
    (check "second hop trusted at 2" (eql (w:signer-depth p (pub c)) 2))
    (check "third hop beyond max-depth not trusted" (not (w:trusted-signer-p p (pub d))))
    (check "stranger not trusted" (not (w:trusted-signer-p p (pub stranger))))
    (check "distinct signers counted, not statements"
           (= 2 (length (w:supporting-signers p "reproduced" :subject subj))))
    (check "threshold 2 met" (w:accepted-p p "reproduced" :subject subj :threshold 2))
    (check "threshold 3 not met" (not (w:accepted-p p "reproduced" :subject subj :threshold 3)))
    (check "stranger's statement rejected with a reason"
           (find "signer not in the web of trust" (w:policy-rejected p) :key #'cdr :test #'equal))
    ;; a proclamation's own depth bounds how far the key may vouch in turn
    (let ((p2 (w:make-policy (list (vouch root b :depth 0) (vouch b c) (reproduced c *pcr-a*))
                             :roots (list (pub root)) :max-depth 3)))
      (check "depth 0 proclaimed key is trusted" (w:trusted-signer-p p2 (pub b)))
      (check "depth 0 proclaimed key cannot vouch" (not (w:trusted-signer-p p2 (pub c)))))
    ;; the follow graph: whom a trusted key follows is trusted, one hop per edge
    (let ((p3 (w:make-policy (list (reproduced c *pcr-a*) (reproduced d *pcr-a*))
                             :roots (list (pub root)) :max-depth 2
                             :follows (list (contacts root b) (contacts b c) (contacts c d)))))
      (check "followed by root: trusted" (w:trusted-signer-p p3 (pub b)))
      (check "followed by a follow: trusted" (w:trusted-signer-p p3 (pub c)))
      (check "three hops out: not trusted" (not (w:trusted-signer-p p3 (pub d))))
      (check "a follow's fact counts" (= 1 (length (w:supporting-signers p3 "reproduced")))))
    (let* ((old (contacts root b))
           (new (ev:build-event root 3 "" :tags (list (list "p" (pub c)))
                                     :created-at (+ (ev:event-created-at old) 10)))
           (p4 (w:make-policy '() :roots (list (pub root)) :follows (list old new))))
      (check "the newer contact list replaces the older" (and (w:trusted-signer-p p4 (pub c))
                                                              (not (w:trusted-signer-p p4 (pub b))))))
    ;; revocation: only by the author, final, and indifferent to timestamps
    (let* ((s1 (reproduced b *pcr-a* :created-at 4000000000))
           (p5 (w:make-policy (list (vouch root b) s1 (revoke b s1 :created-at 1)) :roots (list (pub root))))
           (p6 (w:make-policy (list (vouch root b) s1 (revoke root s1)) :roots (list (pub root)))))
      (check "author's revocation voids the statement, even dated before it"
             (null (w:supporting-signers p5 "reproduced")))
      (check "someone else's revocation does not" (w:supporting-signers p6 "reproduced")))
    (let* ((s1 (reproduced b *pcr-a*)) (r1 (revoke b s1)) (r2 (revoke b r1))
           (p7 (w:make-policy (list (vouch root b) s1 r1 r2) :roots (list (pub root)))))
      (check "a revocation cannot be revoked" (null (w:supporting-signers p7 "reproduced"))))
    (let* ((pr (vouch root b))
           (p8 (w:make-policy (list pr (revoke root pr) (reproduced b *pcr-a*)) :roots (list (pub root)))))
      (check "a revoked proclamation grants nothing" (not (w:trusted-signer-p p8 (pub b)))))
    ;; disagreeing reproducers are a conflict
    (let ((p9 (w:make-policy (list (vouch root b) (reproduced root *pcr-a*) (reproduced b *pcr-b*))
                             :roots (list (pub root)))))
      (check "conflict detected" (= 1 (length (w:conflicts p9))))
      (check "conflict lists both measurements" (= 2 (length (cdr (first (w:conflicts p9)))))))
    (check "no conflict when they agree" (null (w:conflicts p)))))

(defparameter *doc-path*
  (asdf:system-relative-pathname :witness "t/fixtures/opensecret-nitro-2026-10-21.cbor")
  "A real AWS Nitro attestation document, fetched from OpenSecret's enclave on 2026-10-21.")

(defun read-octets (path)
  (with-open-file (s path :element-type '(unsigned-byte 8))
    (let ((v (make-array (file-length s) :element-type '(unsigned-byte 8)))) (read-sequence v s) v)))

(defun test-evidence ()
  (if (not (probe-file *doc-path*))
      (format t "~&SKIP evidence tests: no captured document at ~a~%" *doc-path*)
      (let* ((root (keys:generate-keypair))
             (octets (read-octets *doc-path*))
             (doc (cl-sev-snp:parse-nitro-doc octets))
             (fetched (floor (cl-sev-snp:nitro-doc-timestamp doc) 1000))
             (body (w:nitro-attested-body octets :endpoint "enclave.trymaple.ai" :fetched-at fetched))
             (good (w:event->statement (w:make-statement-event root body))))
        (check "evidence verifies" (w:check-attested-evidence good))
        (check "attested statement counts"
               (w:accepted-p (w:make-policy (list good) :roots (list (pub root)))
                             "attested" :subject "enclave.trymaple.ai"))
        (flet ((forged (k v &optional sub)
                 (let ((b2 (json-simple:parse (json-simple:stringify body))))
                   (if sub (setf (gethash sub (gethash k b2)) v) (setf (gethash k b2) v))
                   (w:event->statement (w:make-statement-event root b2)))))
          (let ((lie-pcr (forged "measurement" (make-string 96 :initial-element #\0) "PCR0"))
                (lie-key (forged "attested_key_hex" (make-string 64 :initial-element #\f)))
                (lie-time (forged "fetched_at" (+ fetched 86400))))
            (check "claimed PCR0 not in document rejected"
                   (signals-witness-error (w:check-attested-evidence lie-pcr)))
            (check "claimed key not in document rejected"
                   (signals-witness-error (w:check-attested-evidence lie-key)))
            (check "fetched_at far from document timestamp rejected"
                   (signals-witness-error (w:check-attested-evidence lie-time)))
            (let ((p (w:make-policy (list lie-pcr) :roots (list (pub root)))))
              (check "policy rejects a trusted signer's false evidence"
                     (and (null (w:policy-statements p))
                          (search "evidence" (cdr (first (w:policy-rejected p))))))))))))

(defun test-store ()
  (let* ((path (merge-pathnames (format nil "witness-test-store-~d.jsonl" (random 1000000000 (make-random-state t)))
                               (uiop:default-temporary-directory)))
         (a (keys:generate-keypair))
         (e1 (w:make-statement-event a (w:obj "method" "observed" "endpoint" "x" "what" "w" "value" "1")))
         (e2 (w:make-statement-event a (w:obj "method" "observed" "endpoint" "y" "what" "w" "value" "2"))))
    (when (probe-file path) (delete-file path))
    (w:store-add path e1) (w:store-add path e1) (w:store-add path e2)
    (check "store dedupes" (= 2 (length (w:store-statements path))))
    (with-open-file (s path :direction :output :if-exists :append) (write-line "{\"not\":\"an event\"}" s))
    (multiple-value-bind (sts bad) (w:store-load path)
      (check "store keeps good lines" (= 2 (length sts)))
      (check "store reports the bad line" (= 1 (length bad))))
    (delete-file path)))

(defun routed (kp measurement &rest routes)
  "A `routed' statement by KP about MEASUREMENT: ROUTES alternate model and provider list."
  (w:make-statement-event
   kp (w:obj "method" "routed" "service" "enclave.example" "measurement" measurement
             "source" "example/repo@abc123" "file" "registry.rs"
             "routes" (apply #'w:obj (loop for (m ps) on routes by #'cddr
                                           collect m collect (coerce ps 'vector))))))

(defun test-routed ()
  (let* ((root (keys:generate-keypair)) (b (keys:generate-keypair)) (c (keys:generate-keypair))
         (stranger (keys:generate-keypair))
         (sb (w:event->statement (routed b *pcr-a* "m1" '("x") "m2" '("x" "y"))))
         (ts (lambda (&rest more) (append (list (vouch root b)) more))))
    (check "routed: subject is the service, indexed by endpoint and measurement"
           (and (equal (w:statement-subject sb) "enclave.example")
                (find "endpoint:enclave.example" (ev:event-tags (w:statement-event sb)) :key #'second :test #'equal)
                (find-if (lambda (tg) (and (equal (first tg) "i") (search "measurement:" (second tg))))
                         (ev:event-tags (w:statement-event sb)))))
    (check "routed: routes must map models to arrays of names"
           (signals-witness-error
            (w:make-statement-event b (w:obj "method" "routed" "service" "s" "measurement" *pcr-a*
                                             "source" "r@c" "routes" (w:obj "m1" "x")))))
    (let ((p (w:make-policy (funcall ts sb) :roots (list (pub root)))))
      (check "routed: a trusted reader's routes are returned, sorted"
             (equal (w:routed-providers p *pcr-a* "m2") '("x" "y")))
      (check "routed: by measurement key string too"
             (equal (w:routed-providers p (w:measurement-key *pcr-a*) "m1") '("x")))
      (check "routed: another image has no routes"
             (null (w:routed-providers p *pcr-b* "m1")))
      (check "routed: a model the statement does not list has no routes"
             (null (w:routed-providers p *pcr-a* "m3")))
      (check "routed: the threshold counts distinct signers"
             (null (w:routed-providers p *pcr-a* "m1" :threshold 2))))
    (let ((p (w:make-policy (list (w:event->statement (routed stranger *pcr-a* "m1" '("x"))))
                            :roots (list (pub root)))))
      (check "routed: an untrusted reader counts for nothing"
             (null (w:routed-providers p *pcr-a* "m1"))))
    (let ((p (w:make-policy (funcall ts sb (vouch root c)
                                     (w:event->statement (routed c *pcr-a* "m1" '("x" "z"))))
                            :roots (list (pub root)))))
      (multiple-value-bind (providers signers conflict) (w:routed-providers p *pcr-a* "m1")
        (check "routed: trusted readers who disagree are a conflict, not an answer"
               (and (null providers) (null signers) (= 2 (length conflict))))))))

(defun run ()
  (setf *pass* 0 *fail* '())
  (test-statements) (test-policy) (test-routed) (test-evidence) (test-store)
  (format t "~&witness: ~d passed, ~d failed~%" *pass* (length *fail*))
  (null *fail*))
