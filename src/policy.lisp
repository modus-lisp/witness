;;;; policy.lisp -- which statements count.
;;;;
;;;; Trust starts at ROOTS (the user's own pubkeys) and spreads along edges:
;;;;
;;;;   follows   a trusted key's contact list (NIP-02 kind 3): the web of trust Nostr
;;;;             already runs on -- relays, agents and clients that admit "whoever I
;;;;             follow".  Pass the kind-3 events as FOLLOWS.
;;;;   proclaim  a trusted key vouching for one other key (DEP-14 `proclaim'), optionally
;;;;             with a `depth' bounding how far that key may vouch in turn.
;;;;
;;;; Each root may grant MAX-DEPTH further hops; every edge costs one.  A key reached at
;;;; zero hops left may still sign facts but cannot bring anyone else in.
;;;;
;;;; A statement counts when its signature verified (EVENT->STATEMENT), its signer is
;;;; trusted, its signer has not revoked it, and -- for `attested' -- its evidence checks
;;;; out.  Agreement is counted by DISTINCT trusted signers, never by statements.
;;;;
;;;; NO CLOCK.  Nothing expires and nothing is ordered by `created_at': those are the
;;;; signer's own numbers.  A revocation names the event it voids by id, applies only to
;;;; its own signer's events, cannot itself be revoked, and is final.

(in-package :witness)

(defstruct (policy (:constructor %make-policy))
  roots max-depth
  trusted        ; hash: pubkey -> depth at which it was reached
  statements     ; the statements that count
  rejected)      ; (statement . reason) for ones that do not

(defvar *evidence-checkers* '()
  "Alist of (METHOD . FUNCTION): FUNCTION takes a statement of METHOD and returns T or
signals.  witness/evidence registers the `attested' checker; without it, `attested'
statements are rejected rather than taken on the witness's word.")

(defun follow-edges (events)
  "Trust edges (FROM . TO) from NIP-02 contact lists (kind 3 EVENTS): every `p' tag of
each author's list.  Events whose signature does not verify are dropped.  Several lists
from one author: the one with the largest created_at is used -- NIP-02's own rule for
a replaceable event, and the one the relays already applied."
  (let ((latest (make-hash-table :test 'equal)))
    (dolist (e events)
      (when (and (eql (ev:event-kind e) 3) (ignore-errors (ev:valid-event-p e)))
        (let ((cur (gethash (ev:event-pubkey e) latest)))
          (when (or (null cur) (> (ev:event-created-at e) (ev:event-created-at cur)))
            (setf (gethash (ev:event-pubkey e) latest) e)))))
    (loop for e being the hash-values of latest
          append (loop for tag in (ev:event-tags e)
                       when (and (equal (first tag) "p") (stringp (second tag)) (= (length (second tag)) 64))
                         collect (cons (string-downcase (ev:event-pubkey e)) (string-downcase (second tag)))))))

(defun %revoked-ids (statements)
  "Ids voided by a revocation from their own signer.  Terminal, timestamp-free."
  (let ((by-id (make-hash-table :test 'equal)) (revoked (make-hash-table :test 'equal)))
    (dolist (st statements) (setf (gethash (statement-id st) by-id) st))
    (dolist (st statements revoked)
      (when (equal (statement-method st) "revoked")
        (let ((target (gethash (statement-subject st) by-id)))
          (when (and target
                     (not (equal (statement-method target) "revoked"))   ; a revocation is final
                     (equal (statement-signer target) (statement-signer st)))
            (setf (gethash (statement-id target) revoked) t)))))))

(defun make-policy (statements &key roots follows (max-depth 2))
  "Decide which of STATEMENTS count, trusting ROOTS (pubkeys: hex or npub) and the keys
reachable from them through FOLLOWS (kind-3 events) and `proclaim' statements."
  (let* ((roots (mapcar (lambda (r) (string-downcase (b32:pubkey-hex r))) roots))
         (trusted (make-hash-table :test 'equal))
         (remaining (make-hash-table :test 'equal))
         (revoked (%revoked-ids statements))
         (edges (append
                 (mapcar (lambda (e) (list (car e) (cdr e) nil)) (follow-edges follows))
                 (loop for st in statements
                       when (and (equal (statement-method st) "proclaim") (statement-key st)
                                 (not (gethash (statement-id st) revoked)))
                         collect (list (string-downcase (statement-signer st)) (statement-key st)
                                       (let ((d (statement-field st "depth")))
                                         (and (integerp d) (>= d 0) d)))))))
    (dolist (r roots) (setf (gethash r trusted) 0 (gethash r remaining) max-depth))
    ;; Spread to a fixed point: an edge can be listed before its source is trusted.
    (loop with changed = t while changed
          do (setf changed nil)
             (dolist (edge edges)
               (destructuring-bind (from to limit) edge
                 (let ((r (gethash from remaining)))
                   (when (and r (plusp r))
                     (let ((nr (if limit (min (1- r) limit) (1- r)))
                           (nd (1+ (gethash from trusted))))
                       (when (or (null (gethash to remaining)) (> nr (gethash to remaining)))
                         (setf (gethash to remaining) nr
                               (gethash to trusted) (min nd (or (gethash to trusted) nd))
                               changed t))))))))
    (let ((counted '()) (rejected '()))
      (dolist (st statements)
        (let ((why (cond ((not (gethash (string-downcase (statement-signer st)) trusted))
                          "signer not in the web of trust")
                         ((gethash (statement-id st) revoked) "revoked by its signer")
                         ((equal (statement-method st) "attested")
                          (let ((check (cdr (assoc "attested" *evidence-checkers* :test #'equal))))
                            (if (null check)
                                "no evidence checker loaded (load witness/evidence)"
                                (handler-case (progn (funcall check st) nil)
                                  (error (e) (format nil "evidence: ~a" e)))))))))
          (if why (push (cons st why) rejected) (push st counted))))
      (%make-policy :roots roots :max-depth max-depth :trusted trusted
                    :statements (nreverse counted) :rejected (nreverse rejected)))))

(defun trusted-signer-p (policy pubkey) (and (gethash (string-downcase pubkey) (policy-trusted policy)) t))
(defun signer-depth (policy pubkey) (gethash (string-downcase pubkey) (policy-trusted policy)))

(defun supporting-signers (policy method &key subject (test (constantly t)))
  "Distinct trusted signers with a counting statement of METHOD (about SUBJECT, if given)
for which TEST is true."
  (let ((signers '()))
    (dolist (st (policy-statements policy) (nreverse signers))
      (when (and (equal (statement-method st) method)
                 (or (null subject) (equal (statement-subject st) subject))
                 (funcall test st))
        (pushnew (statement-signer st) signers :test #'equal)))))

(defun accepted-p (policy method &key subject (test (constantly t)) (threshold 1))
  "True when at least THRESHOLD distinct trusted signers support the fact."
  (>= (length (supporting-signers policy method :subject subject :test test)) threshold))

(defun %by-measurement (policy method subject)
  "Alist of (MEASUREMENT-KEY . distinct signers) among counting METHOD statements about SUBJECT."
  (let ((groups '()))
    (dolist (st (policy-statements policy) groups)
      (when (and (equal (statement-method st) method)
                 (or (null subject) (equal (statement-subject st) subject)))
        (let* ((k (measurement-key (statement-field st "measurement")))
               (cell (assoc k groups :test #'equal)))
          (if cell
              (pushnew (statement-signer st) (cdr cell) :test #'equal)
              (push (list k (statement-signer st)) groups)))))))

(defun reproduced-measurements (policy subject)
  "For SUBJECT (\"repo@commit[:target]\"): alist of measurement-key -> signers who
reproduced it.  More than one key means the reproducers disagree."
  (%by-measurement policy "reproduced" subject))

(defun attested-measurements (policy endpoint)
  "For ENDPOINT: alist of measurement-key -> witnesses who saw it attested there."
  (%by-measurement policy "attested" endpoint))

(defun routed-providers (policy measurement model &key service (threshold 1))
  "Where the image measured as MEASUREMENT (a measurement object, or its MEASUREMENT-KEY)
sends MODEL, according to counting `routed' statements (about SERVICE, if given).
Returns (values PROVIDERS SIGNERS CONFLICT):
  PROVIDERS  the sorted provider list at least THRESHOLD distinct trusted signers agree
             on, or NIL;
  SIGNERS    the signers who agree on it;
  CONFLICT   an alist (PROVIDERS . SIGNERS) when trusted signers disagree -- then
             PROVIDERS is NIL, because a disputed route table is no route table."
  (let ((key (if (stringp measurement) (string-downcase measurement) (measurement-key measurement)))
        (groups '()))
    (dolist (st (policy-statements policy))
      (when (and (equal (statement-method st) "routed")
                 (equal (measurement-key (statement-field st "measurement")) key)
                 (or (null service) (equal (statement-subject st) service)))
        (let ((p (%get (statement-field st "routes") model)))
          (when p
            (let* ((set (sort (remove-duplicates (coerce p 'list) :test #'equal) #'string<))
                   (cell (assoc set groups :test #'equal)))
              (if cell
                  (pushnew (statement-signer st) (cdr cell) :test #'equal)
                  (push (list set (statement-signer st)) groups)))))))
    (cond ((cdr groups) (values nil nil groups))
          ((and groups (>= (length (cdar groups)) threshold))
           (values (caar groups) (cdar groups) nil))
          (t (values nil (and groups (cdar groups)) nil)))))

(defun conflicts (policy)
  "Subjects whose `reproduced' statements disagree on the measurement: a source that
builds to different images for different trusted reproducers."
  (let ((subjects (remove-duplicates (mapcar #'statement-subject
                                             (remove "reproduced" (policy-statements policy)
                                                     :key #'statement-method :test-not #'equal))
                                     :test #'equal)))
    (loop for s in subjects
          for groups = (reproduced-measurements policy s)
          when (cdr groups) collect (cons s groups))))
