;;;; opensecret-routed.lisp -- read an OpenSecret (Maple) release's route table and sign
;;;; it as a `routed' statement.
;;;;
;;;; Maple's backend decides, per model, which GPU provider receives a decrypted request.
;;;; The decision is a table of compile-time constants in
;;;; services/opensecret/src/provider_registry.rs.  This reader takes one of Maple's
;;;; approval commits ("Approve prod OpenSecret EIF measurements from <short>"), reads the
;;;; PCRs it approves (services/opensecret/pcrProd.json) and the source commit it names,
;;;; and parses the table at that source commit.  It refuses rather than guesses: a route
;;;; it cannot parse, a provider it does not know, or a model whose routes it cannot find
;;;; ends the run with nothing signed.
;;;;
;;;; What it does NOT check, and a reader should before signing: that the rest of the
;;;; image still sends requests only along this table (fallback within a model, sticky
;;;; routes, the entrypoint's upstream addresses).  Those were read by hand at 4984a12f.
;;;;
;;;;   sbcl --load contrib/opensecret-routed.lisp \
;;;;        --eval '(opensecret-routed:main "/path/to/Maple" "87b7c49d" "/path/to/key")'
;;;;
;;;; prints the signed event as JSON.  It publishes nothing.

(require :asdf)
(asdf:load-system :witness)
(asdf:load-system :cl-ppcre)

(defpackage :opensecret-routed
  (:use :common-lisp)
  (:export #:read-release #:release-body #:main))

(in-package :opensecret-routed)

(defparameter *service* "enclave.trymaple.ai")

(defun git-show (repo rev path)
  (uiop:run-program (list "git" "-C" (namestring repo) "show" (format nil "~a:~a" rev path))
                    :output :string))

(defun git-message (repo rev)
  (uiop:run-program (list "git" "-C" (namestring repo) "log" "-1" "--format=%B" rev) :output :string))

(defun git-full (repo rev)
  (string-trim '(#\Newline #\Space)
               (uiop:run-program (list "git" "-C" (namestring repo) "rev-parse" rev) :output :string)))

(defun fail (fmt &rest args) (error "opensecret-routed: ~?" fmt args))

(defun scan-all (regex text)
  "Every match of REGEX in TEXT, as lists of its register strings."
  (let ((out '()) (start 0))
    (loop
      (multiple-value-bind (s e rs re) (cl-ppcre:scan regex text :start start)
        (unless s (return))
        (push (loop for a across rs for b across re collect (and a (subseq text a b))) out)
        (setf start (max e (1+ s)))))
    (nreverse out)))

(defun strip-test-items (text)
  "TEXT without the item that follows each #[cfg(test)]: up to the next top-level `;'
or a matching close brace at column 0."
  (cl-ppcre:regex-replace-all "(?ms)^#\\[cfg\\(test\\)\\]\\n.*?^(?:\\}|[^\\n]*;)\\s*$" text ""))

(defun string-consts (text)
  "NAME -> value for `pub const NAME: &str = \"v\";' and aliases `= OTHER;'."
  (let ((consts (make-hash-table :test 'equal)) (aliases '()))
    (loop for (name value) in (scan-all "(?m)^\\s*pub(?:\\(crate\\))? const ([A-Z0-9_]+): &str = \"([^\"]*)\";" text)
          do (setf (gethash name consts) value))
    (loop for (name other) in (scan-all "(?m)^\\s*pub(?:\\(crate\\))? const ([A-Z0-9_]+): &str = ([A-Z0-9_]+);" text)
          do (push (cons name other) aliases))
    (loop for (name . other) in aliases
          do (setf (gethash name consts) (or (gethash other consts) (fail "alias ~a -> unknown ~a" name other))))
    consts))

(defun provider-name (expr)
  "OpenSecret's own ProviderId::as_str names."
  (let ((e (remove #\Space expr)))
    (cond ((string= e "ProviderId::Tinfoil") "tinfoil")
          ((string= e "ProviderId::Continuum") "continuum")
          ((string= e "ProviderId::Maple(MapleInstanceId::I01)") "maple-i01")
          ((string= e "ProviderId::Maple(MapleInstanceId::I02)") "maple-i02")
          (t (fail "unknown provider expression ~s" expr)))))

(defun route-tables (text)
  "NAME -> list of providers, for every `const NAME: &[ModelRouteSpec] = &[...];'.
A route with `enabled: false' is still listed: it is one constant away from use."
  (let ((tables (make-hash-table :test 'equal)))
    (loop for (name body) in (scan-all "(?ms)^const ([A-Z0-9_]+): &\\[ModelRouteSpec\\] = &\\[(.*?)\\];" text)
          do (let ((entries (scan-all "(?s)ModelRouteSpec\\s*\\{(.*?)\\}" body)))
               (when (null entries) (fail "route table ~a has no entries I can read" name))
               (setf (gethash name tables)
                     (loop for (entry) in entries
                           collect (let ((m (scan-all "provider:\\s*([^,]+)," entry)))
                                     (unless (= 1 (length m)) (fail "route in ~a without one provider" name))
                                     (provider-name (first (first m))))))))
    tables))

(defun completion-models (text consts tables)
  "Alist model-id -> providers from COMPLETION_MODELS."
  (let ((block (first (first (scan-all "(?ms)^const COMPLETION_MODELS: &\\[CompletionModelSpec\\] = &\\[(.*?)^\\];" text)))))
    (unless block (fail "no COMPLETION_MODELS table"))
    (let ((entries (scan-all "(?s)completion_model\\(\\s*([^,]+?)\\s*,\\s*([A-Z0-9_]+)\\s*,?\\s*\\)" block)))
      (unless (= (length entries) (count-if (lambda (l) (search "completion_model(" l))
                                            (uiop:split-string block :separator '(#\Newline))))
        (fail "COMPLETION_MODELS has entries I cannot parse"))
      (loop for (id-expr table) in entries
            collect (let ((id (if (char= (char id-expr 0) #\")
                                  (string-trim "\"" id-expr)
                                  (or (gethash id-expr consts) (fail "unknown model constant ~a" id-expr))))
                          (routes (or (gethash table tables) (fail "unknown route table ~a" table))))
                      (cons id (remove-duplicates routes :test #'string= :from-end t)))))))

(defun read-release (repo approval)
  "Read the release APPROVAL approves.  Returns a plist :source :pcrs :routes."
  (let* ((msg (git-message repo approval))
         (source (or (cl-ppcre:register-groups-bind (s) ("Source commit: ([0-9a-f]{40})" msg) s)
                     (fail "approval ~a names no source commit" approval)))
         (pcr (json-simple:parse (git-show repo approval "services/opensecret/pcrProd.json")))
         (registry (strip-test-items (git-show repo source "services/opensecret/src/provider_registry.rs")))
         (consts (string-consts (git-show repo source "services/opensecret/src/model_config.rs")))
         (routes (completion-models registry consts (route-tables registry))))
    (list :approval (git-full repo approval) :source source
          :pcrs (list (gethash "PCR0" pcr) (gethash "PCR1" pcr) (gethash "PCR2" pcr))
          :routes routes)))

(defun release-body (release)
  (witness:obj
   "method" "routed"
   "service" *service*
   "measurement" (destructuring-bind (p0 p1 p2) (getf release :pcrs)
                   (witness:obj "PCR0" p0 "PCR1" p1 "PCR2" p2))
   "source" (format nil "MaplePrivacyLabs/Maple@~a" (getf release :source))
   "approval" (getf release :approval)
   "file" "services/opensecret/src/provider_registry.rs"
   "routes" (let ((h (make-hash-table :test 'equal)))
              (loop for (m . ps) in (getf release :routes) do (setf (gethash m h) (coerce ps 'vector)))
              h)))

(defun main (repo approval key-path)
  (let* ((release (read-release repo approval))
         (kp (witness:load-or-create-key key-path))
         (event (witness:make-statement-event kp (release-body release))))
    (witness:event->statement event)                 ; it must read back as what we signed
    (write-line (cl-nostr.event:event->json event))
    event))
