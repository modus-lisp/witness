;;;; store.lisp -- a local file of signed statements, one event JSON per line.
;;;;
;;;; The store holds events as received.  Nothing in it is trusted: every load
;;;; re-verifies signatures, and the policy decides what counts.

(in-package :witness)

(defun store-load (path)
  "Statements in the store at PATH (verified), and the lines that failed, as
(values STATEMENTS REJECTED) where REJECTED is a list of (LINE-NUMBER . REASON)."
  (let ((out '()) (bad '()) (seen (make-hash-table :test 'equal)))
    (when (probe-file path)
      (with-open-file (s path :external-format :utf-8)
        (loop for line = (read-line s nil) for n from 1 while line
              unless (zerop (length (string-trim " " line)))
                do (handler-case
                       (let ((st (event->statement (ev:json->event line))))
                         (unless (gethash (statement-id st) seen)
                           (setf (gethash (statement-id st) seen) t)
                           (push st out)))
                     (error (e) (push (cons n (princ-to-string e)) bad))))))
    (values (nreverse out) (nreverse bad))))

(defun store-add (path event)
  "Append EVENT to the store at PATH if it verifies and is not already there.
Returns the STATEMENT."
  (let ((st (event->statement event)))
    (unless (find (statement-id st) (store-load path) :key #'statement-id :test #'equal)
      (ensure-directories-exist path)
      (with-open-file (s path :direction :output :if-exists :append :if-does-not-exist :create
                              :external-format :utf-8)
        (write-line (ev:event->json event) s)))
    st))

(defun store-save (path statements)
  "Write STATEMENTS to PATH, replacing it."
  (ensure-directories-exist path)
  (with-open-file (s path :direction :output :if-exists :supersede :external-format :utf-8)
    (dolist (st statements) (write-line (ev:event->json (statement-event st)) s))))

(defun store-statements (path) (values (store-load path)))
