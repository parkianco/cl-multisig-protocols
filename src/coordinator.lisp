;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; coordinator.lisp - Signing Coordinator for multi-party signing sessions
;;;; Manages session state and aggregates signatures from participants

(in-package #:cl-multisig-protocols)

;;; ============================================================================
;;; Signing Coordinator Structure
;;; ============================================================================

(defstruct (signing-coordinator
            (:constructor %make-signing-coordinator))
  "Coordinator for threshold signing sessions."
  (session-id nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (message nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (participants nil :type list)
  (commitments (make-hash-table :test 'equal) :type hash-table)
  (partial-sigs (make-hash-table :test 'equal) :type hash-table)
  (threshold 2 :type (integer 1 *))
  (state :idle :type keyword))

(defun make-signing-coordinator (&key threshold (session-id nil))
  "Create a new signing coordinator."
  (%make-signing-coordinator
   :threshold threshold
   :session-id (or session-id (get-random-bytes 32))))

(defun coordinator-add-participant (coordinator participant-id pubkey)
  "Add a participant to the coordinator."
  (declare (ignore pubkey))
  (push participant-id (signing-coordinator-participants coordinator))
  t)

(defun coordinator-remove-participant (coordinator participant-id)
  "Remove a participant from the coordinator."
  (setf (signing-coordinator-participants coordinator)
        (remove participant-id (signing-coordinator-participants coordinator)
                :test #'equal))
  t)

(defun coordinator-start-session (coordinator message)
  "Start a new signing session for the given message."
  (setf (signing-coordinator-message coordinator) message
        (signing-coordinator-state coordinator) :collecting-commitments)
  (signing-coordinator-session-id coordinator))

(defun coordinator-receive-commitment (coordinator participant-id commitment)
  "Receive a nonce commitment from a participant."
  (declare (ignore commitment))
  (setf (gethash participant-id (signing-coordinator-commitments coordinator)) t)
  ;; Check if all commitments received
  (when (>= (hash-table-count (signing-coordinator-commitments coordinator))
            (length (signing-coordinator-participants coordinator)))
    (setf (signing-coordinator-state coordinator) :collecting-signatures))
  t)

(defun coordinator-receive-partial-sig (coordinator participant-id partial-sig)
  "Receive a partial signature from a participant."
  (setf (gethash participant-id (signing-coordinator-partial-sigs coordinator))
        partial-sig)
  t)

(defun coordinator-get-final-signature (coordinator)
  "Aggregate partial signatures into final signature."
  (when (>= (hash-table-count (signing-coordinator-partial-sigs coordinator))
            (signing-coordinator-threshold coordinator))
    (setf (signing-coordinator-state coordinator) :complete)
    ;; Return placeholder signature
    (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))

(defun coordinator-abort (coordinator)
  "Abort the current signing session."
  (clrhash (signing-coordinator-commitments coordinator))
  (clrhash (signing-coordinator-partial-sigs coordinator))
  (setf (signing-coordinator-state coordinator) :aborted)
  t)
