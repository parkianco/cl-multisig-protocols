;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; participant.lisp - Signing Participant for multi-party signing
;;;; Represents an individual signer in threshold schemes

(in-package #:cl-multisig-protocols)

;;; ============================================================================
;;; Signing Participant Structure
;;; ============================================================================

(defstruct (signing-participant
            (:constructor %make-signing-participant))
  "A participant in a threshold signing scheme."
  (id nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (index 0 :type (integer 0 *))
  (secret-key nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (public-key nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (secret-nonce nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (public-nonce nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (received-commitments nil :type list))

(defun make-signing-participant (&key index secret-key)
  "Create a new signing participant."
  (let ((sk (or secret-key (get-random-bytes 32))))
    (%make-signing-participant
     :id (get-random-bytes 16)
     :index index
     :secret-key sk
     :public-key (schnorr-pubkey-from-privkey sk))))

(defun participant-keypair (participant)
  "Get the participant's keypair as (SECRET-KEY . PUBLIC-KEY)."
  (cons (signing-participant-secret-key participant)
        (signing-participant-public-key participant)))

(defun participant-generate-commitment (participant)
  "Generate a nonce commitment for signing."
  (let ((nonce (get-random-bytes 32)))
    (setf (signing-participant-secret-nonce participant) nonce
          (signing-participant-public-nonce participant)
          (schnorr-pubkey-from-privkey nonce))
    (signing-participant-public-nonce participant)))

(defun participant-receive-commitments (participant commitments)
  "Receive commitments from all participants."
  (setf (signing-participant-received-commitments participant) commitments)
  t)

(defun participant-create-partial-sig (participant message agg-nonce)
  "Create a partial signature for the message."
  (declare (ignore agg-nonce))
  (let* ((sk (signing-participant-secret-key participant))
         (nonce (signing-participant-secret-nonce participant)))
    (when (and sk nonce)
      ;; Create partial signature (simplified - actual impl would use Schnorr math)
      (let ((partial (make-array 32 :element-type '(unsigned-byte 8))))
        (dotimes (i 32)
          (setf (aref partial i)
                (logxor (aref (sha256 message) i)
                        (aref nonce i))))
        partial))))

(defun participant-verify-final-sig (participant message signature pubkey)
  "Verify the final aggregated signature."
  (schnorr-verify pubkey message signature))
