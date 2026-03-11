;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; multisig.lisp - High-level Multisig Interface
;;;; Unified API for MuSig2 and FROST protocols

(in-package #:cl-multisig-protocols)

;;; ============================================================================
;;; Error Conditions
;;; ============================================================================

(define-condition multisig-error (error)
  ((message :initarg :message :reader multisig-error-message))
  (:report (lambda (c s)
             (format s "Multisig error: ~A" (multisig-error-message c)))))

(define-condition insufficient-signatures-error (multisig-error)
  ((received :initarg :received :reader error-received)
   (required :initarg :required :reader error-required))
  (:report (lambda (c s)
             (format s "Insufficient signatures: ~A/~A"
                     (error-received c) (error-required c)))))

(define-condition signature-verification-error (multisig-error)
  ((participant :initarg :participant :reader error-participant))
  (:report (lambda (c s)
             (format s "Signature verification failed for participant ~A"
                     (error-participant c)))))

(define-condition nonce-reuse-error (multisig-error)
  ()
  (:report (lambda (c s)
             (declare (ignore c))
             (format s "Nonce reuse detected - this is a critical security error"))))

;;; ============================================================================
;;; Multisig Wallet
;;; ============================================================================

(defstruct (multisig-wallet
            (:constructor %make-multisig-wallet))
  "A multi-signature wallet."
  (type :musig2 :type keyword)
  (threshold 2 :type (integer 1 *))
  (total-signers 3 :type (integer 1 *))
  (pubkeys nil :type list)
  (aggregated-pubkey nil :type (or null (simple-array (unsigned-byte 8) (*)))))

(defun make-multisig-wallet (&key (type :musig2) (threshold 2) pubkeys)
  "Create a new multisig wallet."
  (let ((total (length pubkeys)))
    (when (> threshold total)
      (error 'invalid-threshold-error :threshold threshold :total total))
    (let ((agg-key (case type
                     (:musig2 (musig2-key-agg pubkeys))
                     (:frost (first pubkeys))  ; Simplified
                     (t (error "Unknown wallet type: ~A" type)))))
      (%make-multisig-wallet
       :type type
       :threshold threshold
       :total-signers total
       :pubkeys pubkeys
       :aggregated-pubkey agg-key))))

(defun multisig-wallet-pubkey (wallet)
  "Get the aggregated public key for the wallet."
  (multisig-wallet-aggregated-pubkey wallet))

;;; ============================================================================
;;; Signing Session
;;; ============================================================================

(defstruct (signing-session
            (:constructor %make-signing-session))
  "A multi-signature signing session."
  (id nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (wallet nil :type (or null multisig-wallet))
  (message nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (partial-sigs nil :type list)
  (commitments nil :type list)
  (state :initialized :type keyword))

(defun create-signing-session (wallet message)
  "Create a new signing session."
  (%make-signing-session
   :id (get-random-bytes 32)
   :wallet wallet
   :message message
   :state :collecting))

(defun session-add-signature (session participant-index partial-sig &key commitment)
  "Add a partial signature to the session."
  (when commitment
    (push (cons participant-index commitment)
          (signing-session-commitments session)))
  (push (cons participant-index partial-sig)
        (signing-session-partial-sigs session))
  (when (>= (length (signing-session-partial-sigs session))
            (multisig-wallet-threshold (signing-session-wallet session)))
    (setf (signing-session-state session) :ready))
  t)

(defun session-complete-p (session)
  "Check if the session has enough signatures."
  (>= (length (signing-session-partial-sigs session))
      (multisig-wallet-threshold (signing-session-wallet session))))

(defun session-finalize (session)
  "Finalize the session and produce the aggregated signature."
  (unless (session-complete-p session)
    (error 'insufficient-signatures-error
           :received (length (signing-session-partial-sigs session))
           :required (multisig-wallet-threshold (signing-session-wallet session))))
  (let ((wallet (signing-session-wallet session))
        (partial-sigs (mapcar #'cdr (signing-session-partial-sigs session))))
    (case (multisig-wallet-type wallet)
      (:musig2
       (musig2-partial-sig-agg partial-sigs))
      (:frost
       (let ((sig (frost-sign-aggregate
                   (make-frost-signing-state :message (signing-session-message session))
                   (mapcar (lambda (ps)
                             (make-signature-share :share ps))
                           partial-sigs)
                   (multisig-wallet-aggregated-pubkey wallet))))
         (concatenate '(vector (unsigned-byte 8))
                      (frost-signature-r sig)
                      (frost-signature-z sig))))
      (t
       (error "Unknown wallet type: ~A" (multisig-wallet-type wallet))))))

;;; ============================================================================
;;; Convenience Functions
;;; ============================================================================

(defun quick-musig2-sign (secret-keys message)
  "Quick MuSig2 signing for testing."
  (musig2-sign secret-keys message))

(defun quick-frost-sign (keypairs message threshold)
  "Quick FROST signing for testing."
  (declare (ignore threshold))
  (let* ((state (frost-sign-begin message))
         (nonces (loop for kp in keypairs
                       collect (multiple-value-list (frost-generate-nonces kp)))))
    ;; Round 1: Collect commitments
    (dolist (n nonces)
      (frost-sign-round1 state (first n)))
    ;; Round 2: Create signature shares
    (let ((shares (loop for (kp . rest) on keypairs
                        for (commitment hiding binding) in nonces
                        collect (frost-sign-round2 state kp hiding binding))))
      (frost-sign-aggregate state shares
                            (frost-keypair-group-public-key (first keypairs))))))
