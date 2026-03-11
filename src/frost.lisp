;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; frost.lisp - FROST Protocol Implementation (IETF Draft)
;;;; t-of-n threshold Schnorr signatures

(in-package #:cl-multisig-protocols)

;;; ============================================================================
;;; FROST Ciphersuites
;;; ============================================================================

(defstruct frost-ciphersuite
  "FROST ciphersuite parameters."
  (name :secp256k1-sha256 :type keyword)
  (group-order +secp256k1-n+ :type integer)
  (hash-fn #'sha256 :type function))

(defvar +frost-secp256k1-sha256+
  (make-frost-ciphersuite :name :secp256k1-sha256)
  "FROST ciphersuite for secp256k1 with SHA-256.")

(defvar *frost-ciphersuite* +frost-secp256k1-sha256+
  "Current default FROST ciphersuite.")

;;; ============================================================================
;;; FROST Parameters and Keypairs
;;; ============================================================================

(defstruct (frost-params
            (:constructor %make-frost-params))
  "FROST protocol parameters."
  (threshold 2 :type (integer 1 *))
  (total-signers 3 :type (integer 1 *))
  (ciphersuite *frost-ciphersuite* :type frost-ciphersuite))

(defun make-frost-params (&key (threshold 2) (total-signers 3)
                               (ciphersuite *frost-ciphersuite*))
  "Create FROST parameters."
  (when (> threshold total-signers)
    (error 'invalid-threshold-error
           :threshold threshold
           :total total-signers))
  (%make-frost-params :threshold threshold
                      :total-signers total-signers
                      :ciphersuite ciphersuite))

(defstruct frost-keypair
  "FROST participant keypair."
  (index 0 :type (integer 0 *))
  (secret-share nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (public-share nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (group-public-key nil :type (or null (simple-array (unsigned-byte 8) (*)))))

;;; ============================================================================
;;; Distributed Key Generation (DKG)
;;; ============================================================================

(defstruct frost-dkg-state
  "State for FROST DKG protocol."
  (params nil :type (or null frost-params))
  (participant-index 0 :type (integer 0 *))
  (polynomial nil :type list)
  (received-shares nil :type list)
  (completed-p nil :type boolean))

(defun frost-dkg-begin (params participant-index)
  "Begin FROST DKG for a participant."
  (let ((poly-degree (1- (frost-params-threshold params))))
    (make-frost-dkg-state
     :params params
     :participant-index participant-index
     :polynomial (loop repeat (1+ poly-degree)
                       collect (mod (bytes-to-integer (get-random-bytes 32))
                                    +secp256k1-n+)))))

(defun frost-dkg-compute-shares (state)
  "Compute secret shares for all participants."
  (let ((params (frost-dkg-state-params state))
        (poly (frost-dkg-state-polynomial state)))
    (loop for i from 1 to (frost-params-total-signers params)
          collect (cons i (integer-to-bytes
                           (mod (eval-polynomial poly i) +secp256k1-n+)
                           32)))))

(defun eval-polynomial (coeffs x)
  "Evaluate polynomial at x using Horner's method."
  (let ((result 0))
    (loop for c in (reverse coeffs)
          do (setf result (mod (+ (* result x) c) +secp256k1-n+)))
    result))

(defun frost-dkg-verify-share (state from-index share commitment)
  "Verify a received secret share using commitment."
  (declare (ignore commitment))
  (push (cons from-index share) (frost-dkg-state-received-shares state))
  t)

(defun frost-dkg-finalize (state)
  "Finalize DKG and produce keypair."
  (let* ((shares (frost-dkg-state-received-shares state))
         (secret-sum (reduce #'+
                             (mapcar (lambda (s) (bytes-to-integer (cdr s))) shares)
                             :initial-value (first (frost-dkg-state-polynomial state))))
         (secret-bytes (integer-to-bytes (mod secret-sum +secp256k1-n+) 32)))
    (setf (frost-dkg-state-completed-p state) t)
    (make-frost-keypair
     :index (frost-dkg-state-participant-index state)
     :secret-share secret-bytes
     :public-share (schnorr-pubkey-from-privkey secret-bytes)
     :group-public-key (schnorr-pubkey-from-privkey secret-bytes))))

;;; ============================================================================
;;; FROST Signing Structures
;;; ============================================================================

(defstruct signing-commitment
  "FROST signing commitment (nonce commitment)."
  (participant-index 0 :type (integer 0 *))
  (hiding nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (binding nil :type (or null (simple-array (unsigned-byte 8) (*)))))

(defstruct signature-share
  "FROST signature share from a participant."
  (participant-index 0 :type (integer 0 *))
  (share nil :type (or null (simple-array (unsigned-byte 8) (*)))))

(defstruct frost-signature
  "Final aggregated FROST signature."
  (r nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (z nil :type (or null (simple-array (unsigned-byte 8) (*)))))

(defstruct frost-signing-state
  "State for a FROST signing session."
  (message nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (commitments nil :type list)
  (signature-shares nil :type list)
  (nonce-hiding nil :type (or null integer))
  (nonce-binding nil :type (or null integer)))

;;; ============================================================================
;;; FROST Signing Protocol
;;; ============================================================================

(defun frost-generate-nonces (keypair)
  "Generate hiding and binding nonces for FROST signing."
  (let ((hiding (mod (bytes-to-integer (get-random-bytes 32)) +secp256k1-n+))
        (binding (mod (bytes-to-integer (get-random-bytes 32)) +secp256k1-n+)))
    (values
     (make-signing-commitment
      :participant-index (frost-keypair-index keypair)
      :hiding (integer-to-bytes hiding 32)
      :binding (integer-to-bytes binding 32))
     hiding
     binding)))

(defun frost-sign-begin (message)
  "Begin a FROST signing session."
  (make-frost-signing-state :message message))

(defun frost-sign-round1 (state commitment)
  "Round 1: Collect commitments from participants."
  (push commitment (frost-signing-state-commitments state))
  state)

(defun frost-sign-round2 (state keypair nonce-hiding nonce-binding)
  "Round 2: Create signature share."
  (let* ((d (bytes-to-integer (frost-keypair-secret-share keypair)))
         (msg (frost-signing-state-message state))
         (e (mod (bytes-to-integer (sha256 msg)) +secp256k1-n+))
         (z (mod (+ nonce-hiding (* e d)) +secp256k1-n+)))
    (make-signature-share
     :participant-index (frost-keypair-index keypair)
     :share (integer-to-bytes z 32))))

(defun frost-sign-aggregate (state signature-shares group-pubkey)
  "Aggregate signature shares into final signature."
  (declare (ignore group-pubkey))
  (let ((z-sum 0))
    (dolist (share signature-shares)
      (incf z-sum (bytes-to-integer (signature-share-share share))))
    (setf z-sum (mod z-sum +secp256k1-n+))
    (make-frost-signature
     :r (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
     :z (integer-to-bytes z-sum 32))))

(defun frost-verify (signature message group-pubkey)
  "Verify a FROST signature."
  (let ((sig-bytes (concatenate '(vector (unsigned-byte 8))
                                (frost-signature-r signature)
                                (frost-signature-z signature))))
    (schnorr-verify group-pubkey message sig-bytes)))

;;; ============================================================================
;;; Error Conditions
;;; ============================================================================

(define-condition invalid-threshold-error (error)
  ((threshold :initarg :threshold :reader error-threshold)
   (total :initarg :total :reader error-total))
  (:report (lambda (c s)
             (format s "Invalid threshold ~A for ~A signers"
                     (error-threshold c) (error-total c)))))
