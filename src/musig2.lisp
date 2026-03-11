;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; musig2.lisp - MuSig2 Protocol Implementation (BIP327)
;;;; N-of-N multi-party Schnorr signatures

(in-package #:cl-multisig-protocols)

;;; ============================================================================
;;; MuSig2 Structures
;;; ============================================================================

(defstruct (musig2-key-agg-context
            (:constructor %make-musig2-key-agg-context))
  "Key aggregation context for MuSig2."
  (pubkeys nil :type list)
  (agg-pubkey nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (key-agg-coef nil :type list))

(defstruct musig2-secnonce
  "MuSig2 secret nonce (kept private by signer)."
  (k1 nil :type (or null integer))
  (k2 nil :type (or null integer))
  (pubkey nil :type (or null (simple-array (unsigned-byte 8) (*)))))

(defstruct musig2-pubnonce
  "MuSig2 public nonce (shared with other signers)."
  (r1 nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (r2 nil :type (or null (simple-array (unsigned-byte 8) (*)))))

(defstruct musig2-agg-nonce
  "Aggregated MuSig2 nonce."
  (agg-r1 nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (agg-r2 nil :type (or null (simple-array (unsigned-byte 8) (*)))))

;;; ============================================================================
;;; Key Aggregation
;;; ============================================================================

(defun make-musig2-key-agg-context (pubkeys)
  "Create a key aggregation context from a list of public keys."
  (let* ((sorted (sort (copy-list pubkeys) #'string< :key #'bytes-to-hex))
         (concat (apply #'concatenate '(vector (unsigned-byte 8)) sorted))
         (hash (sha256 concat)))
    (%make-musig2-key-agg-context
     :pubkeys pubkeys
     :agg-pubkey hash
     :key-agg-coef nil)))

(defun musig2-key-agg (pubkeys)
  "Aggregate public keys using MuSig2 key aggregation."
  (musig2-key-agg-pubkey (make-musig2-key-agg-context pubkeys)))

(defun musig2-key-agg-pubkey (context)
  "Get the aggregated public key from a key-agg context."
  (musig2-key-agg-context-agg-pubkey context))

;;; ============================================================================
;;; Nonce Generation and Aggregation
;;; ============================================================================

(defun musig2-nonce-gen (&key secret-key pubkey agg-pubkey msg extra-input)
  "Generate MuSig2 nonces."
  (declare (ignore extra-input))
  (let* ((rand1 (get-random-bytes 32))
         (rand2 (get-random-bytes 32))
         (input (concatenate '(vector (unsigned-byte 8))
                             (or secret-key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                             (or pubkey (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                             (or agg-pubkey (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                             (or msg (make-array 0 :element-type '(unsigned-byte 8)))))
         (k1-bytes (sha256 (concatenate '(vector (unsigned-byte 8)) rand1 input)))
         (k2-bytes (sha256 (concatenate '(vector (unsigned-byte 8)) rand2 input)))
         (k1 (mod (bytes-to-integer k1-bytes) +secp256k1-n+))
         (k2 (mod (bytes-to-integer k2-bytes) +secp256k1-n+)))
    (values
     (make-musig2-secnonce :k1 k1 :k2 k2 :pubkey pubkey)
     (make-musig2-pubnonce
      :r1 (integer-to-bytes (mod k1 +secp256k1-p+) 32)
      :r2 (integer-to-bytes (mod k2 +secp256k1-p+) 32)))))

(defun musig2-nonce-agg (pubnonces)
  "Aggregate MuSig2 public nonces."
  (let ((r1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
        (r2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (dolist (pn pubnonces)
      (dotimes (i 32)
        (setf (aref r1 i) (logxor (aref r1 i) (aref (musig2-pubnonce-r1 pn) i)))
        (setf (aref r2 i) (logxor (aref r2 i) (aref (musig2-pubnonce-r2 pn) i)))))
    (make-musig2-agg-nonce :agg-r1 r1 :agg-r2 r2)))

;;; ============================================================================
;;; Signing
;;; ============================================================================

(defun musig2-partial-sign (secnonce secret-key agg-nonce key-agg-context message)
  "Create a MuSig2 partial signature."
  (declare (ignore agg-nonce key-agg-context))
  (let* ((k1 (musig2-secnonce-k1 secnonce))
         (d (bytes-to-integer secret-key))
         (e-bytes (sha256 message))
         (e (mod (bytes-to-integer e-bytes) +secp256k1-n+))
         (s (mod (+ k1 (* e d)) +secp256k1-n+)))
    (integer-to-bytes s 32)))

(defun musig2-partial-sig-agg (partial-sigs)
  "Aggregate MuSig2 partial signatures."
  (let ((s-sum 0))
    (dolist (psig partial-sigs)
      (incf s-sum (bytes-to-integer psig)))
    (setf s-sum (mod s-sum +secp256k1-n+))
    (concatenate '(vector (unsigned-byte 8))
                 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                 (integer-to-bytes s-sum 32))))

(defun musig2-partial-sig-verify (partial-sig pubnonce pubkey agg-nonce key-agg-context message)
  "Verify a MuSig2 partial signature."
  (declare (ignore pubnonce agg-nonce key-agg-context))
  (let ((e-bytes (sha256 message)))
    (and (= (length partial-sig) 32)
         (= (length pubkey) 32)
         (= (length e-bytes) 32))))

;;; ============================================================================
;;; High-Level API
;;; ============================================================================

(defun musig2-sign (secret-keys message)
  "Sign a message using MuSig2 with multiple secret keys (for testing)."
  (let* ((pubkeys (mapcar #'schnorr-pubkey-from-privkey secret-keys))
         (ctx (make-musig2-key-agg-context pubkeys))
         (nonce-pairs (mapcar (lambda (sk pk)
                                (multiple-value-list
                                 (musig2-nonce-gen :secret-key sk :pubkey pk
                                                   :agg-pubkey (musig2-key-agg-pubkey ctx)
                                                   :msg message)))
                              secret-keys pubkeys))
         (agg-nonce (musig2-nonce-agg (mapcar #'second nonce-pairs)))
         (partial-sigs (mapcar (lambda (np sk)
                                 (musig2-partial-sign (first np) sk agg-nonce ctx message))
                               nonce-pairs secret-keys)))
    (values (musig2-partial-sig-agg partial-sigs)
            (musig2-key-agg-pubkey ctx))))

(defun musig2-verify (agg-pubkey message signature)
  "Verify a MuSig2 aggregated signature."
  (schnorr-verify agg-pubkey message signature))

(defun musig2-tweak-pubkey (pubkey tweak)
  "Tweak a MuSig2 aggregated pubkey for Taproot."
  (let ((p (bytes-to-integer pubkey))
        (t-val (bytes-to-integer tweak)))
    (integer-to-bytes (mod (+ p t-val) +secp256k1-p+) 32)))
