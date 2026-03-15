;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; ============================================================================
;;;; CL-MULTISIG-PROTOCOLS - Package Definitions
;;;; ============================================================================

(defpackage #:cl-multisig-protocols
  (:use #:cl)
  (:nicknames #:multisig-protocols #:msp)

  ;; ============================================================================
  ;; secp256k1 Constants and Parameters
  ;; ============================================================================
  (:export
   #:deep-copy-list
   #:group-by-count
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-multisig-protocols-timing
   #:multisig-protocols-batch-process
   #:multisig-protocols-health-check#:+secp256k1-p+
   #:+secp256k1-n+
   #:+secp256k1-gx+
   #:+secp256k1-gy+
   #:+secp256k1-lambda+
   #:+secp256k1-beta+)

  ;; ============================================================================
  ;; Utility Functions
  ;; ============================================================================
  (:export
   #:deep-copy-list
   #:group-by-count
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-multisig-protocols-timing
   #:multisig-protocols-batch-process
   #:multisig-protocols-health-check#:bytes-to-integer
   #:integer-to-bytes
   #:get-random-bytes
   #:sha256
   #:tagged-hash
   #:constant-time-bytes=
   #:hex-to-bytes
   #:bytes-to-hex)

  ;; ============================================================================
  ;; Schnorr Signatures (BIP340)
  ;; ============================================================================
  (:export
   #:deep-copy-list
   #:group-by-count
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-multisig-protocols-timing
   #:multisig-protocols-batch-process
   #:multisig-protocols-health-check#:schnorr-sign
   #:schnorr-verify
   #:schnorr-pubkey-from-privkey
   #:lift-x)

  ;; ============================================================================
  ;; MuSig2 Protocol (BIP327)
  ;; ============================================================================
  (:export
   #:deep-copy-list
   #:group-by-count
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-multisig-protocols-timing
   #:multisig-protocols-batch-process
   #:multisig-protocols-health-check;; Key aggregation
   #:musig2-key-agg-context
   #:make-musig2-key-agg-context
   #:musig2-key-agg
   #:musig2-key-agg-pubkey

   ;; Nonce structures
   #:musig2-secnonce
   #:musig2-pubnonce
   #:musig2-agg-nonce

   ;; Nonce generation and aggregation
   #:musig2-nonce-gen
   #:musig2-nonce-agg

   ;; Signing
   #:musig2-partial-sign
   #:musig2-partial-sig-agg
   #:musig2-partial-sig-verify

   ;; High-level API
   #:musig2-sign
   #:musig2-verify

   ;; Taproot tweaking
   #:musig2-tweak-pubkey)

  ;; ============================================================================
  ;; FROST Protocol (IETF Draft)
  ;; ============================================================================
  (:export
   #:deep-copy-list
   #:group-by-count
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-multisig-protocols-timing
   #:multisig-protocols-batch-process
   #:multisig-protocols-health-check;; Ciphersuites
   #:frost-ciphersuite
   #:+frost-secp256k1-sha256+
   #:*frost-ciphersuite*

   ;; Parameters and keypairs
   #:frost-params
   #:make-frost-params
   #:frost-keypair
   #:frost-keypair-index
   #:frost-keypair-secret-share
   #:frost-keypair-public-share
   #:frost-keypair-group-public-key

   ;; DKG
   #:frost-dkg-state
   #:frost-dkg-begin
   #:frost-dkg-compute-shares
   #:frost-dkg-verify-share
   #:frost-dkg-finalize

   ;; Signing
   #:signing-commitment
   #:signature-share
   #:frost-signature
   #:frost-signing-state
   #:frost-generate-nonces
   #:frost-sign-begin
   #:frost-sign-round1
   #:frost-sign-round2
   #:frost-sign-aggregate
   #:frost-verify)

  ;; ============================================================================
  ;; Signing Coordinator
  ;; ============================================================================
  (:export
   #:deep-copy-list
   #:group-by-count
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-multisig-protocols-timing
   #:multisig-protocols-batch-process
   #:multisig-protocols-health-check#:signing-coordinator
   #:make-signing-coordinator
   #:coordinator-add-participant
   #:coordinator-remove-participant
   #:coordinator-start-session
   #:coordinator-receive-commitment
   #:coordinator-receive-partial-sig
   #:coordinator-get-final-signature
   #:coordinator-abort)

  ;; ============================================================================
  ;; Signing Participant
  ;; ============================================================================
  (:export
   #:deep-copy-list
   #:group-by-count
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-multisig-protocols-timing
   #:multisig-protocols-batch-process
   #:multisig-protocols-health-check#:signing-participant
   #:make-signing-participant
   #:participant-keypair
   #:participant-generate-commitment
   #:participant-receive-commitments
   #:participant-create-partial-sig
   #:participant-verify-final-sig)

  ;; ============================================================================
  ;; High-Level Multisig Interface
  ;; ============================================================================
  (:export
   #:deep-copy-list
   #:group-by-count
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-multisig-protocols-timing
   #:multisig-protocols-batch-process
   #:multisig-protocols-health-check;; Wallet types
   #:multisig-wallet
   #:make-multisig-wallet
   #:multisig-wallet-type
   #:multisig-wallet-threshold
   #:multisig-wallet-total-signers
   #:multisig-wallet-pubkeys

   ;; Signing session
   #:signing-session
   #:create-signing-session
   #:session-add-signature
   #:session-finalize
   #:session-complete-p

   ;; Conditions
   #:multisig-error
   #:invalid-threshold-error
   #:insufficient-signatures-error
   #:signature-verification-error
   #:nonce-reuse-error))

(defpackage #:cl-multisig-protocols.test
  (:use #:cl #:cl-multisig-protocols)
  (:export
   #:deep-copy-list
   #:group-by-count
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-multisig-protocols-timing
   #:multisig-protocols-batch-process
   #:multisig-protocols-health-check#:run-all-tests))
