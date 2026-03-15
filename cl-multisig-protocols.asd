;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;; ============================================================================
;;;; CL-MULTISIG-PROTOCOLS - Threshold Multi-Signature Protocols for Common Lisp
;;;; ============================================================================
;;;;
;;;; A standalone implementation of threshold multi-signature protocols:
;;;; - MuSig2 (BIP327): N-of-N multi-party Schnorr signatures
;;;; - FROST: t-of-n threshold Schnorr signatures (IETF draft compliant)
;;;;
;;;; Features:
;;;; - Pure Common Lisp with inlined secp256k1 and Schnorr primitives
;;;; - No external dependencies (SBCL native threading/sockets only)
;;;; - Constant-time cryptographic operations
;;;; - BIP340 Schnorr signature compatible
;;;; - Taproot (BIP341) key tweaking support
;;;;
;;;; License: MIT
;;;; ============================================================================

(asdf:defsystem #:cl-multisig-protocols
  :name "cl-multisig-protocols"
  :version "0.1.0"
  :author "Park Ian Co"
  :license "Apache-2.0"
  :description "Threshold multi-signature protocols (MuSig2, FROST) for Common Lisp"
  :long-description "A standalone implementation of MuSig2 and FROST threshold signature protocols with inlined secp256k1 and Schnorr primitives. Suitable for cryptocurrency wallets and distributed signing applications."

  :depends-on ()

  :serial t
  :components
  ((:file "package")
   (:module "src"
    :serial t
    :components
    ((:file "util")
     (:file "coordinator")
     (:file "participant")
     (:file "musig2")
     (:file "frost")
     (:file "multisig"))))

  :in-order-to ((asdf:test-op (test-op #:cl-multisig-protocols/test))))

(asdf:defsystem #:cl-multisig-protocols/test
  :name "cl-multisig-protocols"
  :version "0.1.0"
  :description "Tests for cl-multisig-protocols"
  :depends-on (#:cl-multisig-protocols)
  :serial t
  :components
  ((:module "test"
    :components
    ((:file "test-multisig"))))
  :perform (asdf:test-op (op c)
             (let ((result (uiop:symbol-call :cl-multisig-protocols.test :run-all-tests)))
               (unless result
                 (error "Tests failed")))))
