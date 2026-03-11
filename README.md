# cl-multisig-protocols

Threshold multi-signature protocols (MuSig2, FROST) with **zero external dependencies**.

## Features

- **MuSig2**: Two-round multi-signature protocol
- **FROST**: Flexible Round-Optimized Schnorr Threshold
- **Key aggregation**: Combine public keys
- **Adaptor signatures**: Atomic swap support
- **Pure Common Lisp**: No CFFI, no external libraries

## Installation

```lisp
(asdf:load-system :cl-multisig-protocols)
```

## Quick Start

```lisp
(use-package :cl-multisig-protocols)

;; MuSig2: 2-of-2 signing
(let* ((keys (list (generate-keypair) (generate-keypair)))
       (pubkeys (mapcar #'keypair-public keys))
       (agg-pubkey (musig2-aggregate-pubkeys pubkeys)))
  ;; Round 1: Generate nonces
  (let ((nonces (mapcar #'musig2-nonce-gen keys)))
    ;; Round 2: Generate partial signatures
    (let ((partials (mapcar (lambda (key nonce)
                              (musig2-sign key message nonces nonce))
                            keys nonces)))
      ;; Aggregate
      (musig2-aggregate-sigs partials))))
```

## API Reference

### MuSig2

- `(musig2-aggregate-pubkeys pubkeys)` - Aggregate public keys
- `(musig2-nonce-gen keypair)` - Generate nonce pair
- `(musig2-sign keypair message all-nonces my-nonce)` - Generate partial sig
- `(musig2-aggregate-sigs partials)` - Aggregate to final signature

### FROST

- `(frost-keygen threshold participants)` - Distributed key generation
- `(frost-sign shares message)` - Threshold signing
- `(frost-verify signature pubkey message)` - Verify signature

## Testing

```lisp
(asdf:test-system :cl-multisig-protocols)
```

## License

BSD-3-Clause

Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
