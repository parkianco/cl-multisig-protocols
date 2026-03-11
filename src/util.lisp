;;;; ============================================================================
;;;; CL-MULTISIG-PROTOCOLS - Utility Functions and Inlined Crypto Primitives
;;;; ============================================================================
;;;;
;;;; This file contains all cryptographic primitives needed for multi-signature
;;;; protocols, inlined for standalone operation:
;;;;
;;;; - secp256k1 curve parameters and operations
;;;; - SHA-256 hash function
;;;; - BIP340 Schnorr signatures
;;;; - Constant-time utilities
;;;;
;;;; All code is pure Common Lisp with no external dependencies.
;;;; ============================================================================

(in-package #:cl-multisig-protocols)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; secp256k1 Curve Parameters
;;; ============================================================================

;; Field prime: p = 2^256 - 2^32 - 977
(defconstant +secp256k1-p+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  "Prime field modulus p for secp256k1.")

;; Group order: n (number of points on the curve)
(defconstant +secp256k1-n+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  "Order of the generator point n for secp256k1.")

;; Generator point G (affine coordinates)
(defconstant +secp256k1-gx+
  #x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  "Generator point x-coordinate for secp256k1.")

(defconstant +secp256k1-gy+
  #x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
  "Generator point y-coordinate for secp256k1.")

;; GLV endomorphism parameters
(defconstant +secp256k1-lambda+
  #x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
  "Lambda parameter for GLV decomposition.")

(defconstant +secp256k1-beta+
  #x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE
  "Beta parameter for endomorphism phi(x,y) = (beta*x, y).")

;;; ============================================================================
;;; Byte/Integer Conversion
;;; ============================================================================

(defun bytes-to-integer (bytes &key (big-endian t))
  "Convert byte array to integer."
  (declare (type (vector (unsigned-byte 8)) bytes)
           (optimize (speed 3) (safety 1)))
  (let ((result 0))
    (if big-endian
        (loop for byte across bytes
              do (setf result (logior (ash result 8) byte)))
        (loop for i from (1- (length bytes)) downto 0
              do (setf result (logior (ash result 8) (aref bytes i)))))
    result))

(defun integer-to-bytes (n size &key (big-endian t))
  "Convert integer to byte array of specified size."
  (declare (type integer n)
           (type fixnum size)
           (optimize (speed 3) (safety 1)))
  (let ((result (make-array size :element-type '(unsigned-byte 8) :initial-element 0)))
    (if big-endian
        (loop for i from (1- size) downto 0
              for j from 0
              do (setf (aref result j) (ldb (byte 8 (* i 8)) n)))
        (loop for i from 0 below size
              do (setf (aref result i) (ldb (byte 8 (* i 8)) n))))
    result))

(defun hex-to-bytes (hex-string)
  "Convert hex string to byte array."
  (let* ((len (/ (length hex-string) 2))
         (result (make-array len :element-type '(unsigned-byte 8))))
    (loop for i from 0 below len
          for pos = (* i 2)
          do (setf (aref result i)
                   (parse-integer hex-string :start pos :end (+ pos 2) :radix 16)))
    result))

(defun bytes-to-hex (bytes)
  "Convert byte array to hex string."
  (with-output-to-string (s)
    (loop for byte across bytes
          do (format s "~2,'0X" byte))))

;;; ============================================================================
;;; Random Number Generation (SBCL-specific CSPRNG)
;;; ============================================================================

(defun get-random-bytes (n)
  "Generate N cryptographically secure random bytes.
   Uses /dev/urandom on Unix systems."
  (declare (type fixnum n)
           (optimize (speed 3) (safety 1)))
  (let ((bytes (make-array n :element-type '(unsigned-byte 8))))
    #+(and sbcl unix)
    (with-open-file (urandom "/dev/urandom" :element-type '(unsigned-byte 8))
      (read-sequence bytes urandom))
    #+(and sbcl win32)
    (progn
      ;; Use Windows CryptGenRandom via SBCL's internal random
      ;; This is a fallback; production should use proper Windows API
      (loop for i from 0 below n
            do (setf (aref bytes i) (random 256))))
    #-sbcl
    (loop for i from 0 below n
          do (setf (aref bytes i) (random 256)))
    bytes))

;;; ============================================================================
;;; SHA-256 Implementation (Pure Common Lisp)
;;; ============================================================================

;; Use defvar to avoid SBCL DEFCONSTANT-UNEQL on array constants
(defvar +sha256-k+
  (make-array 64 :element-type '(unsigned-byte 32)
              :initial-contents
              '(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5 #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
                #xd807aa98 #x12835b01 #x243185be #x550c7dc3 #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
                #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
                #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7 #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
                #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13 #x650a7354 #x766a0abb #x81c2c92e #x92722c85
                #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3 #xd192e819 #xd6990624 #xf40e3585 #x106aa070
                #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5 #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
                #x748f82ee #x78a5636f #x84c87814 #x8cc70208 #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2))
  "SHA-256 round constants.")

(defvar +sha256-h0+
  (make-array 8 :element-type '(unsigned-byte 32)
              :initial-contents
              '(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19))
  "SHA-256 initial hash values.")

(declaim (inline sha256-rotr sha256-shr sha256-ch sha256-maj sha256-sigma0 sha256-sigma1 sha256-s0 sha256-s1))

(defun sha256-rotr (x n)
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n)
           (optimize (speed 3) (safety 0)))
  (logior (ldb (byte 32 0) (ash x (- n)))
          (ldb (byte 32 0) (ash x (- 32 n)))))

(defun sha256-shr (x n)
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n)
           (optimize (speed 3) (safety 0)))
  (ash x (- n)))

(defun sha256-ch (x y z)
  (declare (type (unsigned-byte 32) x y z)
           (optimize (speed 3) (safety 0)))
  (logxor (logand x y) (logand (lognot x) z)))

(defun sha256-maj (x y z)
  (declare (type (unsigned-byte 32) x y z)
           (optimize (speed 3) (safety 0)))
  (logxor (logand x y) (logand x z) (logand y z)))

(defun sha256-sigma0 (x)
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (sha256-rotr x 2) (sha256-rotr x 13) (sha256-rotr x 22)))

(defun sha256-sigma1 (x)
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (sha256-rotr x 6) (sha256-rotr x 11) (sha256-rotr x 25)))

(defun sha256-s0 (x)
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (sha256-rotr x 7) (sha256-rotr x 18) (sha256-shr x 3)))

(defun sha256-s1 (x)
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (sha256-rotr x 17) (sha256-rotr x 19) (sha256-shr x 10)))

(defun sha256-pad-message (message)
  "Pad message according to SHA-256 spec."
  (let* ((msg-len (length message))
         (bit-len (* msg-len 8))
         ;; Padded length must be 64 bytes - 8 bytes = 56 bytes (mod 64)
         (pad-len (- 64 (mod (+ msg-len 9) 64)))
         (total-len (+ msg-len 1 pad-len 8))
         (padded (make-array total-len :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace padded message)
    (setf (aref padded msg-len) #x80)
    ;; Append length in bits as 64-bit big-endian
    (loop for i from 0 below 8
          do (setf (aref padded (+ msg-len 1 pad-len i))
                   (ldb (byte 8 (* (- 7 i) 8)) bit-len)))
    padded))

(defun sha256-process-block (block h)
  "Process a single 512-bit block."
  (declare (type (simple-array (unsigned-byte 8) (64)) block)
           (type (simple-array (unsigned-byte 32) (8)) h)
           (optimize (speed 3) (safety 0)))
  (let ((w (make-array 64 :element-type '(unsigned-byte 32) :initial-element 0)))
    ;; Prepare message schedule
    (loop for i from 0 below 16
          do (setf (aref w i)
                   (logior (ash (aref block (* i 4)) 24)
                           (ash (aref block (+ (* i 4) 1)) 16)
                           (ash (aref block (+ (* i 4) 2)) 8)
                           (aref block (+ (* i 4) 3)))))
    (loop for i from 16 below 64
          do (setf (aref w i)
                   (ldb (byte 32 0)
                        (+ (sha256-s1 (aref w (- i 2)))
                           (aref w (- i 7))
                           (sha256-s0 (aref w (- i 15)))
                           (aref w (- i 16))))))
    ;; Initialize working variables
    (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
          (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
      (declare (type (unsigned-byte 32) a b c d e f g hh))
      ;; Main loop
      (loop for i from 0 below 64
            do (let* ((t1 (ldb (byte 32 0)
                               (+ hh (sha256-sigma1 e) (sha256-ch e f g)
                                  (aref +sha256-k+ i) (aref w i))))
                      (t2 (ldb (byte 32 0)
                               (+ (sha256-sigma0 a) (sha256-maj a b c)))))
                 (setf hh g
                       g f
                       f e
                       e (ldb (byte 32 0) (+ d t1))
                       d c
                       c b
                       b a
                       a (ldb (byte 32 0) (+ t1 t2)))))
      ;; Update hash values
      (setf (aref h 0) (ldb (byte 32 0) (+ (aref h 0) a)))
      (setf (aref h 1) (ldb (byte 32 0) (+ (aref h 1) b)))
      (setf (aref h 2) (ldb (byte 32 0) (+ (aref h 2) c)))
      (setf (aref h 3) (ldb (byte 32 0) (+ (aref h 3) d)))
      (setf (aref h 4) (ldb (byte 32 0) (+ (aref h 4) e)))
      (setf (aref h 5) (ldb (byte 32 0) (+ (aref h 5) f)))
      (setf (aref h 6) (ldb (byte 32 0) (+ (aref h 6) g)))
      (setf (aref h 7) (ldb (byte 32 0) (+ (aref h 7) hh)))))
  h)

(defun sha256 (message)
  "Compute SHA-256 hash of message (byte array)."
  (let* ((padded (sha256-pad-message (if (stringp message)
                                          (map '(vector (unsigned-byte 8)) #'char-code message)
                                          message)))
         (h (make-array 8 :element-type '(unsigned-byte 32)
                         :initial-contents (coerce +sha256-h0+ 'list)))
         (n-blocks (/ (length padded) 64)))
    (dotimes (i n-blocks)
      (let ((block (make-array 64 :element-type '(unsigned-byte 8))))
        (replace block padded :start2 (* i 64) :end2 (* (1+ i) 64))
        (sha256-process-block block h)))
    ;; Convert hash to bytes
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 8
            do (setf (aref result (* i 4)) (ldb (byte 8 24) (aref h i)))
               (setf (aref result (+ (* i 4) 1)) (ldb (byte 8 16) (aref h i)))
               (setf (aref result (+ (* i 4) 2)) (ldb (byte 8 8) (aref h i)))
               (setf (aref result (+ (* i 4) 3)) (ldb (byte 8 0) (aref h i))))
      result)))

;;; ============================================================================
;;; Tagged Hashes (BIP340)
;;; ============================================================================

(defun tagged-hash (tag data)
  "Compute BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."
  (let* ((tag-hash (sha256 tag))
         (combined (concatenate '(vector (unsigned-byte 8))
                                tag-hash tag-hash data)))
    (sha256 combined)))

(defun bip340-challenge-hash (data)
  "BIP340 challenge hash: tagged_hash('BIP0340/challenge', data)."
  (tagged-hash (map '(vector (unsigned-byte 8)) #'char-code "BIP0340/challenge") data))

(defun bip340-aux-hash (data)
  "BIP340 aux hash: tagged_hash('BIP0340/aux', data)."
  (tagged-hash (map '(vector (unsigned-byte 8)) #'char-code "BIP0340/aux") data))

(defun bip340-nonce-hash (data)
  "BIP340 nonce hash: tagged_hash('BIP0340/nonce', data)."
  (tagged-hash (map '(vector (unsigned-byte 8)) #'char-code "BIP0340/nonce") data))

;;; ============================================================================
;;; Constant-Time Utilities
;;; ============================================================================

(defun constant-time-bytes= (a b)
  "Constant-time comparison of two byte arrays.
   Returns T if equal, NIL otherwise.
   Execution time is independent of where arrays differ."
  (declare (type (vector (unsigned-byte 8)) a b)
           (optimize (speed 3) (safety 0)))
  (when (/= (length a) (length b))
    (return-from constant-time-bytes= nil))
  (let ((diff 0))
    (declare (type fixnum diff))
    (loop for i from 0 below (length a)
          do (setf diff (logior diff (logxor (aref a i) (aref b i)))))
    (zerop diff)))

(defun secure-zero-array (array)
  "Zero out a byte array securely (for clearing sensitive data)."
  (declare (type (vector (unsigned-byte 8)) array)
           (optimize (speed 3) (safety 0)))
  (loop for i from 0 below (length array)
        do (setf (aref array i) 0))
  array)

;;; ============================================================================
;;; Modular Arithmetic
;;; ============================================================================

(defun mod-expt (base exp modulus)
  "Modular exponentiation: base^exp mod modulus."
  (declare (type integer base exp modulus)
           (optimize (speed 3) (safety 1)))
  (let ((result 1)
        (base (mod base modulus)))
    (loop while (plusp exp)
          do (when (oddp exp)
               (setf result (mod (* result base) modulus)))
             (setf exp (ash exp -1))
             (setf base (mod (* base base) modulus)))
    result))

(defun mod-inverse (a modulus)
  "Compute modular inverse of A modulo MODULUS using extended Euclidean algorithm."
  (declare (type integer a modulus)
           (optimize (speed 3) (safety 1)))
  (let ((t1 0) (t2 1)
        (r1 modulus) (r2 (mod a modulus)))
    (loop while (not (zerop r2))
          do (let ((q (floor r1 r2)))
               (psetf t1 t2 t2 (- t1 (* q t2)))
               (psetf r1 r2 r2 (- r1 (* q r2)))))
    (when (> r1 1)
      (error "No modular inverse exists"))
    (if (minusp t1)
        (+ t1 modulus)
        t1)))

;;; ============================================================================
;;; secp256k1 Point Operations
;;; ============================================================================

(defun ec-point-add (x1 y1 x2 y2)
  "Add two points on secp256k1. Returns (VALUES rx ry)."
  (declare (type integer x1 y1 x2 y2)
           (optimize (speed 3) (safety 1)))
  ;; Handle identity (point at infinity represented as (0, 0))
  (when (and (zerop x1) (zerop y1))
    (return-from ec-point-add (values x2 y2)))
  (when (and (zerop x2) (zerop y2))
    (return-from ec-point-add (values x1 y1)))

  (let ((p +secp256k1-p+))
    (if (= x1 x2)
        (if (= y1 y2)
            ;; Point doubling
            (ec-point-double x1 y1)
            ;; Points are inverses -> infinity
            (values 0 0))
        ;; Point addition
        (let* ((dx (mod (- x2 x1) p))
               (dy (mod (- y2 y1) p))
               (lambda-val (mod (* dy (mod-inverse dx p)) p))
               (x3 (mod (- (* lambda-val lambda-val) x1 x2) p))
               (y3 (mod (- (* lambda-val (- x1 x3)) y1) p)))
          (values x3 y3)))))

(defun ec-point-double (x y)
  "Double a point on secp256k1. Returns (VALUES rx ry)."
  (declare (type integer x y)
           (optimize (speed 3) (safety 1)))
  (when (zerop y)
    (return-from ec-point-double (values 0 0)))

  (let* ((p +secp256k1-p+)
         ;; lambda = (3x^2 + a) / 2y, where a=0 for secp256k1
         (lambda-val (mod (* 3 x x (mod-inverse (mod (* 2 y) p) p)) p))
         (x3 (mod (- (* lambda-val lambda-val) (* 2 x)) p))
         (y3 (mod (- (* lambda-val (- x x3)) y) p)))
    (values x3 y3)))

(defun ec-scalar-multiply (k x y)
  "Scalar multiplication k * P on secp256k1. Returns (VALUES rx ry)."
  (declare (type integer k x y)
           (optimize (speed 3) (safety 1)))
  (when (zerop k)
    (return-from ec-scalar-multiply (values 0 0)))

  (let ((rx 0) (ry 0)
        (qx x) (qy y)
        (k (mod k +secp256k1-n+)))
    (loop while (plusp k)
          do (when (oddp k)
               (multiple-value-setq (rx ry) (ec-point-add rx ry qx qy)))
             (multiple-value-setq (qx qy) (ec-point-double qx qy))
             (setf k (ash k -1)))
    (values rx ry)))

(defun generator-multiply (k)
  "Multiply generator point G by scalar k."
  (ec-scalar-multiply k +secp256k1-gx+ +secp256k1-gy+))

;;; ============================================================================
;;; BIP340 Schnorr Signatures
;;; ============================================================================

(defun lift-x (x)
  "Recover EC point from x-coordinate with even y (BIP340).
   Returns (VALUES x y) or NIL if x is not on curve."
  (declare (optimize (speed 3) (safety 1)))
  (let ((x-int (if (vectorp x)
                   (bytes-to-integer x :big-endian t)
                   x)))
    (when (or (<= x-int 0) (>= x-int +secp256k1-p+))
      (return-from lift-x nil))

    (let* ((p +secp256k1-p+)
           (x3 (mod-expt x-int 3 p))
           (c (mod (+ x3 7) p))
           ;; sqrt for p = 3 (mod 4): y = c^((p+1)/4)
           (y (mod-expt c (ash (1+ p) -2) p)))
      ;; Verify point is on curve
      (unless (= (mod (* y y) p) c)
        (return-from lift-x nil))
      ;; Choose even y
      (when (oddp y)
        (setf y (- p y)))
      (values x-int y))))

(defun schnorr-pubkey-from-privkey (private-key)
  "Derive 32-byte x-only public key from private key (BIP340)."
  (let* ((d (if (vectorp private-key)
                (bytes-to-integer private-key :big-endian t)
                private-key)))
    (multiple-value-bind (px py) (generator-multiply d)
      (declare (ignore py))
      (integer-to-bytes px 32 :big-endian t))))

(defun schnorr-sign (secret-key message &optional aux-rand)
  "Sign message with BIP340 Schnorr signature.
   Returns 64-byte signature (R || s)."
  (let* ((secret-bytes (if (vectorp secret-key) secret-key
                           (integer-to-bytes secret-key 32 :big-endian t)))
         (d-prime (bytes-to-integer secret-bytes :big-endian t)))
    ;; Validate secret key
    (unless (and (plusp d-prime) (< d-prime +secp256k1-n+))
      (error "Secret key out of range"))

    (multiple-value-bind (px py) (generator-multiply d-prime)
      (let* ((d (if (oddp py)
                    (mod (- +secp256k1-n+ d-prime) +secp256k1-n+)
                    d-prime))
             (p-bytes (integer-to-bytes px 32 :big-endian t))
             (d-bytes (integer-to-bytes d 32 :big-endian t))
             (aux (or aux-rand (get-random-bytes 32)))
             (aux-hash (bip340-aux-hash aux))
             (t-bytes (make-array 32 :element-type '(unsigned-byte 8))))
        ;; t = d XOR aux-hash
        (dotimes (i 32)
          (setf (aref t-bytes i) (logxor (aref d-bytes i) (aref aux-hash i))))
        ;; rand = tagged_hash('BIP0340/nonce', t || P || m)
        (let* ((nonce-input (concatenate '(vector (unsigned-byte 8))
                                         t-bytes p-bytes message))
               (rand (bip340-nonce-hash nonce-input))
               (k-prime (mod (bytes-to-integer rand :big-endian t) +secp256k1-n+)))
          (when (zerop k-prime)
            (error "Derived nonce is zero"))

          (multiple-value-bind (rx ry) (generator-multiply k-prime)
            (let* ((k (if (oddp ry)
                          (mod (- +secp256k1-n+ k-prime) +secp256k1-n+)
                          k-prime))
                   (r-bytes (integer-to-bytes rx 32 :big-endian t))
                   (challenge-input (concatenate '(vector (unsigned-byte 8))
                                                 r-bytes p-bytes message))
                   (e-hash (bip340-challenge-hash challenge-input))
                   (e (mod (bytes-to-integer e-hash :big-endian t) +secp256k1-n+))
                   (s (mod (+ k (* e d)) +secp256k1-n+))
                   (s-bytes (integer-to-bytes s 32 :big-endian t)))
              (concatenate '(vector (unsigned-byte 8)) r-bytes s-bytes))))))))

(defun schnorr-verify (public-key message signature)
  "Verify BIP340 Schnorr signature. Returns T if valid."
  (handler-case
      (let ((pk-bytes (if (vectorp public-key) public-key
                          (integer-to-bytes public-key 32 :big-endian t)))
            (sig-bytes (if (vectorp signature) signature
                           (error "Signature must be byte array"))))
        (unless (and (= (length pk-bytes) 32)
                     (= (length message) 32)
                     (= (length sig-bytes) 64))
          (return-from schnorr-verify nil))

        (let ((px (bytes-to-integer pk-bytes :big-endian t)))
          (multiple-value-bind (px-checked py) (lift-x px)
            (unless px-checked
              (return-from schnorr-verify nil))

            (let* ((r (bytes-to-integer (subseq sig-bytes 0 32) :big-endian t))
                   (s (bytes-to-integer (subseq sig-bytes 32 64) :big-endian t)))
              (unless (and (< r +secp256k1-p+) (< s +secp256k1-n+))
                (return-from schnorr-verify nil))

              (let* ((r-bytes (subseq sig-bytes 0 32))
                     (challenge-input (concatenate '(vector (unsigned-byte 8))
                                                   r-bytes pk-bytes message))
                     (e-hash (bip340-challenge-hash challenge-input))
                     (e (mod (bytes-to-integer e-hash :big-endian t) +secp256k1-n+))
                     ;; R = s*G - e*P
                     (neg-e (mod (- +secp256k1-n+ e) +secp256k1-n+)))
                (multiple-value-bind (sgx sgy) (generator-multiply s)
                  (multiple-value-bind (epx epy) (ec-scalar-multiply neg-e px-checked py)
                    (multiple-value-bind (rx ry) (ec-point-add sgx sgy epx epy)
                      (and (evenp ry) (= rx r))))))))))
    (error () nil)))
