/**
 * QMOOSA Post-Quantum Cryptography Protocol Specification
 * Standards Baseline: NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism)
 */

export const FIPS_203_STANDARD = 'FIPS 203' as const;
export const SPECIFICATION_VERSION = '1.0.0' as const;

/**
 * Algebraic constants in the polynomial ring R_q = Z_q[X] / (X^256 + 1)
 */
export const ML_KEM_RING_DEGREE = 256 as const;
export const ML_KEM_MODULUS = 3329 as const;
export const ML_KEM_PRIMITIVE_ROOT = 17 as const; // 256th primitive root of unity modulo 3329
export const ML_KEM_SHARED_SECRET_BYTES = 32 as const;
export const ML_KEM_SEED_BYTES = 32 as const;

export type MlKemParameterName = 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';

export interface MlKemParameters {
  readonly name: MlKemParameterName;
  readonly k: number; // Module rank / dimension
  readonly eta1: number; // Centered binomial distribution parameter 1
  readonly eta2: number; // Centered binomial distribution parameter 2
  readonly du: number; // Poly vector compression parameter
  readonly dv: number; // Poly compression parameter
  readonly encapsulationKeyBytes: number; // ek length in bytes (800, 1184, 1568)
  readonly decapsulationKeyBytes: number; // dk length in bytes (1632, 2400, 3168)
  readonly ciphertextBytes: number; // ciphertext length in bytes (768, 1088, 1568)
  readonly sharedSecretBytes: number; // shared secret length in bytes (32)
  readonly securityCategory: number; // NIST Security Category (1, 3, 5)
  readonly claimedSecurity: string;
}

export const ML_KEM_512: Readonly<MlKemParameters> = Object.freeze({
  name: 'ML-KEM-512',
  k: 2,
  eta1: 3,
  eta2: 2,
  du: 10,
  dv: 4,
  encapsulationKeyBytes: 800,
  decapsulationKeyBytes: 1632,
  ciphertextBytes: 768,
  sharedSecretBytes: 32,
  securityCategory: 1,
  claimedSecurity: 'NIST Level 1 (AES-128 equivalent)'
});

export const ML_KEM_768: Readonly<MlKemParameters> = Object.freeze({
  name: 'ML-KEM-768',
  k: 3,
  eta1: 2,
  eta2: 2,
  du: 10,
  dv: 4,
  encapsulationKeyBytes: 1184,
  decapsulationKeyBytes: 2400,
  ciphertextBytes: 1088,
  sharedSecretBytes: 32,
  securityCategory: 3,
  claimedSecurity: 'NIST Level 3 (AES-192 equivalent, primary recommended parameter set)'
});

export const ML_KEM_1024: Readonly<MlKemParameters> = Object.freeze({
  name: 'ML-KEM-1024',
  k: 4,
  eta1: 2,
  eta2: 2,
  du: 11,
  dv: 5,
  encapsulationKeyBytes: 1568,
  decapsulationKeyBytes: 3168,
  ciphertextBytes: 1568,
  sharedSecretBytes: 32,
  securityCategory: 5,
  claimedSecurity: 'NIST Level 5 (AES-256 equivalent)'
});

export const ML_KEM_PARAMETERS: Readonly<Record<MlKemParameterName, Readonly<MlKemParameters>>> = Object.freeze({
  'ML-KEM-512': ML_KEM_512,
  'ML-KEM-768': ML_KEM_768,
  'ML-KEM-1024': ML_KEM_1024
});

export function getMlKemParameters(name: MlKemParameterName): Readonly<MlKemParameters> {
  const params = ML_KEM_PARAMETERS[name];
  if (!params) {
    throw new Error(`UNSUPPORTED_ML_KEM_PARAMETER_SET: ${name}`);
  }
  return params;
}

export interface MlKemKeyPair {
  readonly encapsulationKey: Uint8Array;
  readonly decapsulationKey: Uint8Array;
  readonly parameterSet: MlKemParameterName;
}

export interface MlKemEncapsulationResult {
  readonly ciphertext: Uint8Array;
  readonly sharedSecret: Uint8Array;
  readonly parameterSet: MlKemParameterName;
}

export interface HybridKemKeyPair {
  readonly pqcKeyPair: MlKemKeyPair;
  readonly ecdhPublicKey: Uint8Array; // 32 bytes X25519 public key
  readonly ecdhPrivateKey: Uint8Array; // 32 bytes X25519 private key
}

export interface HybridKemEncapsulationResult {
  readonly pqcCiphertext: Uint8Array;
  readonly ecdhEphemeralPublicKey: Uint8Array; // 32 bytes
  readonly combinedSharedSecret: Uint8Array; // 32 bytes HKDF-SHA256 derived key
  readonly parameterSet: MlKemParameterName;
}

export interface MlKemKatVector {
  readonly count: number;
  readonly parameterSet: MlKemParameterName;
  readonly seedD: string; // 32 bytes hex
  readonly seedZ: string; // 32 bytes hex
  readonly encapsulationKeyHex: string;
  readonly decapsulationKeyHex: string;
  readonly ciphertextHex: string;
  readonly sharedSecretHex: string;
}

/**
 * Validation utilities
 */
export function validateEncapsulationKey(key: Uint8Array, params: MlKemParameters): boolean {
  if (!key || !(key instanceof Uint8Array)) return false;
  return key.length === params.encapsulationKeyBytes;
}

export function validateDecapsulationKey(key: Uint8Array, params: MlKemParameters): boolean {
  if (!key || !(key instanceof Uint8Array)) return false;
  return key.length === params.decapsulationKeyBytes;
}

export function validateCiphertext(ciphertext: Uint8Array, params: MlKemParameters): boolean {
  if (!ciphertext || !(ciphertext instanceof Uint8Array)) return false;
  return ciphertext.length === params.ciphertextBytes;
}

export function validateSharedSecret(secret: Uint8Array): boolean {
  if (!secret || !(secret instanceof Uint8Array)) return false;
  return secret.length === ML_KEM_SHARED_SECRET_BYTES;
}

/**
 * Validates modulus and ring invariants
 */
export function verifyRingModulus(): boolean {
  // Check 3329 is prime
  for (let i = 2; i * i <= ML_KEM_MODULUS; i++) {
    if (ML_KEM_MODULUS % i === 0) return false;
  }
  // Check 3329 = 1 mod 256 for NTT support
  return ML_KEM_MODULUS % 256 === 1;
}

/**
 * Constant-time comparison of two Uint8Arrays to prevent timing side channels
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
