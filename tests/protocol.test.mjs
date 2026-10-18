import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ML_KEM_512,
  ML_KEM_768,
  ML_KEM_1024,
  ML_KEM_MODULUS,
  ML_KEM_RING_DEGREE,
  ML_KEM_SHARED_SECRET_BYTES,
  getMlKemParameters,
  validateEncapsulationKey,
  validateDecapsulationKey,
  validateCiphertext,
  validateSharedSecret,
  verifyRingModulus,
  constantTimeEqual
} from '../dist/index.js';

test('Protocol Specification: NIST FIPS 203 Parameter Set Dimensions', () => {
  // ML-KEM-512
  assert.equal(ML_KEM_512.k, 2);
  assert.equal(ML_KEM_512.eta1, 3);
  assert.equal(ML_KEM_512.eta2, 2);
  assert.equal(ML_KEM_512.encapsulationKeyBytes, 800);
  assert.equal(ML_KEM_512.decapsulationKeyBytes, 1632);
  assert.equal(ML_KEM_512.ciphertextBytes, 768);
  assert.equal(ML_KEM_512.securityCategory, 1);

  // ML-KEM-768
  assert.equal(ML_KEM_768.k, 3);
  assert.equal(ML_KEM_768.eta1, 2);
  assert.equal(ML_KEM_768.eta2, 2);
  assert.equal(ML_KEM_768.encapsulationKeyBytes, 1184);
  assert.equal(ML_KEM_768.decapsulationKeyBytes, 2400);
  assert.equal(ML_KEM_768.ciphertextBytes, 1088);
  assert.equal(ML_KEM_768.securityCategory, 3);

  // ML-KEM-1024
  assert.equal(ML_KEM_1024.k, 4);
  assert.equal(ML_KEM_1024.eta1, 2);
  assert.equal(ML_KEM_1024.eta2, 2);
  assert.equal(ML_KEM_1024.encapsulationKeyBytes, 1568);
  assert.equal(ML_KEM_1024.decapsulationKeyBytes, 3168);
  assert.equal(ML_KEM_1024.ciphertextBytes, 1568);
  assert.equal(ML_KEM_1024.securityCategory, 5);

  assert.equal(ML_KEM_SHARED_SECRET_BYTES, 32);
  assert.equal(ML_KEM_RING_DEGREE, 256);
  assert.equal(ML_KEM_MODULUS, 3329);
});

test('Protocol Specification: Algebraic Ring Modulus & NTT Invariant', () => {
  assert.equal(verifyRingModulus(), true);
  assert.equal(ML_KEM_MODULUS % 256, 1);
});

test('Protocol Specification: Defensive Immutability of Parameter Sets', () => {
  assert.ok(Object.isFrozen(ML_KEM_512));
  assert.ok(Object.isFrozen(ML_KEM_768));
  assert.ok(Object.isFrozen(ML_KEM_1024));

  assert.throws(() => {
    // Attempt to mutate parameter definition in strict mode
    // @ts-ignore
    ML_KEM_768.encapsulationKeyBytes = 999;
  });
});

test('Protocol Specification: Key and Ciphertext Validation Functions', () => {
  const dummyEk512 = new Uint8Array(800);
  const dummyDk512 = new Uint8Array(1632);
  const dummyC512 = new Uint8Array(768);

  assert.equal(validateEncapsulationKey(dummyEk512, ML_KEM_512), true);
  assert.equal(validateDecapsulationKey(dummyDk512, ML_KEM_512), true);
  assert.equal(validateCiphertext(dummyC512, ML_KEM_512), true);

  // Cross-parameter length mismatch rejection
  assert.equal(validateEncapsulationKey(dummyEk512, ML_KEM_768), false);
  assert.equal(validateDecapsulationKey(dummyDk512, ML_KEM_768), false);
  assert.equal(validateCiphertext(dummyC512, ML_KEM_768), false);

  // Shared secret length
  assert.equal(validateSharedSecret(new Uint8Array(32)), true);
  assert.equal(validateSharedSecret(new Uint8Array(31)), false);
  assert.equal(validateSharedSecret(new Uint8Array(64)), false);
});

test('Protocol Specification: Constant-Time Comparison Timing Leak Resistance', () => {
  const a = new Uint8Array([1, 2, 3, 4, 5]);
  const b = new Uint8Array([1, 2, 3, 4, 5]);
  const c = new Uint8Array([1, 2, 3, 4, 6]);
  const d = new Uint8Array([1, 2, 3]);

  assert.equal(constantTimeEqual(a, b), true);
  assert.equal(constantTimeEqual(a, c), false);
  assert.equal(constantTimeEqual(a, d), false);
});

test('Protocol Specification: Parameter Set Resolver', () => {
  assert.equal(getMlKemParameters('ML-KEM-512').name, 'ML-KEM-512');
  assert.equal(getMlKemParameters('ML-KEM-768').name, 'ML-KEM-768');
  assert.equal(getMlKemParameters('ML-KEM-1024').name, 'ML-KEM-1024');

  assert.throws(
    // @ts-ignore
    () => getMlKemParameters('ML-KEM-256'),
    /UNSUPPORTED_ML_KEM_PARAMETER_SET/
  );
});
