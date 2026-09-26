const assert = require('assert');
const BruteForceDetector = require('./detector.js');

console.log('--- RUNNING DETECTOR TESTS ---');

const detector = new BruteForceDetector({
  maxIpFailures: 3,
  windowMs: 10000,
  lockoutMs: 20000
});

// Test 1: Normal successful login
console.log('Test 1: Normal Login');
const res1 = detector.processLogin({ ip: '10.0.0.1', username: 'alice', success: true });
assert.strictEqual(res1.status, 'SUCCESS');
assert.strictEqual(res1.riskScore, 0);

// Test 2: Failed logins within threshold
console.log('Test 2: Failed logins under threshold');
detector.processLogin({ ip: '10.0.0.2', username: 'bob', success: false });
detector.processLogin({ ip: '10.0.0.2', username: 'bob', success: false });
assert.strictEqual(detector.isBlocked('10.0.0.2'), false);

// Test 3: Exceed threshold -> Auto Block
console.log('Test 3: Threshold Exceeded -> Auto Lockout');
const res3 = detector.processLogin({ ip: '10.0.0.2', username: 'bob', success: false });
assert.strictEqual(res3.threatType, 'BRUTE_FORCE_ATTACK');
assert.strictEqual(res3.status, 'BLOCKED');
assert.notStrictEqual(detector.isBlocked('10.0.0.2'), false);

// Test 4: Blocked IP immediate rejection
console.log('Test 4: Subsequent login from blocked IP rejected');
const res4 = detector.processLogin({ ip: '10.0.0.2', username: 'bob', success: false });
assert.strictEqual(res4.status, 'BLOCKED');
assert.strictEqual(res4.riskScore, 100);

// Test 5: Credential Stuffing Detection
console.log('Test 5: Credential Stuffing Detection');
detector.processLogin({ ip: '10.0.0.3', username: 'user1', success: false });
detector.processLogin({ ip: '10.0.0.3', username: 'user2', success: false });
const res5 = detector.processLogin({ ip: '10.0.0.3', username: 'user3', success: false });
assert.strictEqual(res5.threatType, 'CREDENTIAL_STUFFING');
assert.strictEqual(res5.status, 'BLOCKED');

// Test 6: Unblock IP
console.log('Test 6: Manual Unblock');
detector.unblockIp('10.0.0.2');
assert.strictEqual(detector.isBlocked('10.0.0.2'), false);

console.log('✅ ALL DETECTOR TESTS PASSED SUCCESSFULLY!');
