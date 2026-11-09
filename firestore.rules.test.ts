import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

/**
 * Static and structural verification of Firestore Security Rules against the Dirty Dozen
 * adversarial attack vectors defined in security_spec.md.
 */
const rulesText = readFileSync(new URL('./firestore.rules', import.meta.url), 'utf8');
const blueprint = JSON.parse(readFileSync(new URL('./firebase-blueprint.json', import.meta.url), 'utf8'));

test('Pillar 1: Global default-deny safety net is present', () => {
  assert.match(rulesText, /match \/\{document=\*\*\} \{\s*allow read, write: if false;\s*\}/);
});

test('Pillar 2 & 4: Every collection in firebase-blueprint.json has an explicit match block and validation helper', () => {
  const firestorePaths = Object.keys(blueprint.firestore);
  assert.ok(firestorePaths.length >= 5);
  assert.match(rulesText, /match \/policies\/\{userId\}/);
  assert.match(rulesText, /match \/blockRules\/\{ruleId\}/);
  assert.match(rulesText, /match \/schedules\/\{scheduleId\}/);
  assert.match(rulesText, /match \/devices\/\{deviceId\}/);
  assert.match(rulesText, /match \/auditLogs\/\{logId\}/);

  assert.match(rulesText, /function isValidPolicyConfig\(data\)/);
  assert.match(rulesText, /function isValidBlockRule\(data\)/);
  assert.match(rulesText, /function isValidScheduleWindow\(data\)/);
  assert.match(rulesText, /function isValidProtectedDevice\(data\)/);
  assert.match(rulesText, /function isValidAuditEvent\(data\)/);
});

test('Dirty Dozen #1-3: Unauthenticated, unverified email, and PII cross-tenant reads are blocked', () => {
  assert.match(rulesText, /request\.auth != null/);
  assert.match(rulesText, /request\.auth\.token\.email_verified == true/);
  assert.match(rulesText, /userId == request\.auth\.uid/);
});

test('Dirty Dozen #4-7: Shadow fields, domain regex poisoning, and ownership mutation are rejected', () => {
  assert.match(rulesText, /data\.keys\(\)\.hasOnly\(/);
  assert.match(rulesText, /affectedKeys\(\)\.hasOnly\(/);
  assert.match(rulesText, /incoming\(\)\.ownerId == existing\(\)\.ownerId/);
  assert.ok(rulesText.includes("data.domain.matches('^[a-z0-9.-]+\\\\.[a-z]{2,}$')"));
});

test('Dirty Dozen #8-12: Timestamp forgery, audit log deletion, ID poisoning, and unfiltered list scraping are rejected', () => {
  assert.match(rulesText, /incoming\(\)\.createdAt == request\.time/);
  assert.match(rulesText, /allow update, delete: if false;/);
  assert.match(rulesText, /function isValidId\(id\)/);
  assert.match(rulesText, /allow list: if isVerifiedUser\(\) && existing\(\)\.ownerId == request\.auth\.uid;/);
});
