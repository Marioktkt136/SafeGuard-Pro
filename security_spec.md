# SafeGuard Pro — Firestore Security Specification (Phase 0 TDD)

## 1. Data Invariants

1. **Zero-Trust Default Deny**: Every path not explicitly matched is denied via `match /{document=**} { allow read, write: if false; }`.
2. **Verified Identity & Ownership**: Every read and write requires `request.auth != null`, `request.auth.token.email_verified == true`, and strict ownership verification (`ownerId == request.auth.uid`).
3. **Path Variable Hardening**: Every single-document path parameter (`userId`, `ruleId`, `scheduleId`, `deviceId`, `logId`) is validated with `isValidId(id)` (`id is string && id.size() >= 1 && id.size() <= 128 && id.matches('^[a-zA-Z0-9_\\-]+$')`).
4. **Strict Schema & Anti-Update-Gap**: Every `create` and `update` invokes `isValidPolicyConfig`, `isValidBlockRule`, `isValidScheduleWindow`, `isValidProtectedDevice`, or `isValidAuditEvent`, enforcing `keys().hasAll(...)` and `keys().hasOnly(...)` as well as bounded string lengths and regex patterns from `firebase-blueprint.json`.
5. **Immutable Audit Logs**: Documents in `/auditLogs/{logId}` are append-only (`allow update, delete: if false;`) and enforce server timestamps (`createdAt == request.time`).
6. **Immutable Ownership & Creation Timestamps**: `ownerId` and `createdAt` can never be mutated during updates (`incoming().ownerId == existing().ownerId && incoming().createdAt == existing().createdAt`).
7. **Secure List Queries**: Every `allow list` rule enforces `resource.data.ownerId == request.auth.uid` on the server without delegating security to client filters.

## 2. The "Dirty Dozen" Adversarial Payloads

1. **Payload 01 — Unauthenticated Policy Write**: `auth = null`, creating `/policies/user_1` -> `PERMISSION_DENIED`.
2. **Payload 02 — Unverified Email Spoof**: `auth = { uid: 'user_1', token: { email_verified: false } }`, creating `/policies/user_1` -> `PERMISSION_DENIED`.
3. **Payload 03 — Cross-Tenant Policy Read (PII Leak)**: `auth.uid = 'attacker_99'`, reading `/policies/user_1` (which contains `partnerEmail`) -> `PERMISSION_DENIED`.
4. **Payload 04 — Cross-Tenant Ownership Spoof on BlockRule Create**: `auth.uid = 'attacker_99'`, creating `/blockRules/rule_1` with `ownerId: 'user_1'` -> `PERMISSION_DENIED`.
5. **Payload 05 — Shadow Field Injection on BlockRule**: Creating `/blockRules/rule_1` with extra field `isAdminBypass: true` -> `PERMISSION_DENIED`.
6. **Payload 06 — Invalid Domain Regex / Resource Poisoning**: Creating `/blockRules/rule_1` with `domain: 'javascript:alert(1)'` or 500-char string -> `PERMISSION_DENIED`.
7. **Payload 07 — Ownership Mutation on BlockRule Update**: Updating `/blockRules/rule_1` changing `ownerId` from `'user_1'` to `'attacker_99'` -> `PERMISSION_DENIED`.
8. **Payload 08 — Client Timestamp Forgery**: Creating `/schedules/sched_1` with a past/future `createdAt` instead of `request.time` -> `PERMISSION_DENIED`.
9. **Payload 09 — Invalid Schedule Time Pattern**: Creating `/schedules/sched_1` with `startTime: '99:99'` -> `PERMISSION_DENIED`.
10. **Payload 10 — Audit Log Tampering (Update/Delete)**: Authenticated owner attempting to update or delete `/auditLogs/log_1` to erase evidence of a bypass attempt -> `PERMISSION_DENIED`.
11. **Payload 11 — Path ID Poisoning**: Creating `/devices/invalid$id!with*spaces` -> `PERMISSION_DENIED`.
12. **Payload 12 — Unfiltered List Scraping**: Authenticated user running an unconstrained collection list query across all users' `/blockRules` -> `PERMISSION_DENIED`.

## 3. Red Team Audit & Verification Summary

- **Shadow Update Test**: Passed. Every collection enforces `keys().hasOnly(...)` in `isValid[Entity]` and `affectedKeys().hasOnly(...)` on every update action branch.
- **Email Spoofing Test**: Passed. `isVerifiedUser()` enforces `request.auth != null && request.auth.token.email_verified == true`.
- **PII Blanket Test**: Passed. `/policies/{userId}` containing `partnerEmail` is strictly locked to `userId == request.auth.uid && resource.data.ownerId == request.auth.uid`.
- **Query Trust Test**: Passed. All `allow list` rules check `resource.data.ownerId == request.auth.uid`.
- **Value Poisoning Test**: Passed. Every `allow update` begins with `isValid[Entity](incoming())`.
