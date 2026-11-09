import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeDomain,
  isValidDomain,
  isValidTime24h,
  isTimeWithinSchedule,
  evaluateDomainAccess,
  verifyTamperAuthorization,
  generateNativeAgentConfig,
  PolicyConfigState,
  BlockRuleItem,
  ScheduleWindowItem,
} from './blocking-engine';

const samplePolicy: PolicyConfigState = {
  ownerId: 'user_demo_01',
  protectionModel: 'model-a',
  partnerName: 'Alex Rivera (Accountability Partner)',
  partnerEmail: 'alex.rivera@trusted-partner.org',
  unlockPin: '849204',
  cooldownMinutes: 1440,
  blockAdultCore: true,
  blockProxyVpn: true,
  enforceSafeSearch: true,
  blockMixedSocial: false,
  blockGambling: true,
  lockHostsFile: true,
  lockDnsSettings: true,
  forceBrowserExtension: true,
  uninstallProtection: true,
};

const sampleRules: BlockRuleItem[] = [
  {
    id: 'rule-1',
    ownerId: 'user_demo_01',
    domain: 'distraction-stream.tv',
    category: 'Custom',
    strictLock: true,
    notes: 'Late night binge trigger',
    hitCount: 14,
    createdAt: '2026-11-08T10:00:00Z',
  },
];

const sampleSchedules: ScheduleWindowItem[] = [
  {
    id: 'sched-1',
    ownerId: 'user_demo_01',
    name: 'Nighttime Recovery Lockout',
    days: 'Mon,Tue,Wed,Thu,Fri,Sat,Sun',
    startTime: '22:00',
    endTime: '06:30',
    strictness: 'Hard Commitment Lock',
    enabled: true,
    createdAt: '2026-11-08T10:00:00Z',
  },
];

test('normalizeDomain strips protocol, www, port, path, and query string', () => {
  assert.equal(normalizeDomain('https://www.PornHub.com:443/view_video.php?viewkey=123'), 'pornhub.com');
  assert.equal(normalizeDomain('  http://sub.example.org/test/path  '), 'sub.example.org');
});

test('isValidDomain accepts valid domains and rejects malformed inputs', () => {
  assert.equal(isValidDomain('safeguard.pro'), true);
  assert.equal(isValidDomain('https://www.reddit.com/r/all'), true);
  assert.equal(isValidDomain('not a domain'), false);
  assert.equal(isValidDomain('a..b.com'), false);
  assert.equal(isValidDomain('localhost'), false);
});

test('isValidTime24h and isTimeWithinSchedule support same-day and overnight windows', () => {
  assert.equal(isValidTime24h('22:00'), true);
  assert.equal(isValidTime24h('25:99'), false);

  // Overnight window 22:00 -> 06:30
  assert.equal(isTimeWithinSchedule('23:30', 'Mon', sampleSchedules[0]), true);
  assert.equal(isTimeWithinSchedule('02:15', 'Tue', sampleSchedules[0]), true);
  assert.equal(isTimeWithinSchedule('14:00', 'Mon', sampleSchedules[0]), false);
});

test('evaluateDomainAccess blocks adult, proxy, custom, and scheduled domains accurately', () => {
  const adultRes = evaluateDomainAccess('https://www.pornhub.com/video', samplePolicy, sampleRules, sampleSchedules);
  assert.equal(adultRes.allowed, false);
  assert.equal(adultRes.matchedCategory, 'Adult & Pornography Core Filter');

  const customRes = evaluateDomainAccess('live.distraction-stream.tv', samplePolicy, sampleRules, sampleSchedules);
  assert.equal(customRes.allowed, false);
  assert.equal(customRes.matchedRule, 'distraction-stream.tv');

  const proxyRes = evaluateDomainAccess('croxyproxy.com', samplePolicy, sampleRules, sampleSchedules);
  assert.equal(proxyRes.allowed, false);
  assert.equal(proxyRes.matchedCategory, 'Proxy & Circumvention Prevention');

  const safeSearchRes = evaluateDomainAccess('google.com', samplePolicy, sampleRules, sampleSchedules, '12:00', 'Mon');
  assert.equal(safeSearchRes.allowed, true);
  assert.equal(safeSearchRes.matchedCategory, 'SafeSearch CNAME Forced');
});

test('verifyTamperAuthorization validates partner PIN and rejects unauthorized codes', () => {
  const denied = verifyTamperAuthorization('000000', samplePolicy);
  assert.equal(denied.authorized, false);

  const approved = verifyTamperAuthorization('849204', samplePolicy);
  assert.equal(approved.authorized, true);
});

test('generateNativeAgentConfig outputs platform-specific enforcement artifacts', () => {
  const win = generateNativeAgentConfig('Windows', samplePolicy, sampleRules);
  assert.ok(win.code.includes('0.0.0.0 distraction-stream.tv'));
  assert.ok(win.code.includes('SafeGuardFilterSvc'));

  const android = generateNativeAgentConfig('Android', samplePolicy, sampleRules);
  assert.ok(android.code.includes('class SafeGuardVpnService : VpnService()'));

  const ios = generateNativeAgentConfig('iOS', samplePolicy, sampleRules);
  assert.ok(ios.code.includes('com.apple.webcontent-filter'));
});
