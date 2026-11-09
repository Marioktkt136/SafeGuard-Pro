import { Injectable, PLATFORM_ID, inject, signal, computed } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import {
  User,
  onAuthStateChanged,
  signInWithPopup,
  signOut,
} from 'firebase/auth';
import {
  collection,
  doc,
  setDoc,
  updateDoc,
  deleteDoc,
  onSnapshot,
  query,
  where,
  serverTimestamp,
  Unsubscribe,
} from 'firebase/firestore';
import {
  auth,
  db,
  googleProvider,
  handleFirestoreError,
  OperationType,
  testFirestoreConnection,
} from './firebase-client';
import {
  PolicyConfigState,
  BlockRuleItem,
  ScheduleWindowItem,
  ProtectedDeviceItem,
  AuditEventItem,
  RuleCategory,
  ScheduleStrictness,
  DevicePlatform,
  AuditEventType,
  AuditSeverity,
  normalizeDomain,
  isValidDomain,
  isValidTime24h,
  evaluateDomainAccess,
  verifyTamperAuthorization,
  FilterDecision,
} from './blocking-engine';

const INITIAL_POLICY: PolicyConfigState = {
  ownerId: 'local_operator',
  protectionModel: 'model-a',
  partnerName: 'Jordan Vance (Trusted Partner)',
  partnerEmail: 'jordan.vance@accountability-partner.org',
  unlockPin: '482910',
  cooldownMinutes: 1440,
  blockAdultCore: true,
  blockProxyVpn: true,
  enforceSafeSearch: true,
  blockMixedSocial: true,
  blockGambling: true,
  lockHostsFile: true,
  lockDnsSettings: true,
  forceBrowserExtension: true,
  uninstallProtection: true,
};

const INITIAL_RULES: BlockRuleItem[] = [
  {
    id: 'rule-seed-1',
    ownerId: 'local_operator',
    domain: 'pornhub.com',
    category: 'Adult',
    strictLock: true,
    notes: 'Core adult video portal — locked at hosts & DNS layers',
    hitCount: 42,
    createdAt: '2026-11-08 09:15',
  },
  {
    id: 'rule-seed-2',
    ownerId: 'local_operator',
    domain: 'xvideos.com',
    category: 'Adult',
    strictLock: true,
    notes: 'Core adult tube signature — sinkholed to 0.0.0.0',
    hitCount: 19,
    createdAt: '2026-11-08 09:15',
  },
  {
    id: 'rule-seed-3',
    ownerId: 'local_operator',
    domain: 'onlyfans.com',
    category: 'Adult',
    strictLock: true,
    notes: 'Subscription adult portal — strict commitment lock',
    hitCount: 11,
    createdAt: '2026-11-08 11:30',
  },
  {
    id: 'rule-seed-4',
    ownerId: 'local_operator',
    domain: 'croxyproxy.com',
    category: 'Proxy/Bypass',
    strictLock: true,
    notes: 'Web proxy circumvention gateway blocked',
    hitCount: 8,
    createdAt: '2026-11-08 14:20',
  },
  {
    id: 'rule-seed-5',
    ownerId: 'local_operator',
    domain: 'nsfw.reddit.com',
    category: 'Social/Trigger',
    strictLock: false,
    notes: 'Mixed-content social trigger subdomain',
    hitCount: 15,
    createdAt: '2026-11-09 07:45',
  },
];

const INITIAL_SCHEDULES: ScheduleWindowItem[] = [
  {
    id: 'sched-seed-1',
    ownerId: 'local_operator',
    name: 'Nighttime Vulnerability Lockout',
    days: 'Mon,Tue,Wed,Thu,Fri,Sat,Sun',
    startTime: '22:00',
    endTime: '07:00',
    strictness: 'Hard Commitment Lock',
    enabled: true,
    createdAt: '2026-11-07 20:00',
  },
  {
    id: 'sched-seed-2',
    ownerId: 'local_operator',
    name: 'Deep Work Focus Window',
    days: 'Mon,Tue,Wed,Thu,Fri',
    startTime: '08:30',
    endTime: '17:30',
    strictness: 'Standard Filter',
    enabled: true,
    createdAt: '2026-11-07 20:05',
  },
];

const INITIAL_DEVICES: ProtectedDeviceItem[] = [
  {
    id: 'dev-seed-1',
    ownerId: 'local_operator',
    name: 'DESKTOP-WIN11-PRO (Primary Workstation)',
    platform: 'Windows',
    agentType: 'C#/.NET 8 Windows Service + WFP Callout',
    agentVersion: 'v2.4.1-lts',
    status: 'Protected',
    dnsLockActive: true,
    hostsLockActive: true,
    createdAt: '2026-11-09 09:50',
  },
  {
    id: 'dev-seed-2',
    ownerId: 'local_operator',
    name: 'Pixel 9 Pro (Android 16)',
    platform: 'Android',
    agentType: 'Kotlin VpnService + Always-On Lockdown',
    agentVersion: 'v2.4.0-vpn',
    status: 'Protected',
    dnsLockActive: true,
    hostsLockActive: true,
    createdAt: '2026-11-09 09:52',
  },
  {
    id: 'dev-seed-3',
    ownerId: 'local_operator',
    name: 'iPhone 16 Pro (Supervised iOS 19)',
    platform: 'iOS',
    agentType: 'Swift NetworkExtension + Managed DoH Profile',
    agentVersion: 'v2.3.9-ne',
    status: 'Protected',
    dnsLockActive: true,
    hostsLockActive: true,
    createdAt: '2026-11-09 09:54',
  },
];

const INITIAL_LOGS: AuditEventItem[] = [
  {
    id: 'log-seed-1',
    ownerId: 'local_operator',
    eventType: 'Blocked Request',
    severity: 'Warning',
    target: 'pornhub.com',
    deviceName: 'DESKTOP-WIN11-PRO',
    actionTaken: 'Sinkholed to 0.0.0.0 via Windows Hosts & CleanBrowsing DoH',
    createdAt: '2026-11-09 09:42:18',
  },
  {
    id: 'log-seed-2',
    ownerId: 'local_operator',
    eventType: 'Tamper Attempt',
    severity: 'Critical',
    target: 'C:\\Windows\\System32\\drivers\\etc\\hosts',
    deviceName: 'DESKTOP-WIN11-PRO',
    actionTaken: 'Blocked unauthorized write via NTFS ACL & restored SHA-256 baseline within 40ms',
    createdAt: '2026-11-09 08:19:04',
  },
  {
    id: 'log-seed-3',
    ownerId: 'local_operator',
    eventType: 'Tamper Attempt',
    severity: 'Critical',
    target: 'Android VPN Settings Override',
    deviceName: 'Pixel 9 Pro',
    actionTaken: 'DevicePolicyManager DISALLOW_CONFIG_VPN rejected user disconnect attempt',
    createdAt: '2026-11-09 01:14:52',
  },
  {
    id: 'log-seed-4',
    ownerId: 'local_operator',
    eventType: 'Blocked Request',
    severity: 'Warning',
    target: 'croxyproxy.com',
    deviceName: 'iPhone 16 Pro',
    actionTaken: 'Blocked proxy circumvention domain via Swift NetworkExtension',
    createdAt: '2026-11-08 23:48:10',
  },
  {
    id: 'log-seed-5',
    ownerId: 'local_operator',
    eventType: 'Service Heartbeat',
    severity: 'Normal',
    target: 'All 3 Native Agents + DoH Resolver',
    deviceName: 'Fleet Coordinator',
    actionTaken: 'Verified cryptographic policy signature & SafeSearch CNAME enforcement',
    createdAt: '2026-11-09 09:55:00',
  },
];

@Injectable({
  providedIn: 'root',
})
export class SafeguardService {
  private readonly platformId = inject(PLATFORM_ID);
  private readonly isBrowser = isPlatformBrowser(this.platformId);
  private unsubscribers: Unsubscribe[] = [];

  readonly currentUser = signal<User | null>(null);
  readonly authReady = signal<boolean>(false);
  readonly authError = signal<string | null>(null);

  readonly policy = signal<PolicyConfigState>(INITIAL_POLICY);
  readonly blockRules = signal<BlockRuleItem[]>(INITIAL_RULES);
  readonly schedules = signal<ScheduleWindowItem[]>(INITIAL_SCHEDULES);
  readonly devices = signal<ProtectedDeviceItem[]>(INITIAL_DEVICES);
  readonly auditLogs = signal<AuditEventItem[]>(INITIAL_LOGS);

  readonly sessionAuthorized = signal<boolean>(false);
  readonly lastSimulatorResult = signal<FilterDecision | null>(
    evaluateDomainAccess('https://www.pornhub.com', INITIAL_POLICY, INITIAL_RULES, INITIAL_SCHEDULES)
  );

  readonly totalBlockedHits = computed(() =>
    this.blockRules().reduce((acc, item) => acc + item.hitCount, 0) +
    (this.policy().blockAdultCore ? 142 : 0)
  );

  readonly activeDefenseLayerCount = computed(() => {
    const p = this.policy();
    let count = 0;
    if (p.blockAdultCore) count++;
    if (p.blockProxyVpn) count++;
    if (p.enforceSafeSearch) count++;
    if (p.lockHostsFile) count++;
    if (p.lockDnsSettings) count++;
    if (p.forceBrowserExtension) count++;
    if (p.uninstallProtection) count++;
    return count;
  });

  readonly isTamperLockActive = computed(() => {
    const p = this.policy();
    return (p.uninstallProtection || p.lockHostsFile || p.lockDnsSettings) && !this.sessionAuthorized();
  });

  constructor() {
    if (this.isBrowser) {
      void testFirestoreConnection();
      onAuthStateChanged(auth, (user) => {
        this.currentUser.set(user);
        this.authReady.set(true);
        this.cleanupSubscriptions();
        if (user) {
          this.attachFirestoreListeners(user.uid);
        }
      });
    } else {
      this.authReady.set(true);
    }
  }

  private cleanupSubscriptions(): void {
    for (const unsub of this.unsubscribers) {
      unsub();
    }
    this.unsubscribers = [];
  }

  async signInWithGoogle(): Promise<void> {
    if (!this.isBrowser) return;
    this.authError.set(null);
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (err) {
      this.authError.set(err instanceof Error ? err.message : 'Google Sign-In failed.');
    }
  }

  async signOutUser(): Promise<void> {
    if (!this.isBrowser) return;
    this.cleanupSubscriptions();
    await signOut(auth);
    this.sessionAuthorized.set(false);
  }

  private attachFirestoreListeners(uid: string): void {
    // 1. Policy listener
    const policyRef = doc(db, 'policies', uid);
    const unsubPolicy = onSnapshot(
      policyRef,
      (snap) => {
        if (snap.exists()) {
          const data = snap.data() as PolicyConfigState;
          this.policy.set({ ...data, ownerId: uid });
        } else {
          void this.seedUserPolicyInFirestore(uid);
        }
      },
      (err) => handleFirestoreError(err, OperationType.GET, `policies/${uid}`)
    );

    // 2. BlockRules listener
    const rulesQuery = query(collection(db, 'blockRules'), where('ownerId', '==', uid));
    const unsubRules = onSnapshot(
      rulesQuery,
      (snap) => {
        if (snap.empty) {
          void this.seedInitialRulesInFirestore(uid);
          return;
        }
        const items: BlockRuleItem[] = snap.docs.map((d) => {
          const raw = d.data();
          return {
            id: d.id,
            ownerId: String(raw['ownerId'] || uid),
            domain: String(raw['domain'] || ''),
            category: (raw['category'] as RuleCategory) || 'Custom',
            strictLock: Boolean(raw['strictLock']),
            notes: String(raw['notes'] || ''),
            hitCount: Number(raw['hitCount'] || 0),
            createdAt: raw['createdAt']?.toDate
              ? raw['createdAt'].toDate().toISOString().slice(0, 16).replace('T', ' ')
              : 'Just now',
          };
        });
        this.blockRules.set(items);
      },
      (err) => handleFirestoreError(err, OperationType.LIST, 'blockRules')
    );

    // 3. Schedules listener
    const schedQuery = query(collection(db, 'schedules'), where('ownerId', '==', uid));
    const unsubSched = onSnapshot(
      schedQuery,
      (snap) => {
        if (snap.empty) {
          void this.seedInitialSchedulesInFirestore(uid);
          return;
        }
        const items: ScheduleWindowItem[] = snap.docs.map((d) => {
          const raw = d.data();
          return {
            id: d.id,
            ownerId: String(raw['ownerId'] || uid),
            name: String(raw['name'] || ''),
            days: String(raw['days'] || 'Mon,Tue,Wed,Thu,Fri,Sat,Sun'),
            startTime: String(raw['startTime'] || '22:00'),
            endTime: String(raw['endTime'] || '07:00'),
            strictness: (raw['strictness'] as ScheduleStrictness) || 'Hard Commitment Lock',
            enabled: Boolean(raw['enabled']),
            createdAt: raw['createdAt']?.toDate
              ? raw['createdAt'].toDate().toISOString().slice(0, 16).replace('T', ' ')
              : 'Just now',
          };
        });
        this.schedules.set(items);
      },
      (err) => handleFirestoreError(err, OperationType.LIST, 'schedules')
    );

    // 4. Devices listener
    const devQuery = query(collection(db, 'devices'), where('ownerId', '==', uid));
    const unsubDev = onSnapshot(
      devQuery,
      (snap) => {
        if (snap.empty) {
          void this.seedInitialDevicesInFirestore(uid);
          return;
        }
        const items: ProtectedDeviceItem[] = snap.docs.map((d) => {
          const raw = d.data();
          return {
            id: d.id,
            ownerId: String(raw['ownerId'] || uid),
            name: String(raw['name'] || ''),
            platform: (raw['platform'] as DevicePlatform) || 'Windows',
            agentType: String(raw['agentType'] || ''),
            agentVersion: String(raw['agentVersion'] || 'v2.4.1'),
            status: (raw['status'] as ProtectedDeviceItem['status']) || 'Protected',
            dnsLockActive: Boolean(raw['dnsLockActive']),
            hostsLockActive: Boolean(raw['hostsLockActive']),
            createdAt: raw['createdAt']?.toDate
              ? raw['createdAt'].toDate().toISOString().slice(0, 16).replace('T', ' ')
              : 'Just now',
          };
        });
        this.devices.set(items);
      },
      (err) => handleFirestoreError(err, OperationType.LIST, 'devices')
    );

    // 5. Audit logs listener
    const logsQuery = query(collection(db, 'auditLogs'), where('ownerId', '==', uid));
    const unsubLogs = onSnapshot(
      logsQuery,
      (snap) => {
        if (snap.empty) return;
        const items: AuditEventItem[] = snap.docs.map((d) => {
          const raw = d.data();
          return {
            id: d.id,
            ownerId: String(raw['ownerId'] || uid),
            eventType: (raw['eventType'] as AuditEventType) || 'Blocked Request',
            severity: (raw['severity'] as AuditSeverity) || 'Normal',
            target: String(raw['target'] || ''),
            deviceName: String(raw['deviceName'] || ''),
            actionTaken: String(raw['actionTaken'] || ''),
            createdAt: raw['createdAt']?.toDate
              ? raw['createdAt'].toDate().toISOString().slice(0, 19).replace('T', ' ')
              : new Date().toISOString().slice(0, 19).replace('T', ' '),
          };
        });
        this.auditLogs.set(items);
      },
      (err) => handleFirestoreError(err, OperationType.LIST, 'auditLogs')
    );

    this.unsubscribers.push(unsubPolicy, unsubRules, unsubSched, unsubDev, unsubLogs);
  }

  private async seedUserPolicyInFirestore(uid: string): Promise<void> {
    const payload = {
      ...INITIAL_POLICY,
      ownerId: uid,
      updatedAt: serverTimestamp(),
    };
    try {
      await setDoc(doc(db, 'policies', uid), payload);
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `policies/${uid}`);
    }
  }

  private async seedInitialRulesInFirestore(uid: string): Promise<void> {
    for (const r of INITIAL_RULES) {
      const ruleId = `${uid}_${r.id}`;
      try {
        await setDoc(doc(db, 'blockRules', ruleId), {
          ownerId: uid,
          domain: r.domain,
          category: r.category,
          strictLock: r.strictLock,
          notes: r.notes.slice(0, 200),
          hitCount: r.hitCount,
          createdAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, `blockRules/${ruleId}`);
      }
    }
  }

  private async seedInitialSchedulesInFirestore(uid: string): Promise<void> {
    for (const s of INITIAL_SCHEDULES) {
      const schedId = `${uid}_${s.id}`;
      try {
        await setDoc(doc(db, 'schedules', schedId), {
          ownerId: uid,
          name: s.name.slice(0, 80),
          days: s.days.slice(0, 40),
          startTime: s.startTime,
          endTime: s.endTime,
          strictness: s.strictness,
          enabled: s.enabled,
          createdAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, `schedules/${schedId}`);
      }
    }
  }

  private async seedInitialDevicesInFirestore(uid: string): Promise<void> {
    for (const d of INITIAL_DEVICES) {
      const devId = `${uid}_${d.id}`;
      try {
        await setDoc(doc(db, 'devices', devId), {
          ownerId: uid,
          name: d.name.slice(0, 80),
          platform: d.platform,
          agentType: d.agentType.slice(0, 80),
          agentVersion: d.agentVersion.slice(0, 24),
          status: d.status,
          dnsLockActive: d.dnsLockActive,
          hostsLockActive: d.hostsLockActive,
          createdAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, `devices/${devId}`);
      }
    }
  }

  // --- Mutations ---

  async updatePolicyField(partial: Partial<PolicyConfigState>): Promise<void> {
    const next: PolicyConfigState = {
      ...this.policy(),
      ...partial,
    };
    // Enforce blueprint volumetric constraints
    next.partnerName = next.partnerName.trim().slice(0, 80) || 'Trusted Partner';
    next.partnerEmail = next.partnerEmail.trim().slice(0, 120) || 'partner@example.org';
    next.unlockPin = next.unlockPin.trim().replace(/[^0-9A-Za-z-]/g, '').slice(0, 16) || '482910';
    next.cooldownMinutes = Math.max(0, Math.min(10080, Math.round(Number(next.cooldownMinutes) || 0)));

    this.policy.set(next);
    await this.recordAuditEvent(
      'Policy Change',
      'Normal',
      Object.keys(partial).join(', '),
      'Management Console',
      `Updated policy settings (${next.protectionModel.toUpperCase()})`
    );

    const user = this.currentUser();
    if (user) {
      const path = `policies/${user.uid}`;
      try {
        await setDoc(doc(db, 'policies', user.uid), {
          ownerId: user.uid,
          protectionModel: next.protectionModel,
          partnerName: next.partnerName,
          partnerEmail: next.partnerEmail,
          unlockPin: next.unlockPin,
          cooldownMinutes: next.cooldownMinutes,
          blockAdultCore: next.blockAdultCore,
          blockProxyVpn: next.blockProxyVpn,
          enforceSafeSearch: next.enforceSafeSearch,
          blockMixedSocial: next.blockMixedSocial,
          blockGambling: next.blockGambling,
          lockHostsFile: next.lockHostsFile,
          lockDnsSettings: next.lockDnsSettings,
          forceBrowserExtension: next.forceBrowserExtension,
          uninstallProtection: next.uninstallProtection,
          updatedAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.UPDATE, path);
      }
    }
  }

  async addCustomBlockRule(
    rawDomain: string,
    category: RuleCategory,
    strictLock: boolean,
    notes: string
  ): Promise<{ ok: boolean; error?: string }> {
    const domain = normalizeDomain(rawDomain);
    if (!isValidDomain(domain)) {
      return { ok: false, error: 'Enter a valid domain (e.g., badsite.org or sub.domain.com).' };
    }
    if (this.blockRules().some((r) => r.domain === domain)) {
      return { ok: false, error: `Domain "${domain}" is already in the blocklist.` };
    }

    const sanitizedNotes = (notes || '').trim().slice(0, 200);
    const id = `rule_${Date.now()}`;
    const user = this.currentUser();
    const ownerId = user?.uid ?? 'local_operator';
    const newItem: BlockRuleItem = {
      id,
      ownerId,
      domain,
      category,
      strictLock,
      notes: sanitizedNotes || 'User-defined custom block rule',
      hitCount: 0,
      createdAt: new Date().toISOString().slice(0, 16).replace('T', ' '),
    };

    this.blockRules.update((list) => [newItem, ...list]);
    await this.recordAuditEvent(
      'Policy Change',
      'Normal',
      domain,
      'Management Console',
      `Added custom block rule [${category}]${strictLock ? ' with Tamper Lock' : ''}`
    );

    if (user) {
      try {
        await setDoc(doc(db, 'blockRules', id), {
          ownerId: user.uid,
          domain,
          category,
          strictLock,
          notes: newItem.notes,
          hitCount: 0,
          createdAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, `blockRules/${id}`);
      }
    }
    return { ok: true };
  }

  async removeBlockRule(rule: BlockRuleItem): Promise<{ ok: boolean; requiresPin?: boolean }> {
    if (rule.strictLock && !this.sessionAuthorized()) {
      await this.recordAuditEvent(
        'Tamper Attempt',
        'Warning',
        rule.domain,
        'Management Console',
        'Blocked unauthorized attempt to delete strict-locked domain rule without partner PIN'
      );
      return { ok: false, requiresPin: true };
    }

    this.blockRules.update((list) => list.filter((r) => r.id !== rule.id));
    await this.recordAuditEvent(
      'Policy Change',
      'Warning',
      rule.domain,
      'Management Console',
      'Removed domain from custom blocklist after authorization check'
    );

    const user = this.currentUser();
    if (user) {
      try {
        await deleteDoc(doc(db, 'blockRules', rule.id));
      } catch (err) {
        handleFirestoreError(err, OperationType.DELETE, `blockRules/${rule.id}`);
      }
    }
    return { ok: true };
  }

  async addScheduleWindow(
    name: string,
    days: string,
    startTime: string,
    endTime: string,
    strictness: ScheduleStrictness
  ): Promise<{ ok: boolean; error?: string }> {
    const cleanName = (name || '').trim().slice(0, 80);
    if (cleanName.length < 2) {
      return { ok: false, error: 'Schedule name must be at least 2 characters.' };
    }
    if (!isValidTime24h(startTime) || !isValidTime24h(endTime)) {
      return { ok: false, error: 'Start and end times must be valid 24-hour times (HH:MM).' };
    }
    const cleanDays = (days || 'Mon,Tue,Wed,Thu,Fri,Sat,Sun').trim().slice(0, 40);
    const id = `sched_${Date.now()}`;
    const user = this.currentUser();
    const ownerId = user?.uid ?? 'local_operator';

    const newSched: ScheduleWindowItem = {
      id,
      ownerId,
      name: cleanName,
      days: cleanDays,
      startTime,
      endTime,
      strictness,
      enabled: true,
      createdAt: new Date().toISOString().slice(0, 16).replace('T', ' '),
    };

    this.schedules.update((list) => [newSched, ...list]);
    await this.recordAuditEvent(
      'Policy Change',
      'Normal',
      cleanName,
      'Schedule Engine',
      `Created recurring schedule (${startTime}–${endTime}, ${strictness})`
    );

    if (user) {
      try {
        await setDoc(doc(db, 'schedules', id), {
          ownerId: user.uid,
          name: cleanName,
          days: cleanDays,
          startTime,
          endTime,
          strictness,
          enabled: true,
          createdAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, `schedules/${id}`);
      }
    }
    return { ok: true };
  }

  async toggleSchedule(schedule: ScheduleWindowItem): Promise<{ ok: boolean; requiresPin?: boolean }> {
    if (
      schedule.enabled &&
      schedule.strictness === 'Hard Commitment Lock' &&
      !this.sessionAuthorized()
    ) {
      await this.recordAuditEvent(
        'Tamper Attempt',
        'Warning',
        schedule.name,
        'Schedule Engine',
        'Rejected disabling of Hard Commitment Lock schedule without Partner/Admin PIN'
      );
      return { ok: false, requiresPin: true };
    }

    const nextEnabled = !schedule.enabled;
    this.schedules.update((list) =>
      list.map((s) => (s.id === schedule.id ? { ...s, enabled: nextEnabled } : s))
    );

    const user = this.currentUser();
    if (user) {
      try {
        await updateDoc(doc(db, 'schedules', schedule.id), {
          enabled: nextEnabled,
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.UPDATE, `schedules/${schedule.id}`);
      }
    }
    return { ok: true };
  }

  async enrollDevice(
    name: string,
    platform: DevicePlatform
  ): Promise<{ ok: boolean; error?: string }> {
    const cleanName = (name || '').trim().slice(0, 80);
    if (cleanName.length < 2) {
      return { ok: false, error: 'Enter a valid device hostname or label (at least 2 characters).' };
    }
    const agentMap: Record<DevicePlatform, { type: string; ver: string }> = {
      Windows: { type: 'C#/.NET 8 Windows Service + WFP Callout', ver: 'v2.4.1-lts' },
      Android: { type: 'Kotlin VpnService + Always-On Lockdown', ver: 'v2.4.0-vpn' },
      iOS: { type: 'Swift NetworkExtension + Managed DoH Profile', ver: 'v2.3.9-ne' },
    };
    const id = `dev_${Date.now()}`;
    const user = this.currentUser();
    const ownerId = user?.uid ?? 'local_operator';

    const newDevice: ProtectedDeviceItem = {
      id,
      ownerId,
      name: cleanName,
      platform,
      agentType: agentMap[platform].type,
      agentVersion: agentMap[platform].ver,
      status: 'Protected',
      dnsLockActive: true,
      hostsLockActive: true,
      createdAt: new Date().toISOString().slice(0, 16).replace('T', ' '),
    };

    this.devices.update((list) => [newDevice, ...list]);
    await this.recordAuditEvent(
      'Service Heartbeat',
      'Normal',
      cleanName,
      cleanName,
      `Enrolled ${platform} native agent (${agentMap[platform].type})`
    );

    if (user) {
      try {
        await setDoc(doc(db, 'devices', id), {
          ownerId: user.uid,
          name: cleanName,
          platform,
          agentType: newDevice.agentType,
          agentVersion: newDevice.agentVersion,
          status: 'Protected',
          dnsLockActive: true,
          hostsLockActive: true,
          createdAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, `devices/${id}`);
      }
    }
    return { ok: true };
  }

  async simulateDomainCheck(rawInput: string): Promise<FilterDecision> {
    const decision = evaluateDomainAccess(
      rawInput,
      this.policy(),
      this.blockRules(),
      this.schedules()
    );
    this.lastSimulatorResult.set(decision);

    if (!decision.allowed && decision.matchedCategory !== 'Invalid Hostname') {
      // Increment hit count if custom rule matched
      const matchedCustom = this.blockRules().find((r) => r.domain === decision.matchedRule);
      if (matchedCustom) {
        const nextHits = matchedCustom.hitCount + 1;
        this.blockRules.update((list) =>
          list.map((r) => (r.id === matchedCustom.id ? { ...r, hitCount: nextHits } : r))
        );
        const user = this.currentUser();
        if (user) {
          try {
            await updateDoc(doc(db, 'blockRules', matchedCustom.id), { hitCount: nextHits });
          } catch (err) {
            handleFirestoreError(err, OperationType.UPDATE, `blockRules/${matchedCustom.id}`);
          }
        }
      }

      await this.recordAuditEvent(
        'Blocked Request',
        'Warning',
        decision.normalizedDomain,
        'DNS & Hosts Filter Simulator',
        `Blocked via ${decision.matchedCategory} (${decision.enforcementLayers.join(' + ')})`
      );
    }
    return decision;
  }

  async unlockSessionWithPin(pin: string): Promise<{ authorized: boolean; reason: string }> {
    const res = verifyTamperAuthorization(pin, this.policy());
    if (res.authorized) {
      this.sessionAuthorized.set(true);
      await this.recordAuditEvent(
        'Policy Change',
        'Normal',
        'Tamper Guard Session Unlock',
        'Authorization Gate',
        res.reason
      );
    } else {
      await this.recordAuditEvent(
        'Tamper Attempt',
        'Critical',
        'Tamper Guard PIN Verification',
        'Authorization Gate',
        res.reason
      );
    }
    return res;
  }

  lockSession(): void {
    this.sessionAuthorized.set(false);
  }

  async recordAuditEvent(
    eventType: AuditEventType,
    severity: AuditSeverity,
    target: string,
    deviceName: string,
    actionTaken: string
  ): Promise<void> {
    const id = `log_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
    const user = this.currentUser();
    const ownerId = user?.uid ?? 'local_operator';
    const cleanTarget = (target || 'System').slice(0, 253);
    const cleanDevice = (deviceName || 'Local Agent').slice(0, 80);
    const cleanAction = (actionTaken || 'Enforced policy').slice(0, 160);

    const entry: AuditEventItem = {
      id,
      ownerId,
      eventType,
      severity,
      target: cleanTarget,
      deviceName: cleanDevice,
      actionTaken: cleanAction,
      createdAt: new Date().toISOString().slice(0, 19).replace('T', ' '),
    };

    this.auditLogs.update((list) => [entry, ...list.slice(0, 99)]);

    if (user) {
      try {
        await setDoc(doc(db, 'auditLogs', id), {
          ownerId: user.uid,
          eventType,
          severity,
          target: cleanTarget,
          deviceName: cleanDevice,
          actionTaken: cleanAction,
          createdAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, `auditLogs/${id}`);
      }
    }
  }
}
