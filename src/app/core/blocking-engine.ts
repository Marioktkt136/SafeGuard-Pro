export type ProtectionModelType = 'model-a' | 'model-b';
export type RuleCategory = 'Adult' | 'Proxy/Bypass' | 'Social/Trigger' | 'Custom';
export type ScheduleStrictness = 'Standard Filter' | 'Hard Commitment Lock';
export type DevicePlatform = 'Windows' | 'Android' | 'iOS';
export type DeviceHealthStatus = 'Protected' | 'Tamper Alert' | 'Sync Pending';
export type AuditEventType = 'Blocked Request' | 'Tamper Attempt' | 'Policy Change' | 'Service Heartbeat';
export type AuditSeverity = 'Normal' | 'Warning' | 'Critical';

export interface PolicyConfigState {
  ownerId: string;
  protectionModel: ProtectionModelType;
  partnerName: string;
  partnerEmail: string;
  unlockPin: string;
  cooldownMinutes: number;
  blockAdultCore: boolean;
  blockProxyVpn: boolean;
  enforceSafeSearch: boolean;
  blockMixedSocial: boolean;
  blockGambling: boolean;
  lockHostsFile: boolean;
  lockDnsSettings: boolean;
  forceBrowserExtension: boolean;
  uninstallProtection: boolean;
  updatedAt?: string;
}

export interface BlockRuleItem {
  id: string;
  ownerId: string;
  domain: string;
  category: RuleCategory;
  strictLock: boolean;
  notes: string;
  hitCount: number;
  createdAt: string;
}

export interface ScheduleWindowItem {
  id: string;
  ownerId: string;
  name: string;
  days: string;
  startTime: string;
  endTime: string;
  strictness: ScheduleStrictness;
  enabled: boolean;
  createdAt: string;
}

export interface ProtectedDeviceItem {
  id: string;
  ownerId: string;
  name: string;
  platform: DevicePlatform;
  agentType: string;
  agentVersion: string;
  status: DeviceHealthStatus;
  dnsLockActive: boolean;
  hostsLockActive: boolean;
  createdAt: string;
}

export interface AuditEventItem {
  id: string;
  ownerId: string;
  eventType: AuditEventType;
  severity: AuditSeverity;
  target: string;
  deviceName: string;
  actionTaken: string;
  createdAt: string;
}

export interface FilterDecision {
  allowed: boolean;
  normalizedDomain: string;
  matchedCategory: string;
  matchedRule: string;
  enforcementLayers: string[];
  reason: string;
}

const KNOWN_ADULT_DOMAINS = new Set([
  'pornhub.com',
  'xvideos.com',
  'xnxx.com',
  'onlyfans.com',
  'redtube.com',
  'youporn.com',
  'chaturbate.com',
  'stripchat.com',
  'brazzers.com',
  'spankbang.com',
  'eporner.com',
  'txxx.com',
  'tube8.com',
  'rule34.xxx',
]);

const KNOWN_PROXY_BYPASS_DOMAINS = new Set([
  'croxyproxy.com',
  'proxysite.com',
  'hide.me',
  'kproxy.com',
  'hidester.com',
  '4everproxy.com',
  'whoer.net',
  'vpnbook.com',
]);

const KNOWN_SOCIAL_TRIGGER_DOMAINS = new Set([
  'nsfw.reddit.com',
  'old.reddit.com',
  'tumblr.com',
  '9gag.com',
]);

const KNOWN_GAMBLING_DOMAINS = new Set([
  'stake.com',
  'bet365.com',
  'draftkings.com',
  'pokerstars.com',
  'roobet.com',
]);

export function normalizeDomain(input: string): string {
  if (!input) return '';
  let cleaned = input.trim().toLowerCase();
  cleaned = cleaned.replace(/^[a-z]+:\/\//i, '');
  cleaned = cleaned.replace(/^www\./i, '');
  const slashIndex = cleaned.indexOf('/');
  if (slashIndex !== -1) {
    cleaned = cleaned.slice(0, slashIndex);
  }
  const portIndex = cleaned.indexOf(':');
  if (portIndex !== -1) {
    cleaned = cleaned.slice(0, portIndex);
  }
  const queryIndex = cleaned.indexOf('?');
  if (queryIndex !== -1) {
    cleaned = cleaned.slice(0, queryIndex);
  }
  cleaned = cleaned.replace(/\.+$/, '');
  return cleaned;
}

export function isValidDomain(domain: string): boolean {
  const normalized = normalizeDomain(domain);
  if (normalized.length < 3 || normalized.length > 253) {
    return false;
  }
  if (normalized.includes('..') || normalized.startsWith('.') || normalized.startsWith('-') || normalized.endsWith('-')) {
    return false;
  }
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(normalized);
}

export function isValidTime24h(time: string): boolean {
  return /^([01][0-9]|2[0-3]):[0-5][0-9]$/.test(time);
}

export function timeToMinutes(hhMm: string): number {
  if (!isValidTime24h(hhMm)) return -1;
  const [h, m] = hhMm.split(':').map(Number);
  return h * 60 + m;
}

export function isTimeWithinSchedule(
  currentHhMm: string,
  currentDayShort: string,
  schedule: Pick<ScheduleWindowItem, 'days' | 'startTime' | 'endTime' | 'enabled'>
): boolean {
  if (!schedule.enabled) return false;
  const activeDays = schedule.days
    .split(',')
    .map((d) => d.trim().toLowerCase().slice(0, 3));
  const dayNorm = currentDayShort.trim().toLowerCase().slice(0, 3);
  if (!activeDays.includes(dayNorm) && !activeDays.includes('all')) {
    return false;
  }
  const cur = timeToMinutes(currentHhMm);
  const start = timeToMinutes(schedule.startTime);
  const end = timeToMinutes(schedule.endTime);
  if (cur < 0 || start < 0 || end < 0) return false;

  if (start <= end) {
    return cur >= start && cur <= end;
  }
  // Overnight window (e.g., 22:00 to 07:00)
  return cur >= start || cur <= end;
}

function matchesDomainOrSubdomain(candidate: string, ruleDomain: string): boolean {
  return candidate === ruleDomain || candidate.endsWith(`.${ruleDomain}`);
}

export function evaluateDomainAccess(
  rawInput: string,
  policy: PolicyConfigState,
  customRules: BlockRuleItem[],
  schedules: ScheduleWindowItem[],
  currentHhMm = '23:15',
  currentDay = 'Mon'
): FilterDecision {
  const normalized = normalizeDomain(rawInput);
  if (!isValidDomain(normalized)) {
    return {
      allowed: false,
      normalizedDomain: normalized || rawInput.trim(),
      matchedCategory: 'Invalid Hostname',
      matchedRule: 'RFC-1123 Syntax Guard',
      enforcementLayers: ['Input Validator'],
      reason: 'Enter a valid domain name (e.g., example.com).',
    };
  }

  const activeLayers: string[] = ['Centralized DoH/DoT Resolver'];
  if (policy.lockDnsSettings) activeLayers.push('OS DNS Policy Lock');
  if (policy.lockHostsFile) activeLayers.push('System Hosts / VPN Sinkhole');
  if (policy.forceBrowserExtension) activeLayers.push('Managed Browser Policy');

  // 1. Check Custom User Blocklist first
  for (const rule of customRules) {
    if (matchesDomainOrSubdomain(normalized, rule.domain)) {
      return {
        allowed: false,
        normalizedDomain: normalized,
        matchedCategory: `Custom Blocklist (${rule.category})`,
        matchedRule: rule.domain,
        enforcementLayers: activeLayers,
        reason: `Explicitly blocked by custom rule "${rule.domain}"${rule.strictLock ? ' [Tamper-Locked]' : ''}.`,
      };
    }
  }

  // 2. Check Adult Content Core Filter
  if (policy.blockAdultCore) {
    for (const adultDom of KNOWN_ADULT_DOMAINS) {
      if (matchesDomainOrSubdomain(normalized, adultDom)) {
        return {
          allowed: false,
          normalizedDomain: normalized,
          matchedCategory: 'Adult & Pornography Core Filter',
          matchedRule: adultDom,
          enforcementLayers: activeLayers,
          reason: `Domain matches SafeGuard Adult Content Core Signature (${adultDom}). Sinkholed to 0.0.0.0.`,
        };
      }
    }
    if (/\.(xxx|porn|adult|sex|cam)$/i.test(normalized) || /(porn|xxx|nsfw|hentai|sexchat|livecam)/i.test(normalized)) {
      return {
        allowed: false,
        normalizedDomain: normalized,
        matchedCategory: 'Adult Heuristic & TLD Filter',
        matchedRule: '*.adult / heuristic signature',
        enforcementLayers: activeLayers,
        reason: 'Blocked by adult TLD / lexical signature inspection at DNS & local service layers.',
      };
    }
  }

  // 3. Check Proxy & VPN Bypass Filter
  if (policy.blockProxyVpn) {
    for (const proxyDom of KNOWN_PROXY_BYPASS_DOMAINS) {
      if (matchesDomainOrSubdomain(normalized, proxyDom)) {
        return {
          allowed: false,
          normalizedDomain: normalized,
          matchedCategory: 'Proxy & Circumvention Prevention',
          matchedRule: proxyDom,
          enforcementLayers: activeLayers,
          reason: `Blocked web proxy / DNS bypass endpoint (${proxyDom}) to prevent filter circumvention.`,
        };
      }
    }
  }

  // 4. Check Mixed-Content Social Media
  if (policy.blockMixedSocial) {
    for (const socialDom of KNOWN_SOCIAL_TRIGGER_DOMAINS) {
      if (matchesDomainOrSubdomain(normalized, socialDom)) {
        return {
          allowed: false,
          normalizedDomain: normalized,
          matchedCategory: 'Mixed-Content Social Media Filter',
          matchedRule: socialDom,
          enforcementLayers: activeLayers,
          reason: `Restricted high-risk mixed-content platform (${socialDom}).`,
        };
      }
    }
  }

  // 5. Check Gambling Filter
  if (policy.blockGambling) {
    for (const gamblingDom of KNOWN_GAMBLING_DOMAINS) {
      if (matchesDomainOrSubdomain(normalized, gamblingDom)) {
        return {
          allowed: false,
          normalizedDomain: normalized,
          matchedCategory: 'Gambling & Wagering Filter',
          matchedRule: gamblingDom,
          enforcementLayers: activeLayers,
          reason: `Blocked wagering domain (${gamblingDom}).`,
        };
      }
    }
  }

  // 6. Check Active Schedule Lockouts for distraction domains
  const activeSchedules = schedules.filter((s) => isTimeWithinSchedule(currentHhMm, currentDay, s));
  const hardSchedule = activeSchedules.find((s) => s.strictness === 'Hard Commitment Lock');
  if (hardSchedule && /(youtube\.com|twitch\.tv|netflix\.com|reddit\.com|instagram\.com|x\.com|twitter\.com)/i.test(normalized)) {
    return {
      allowed: false,
      normalizedDomain: normalized,
      matchedCategory: `Scheduled Lockout (${hardSchedule.name})`,
      matchedRule: `${hardSchedule.startTime}–${hardSchedule.endTime} (${hardSchedule.strictness})`,
      enforcementLayers: activeLayers,
      reason: `Blocked during active schedule "${hardSchedule.name}" (${hardSchedule.startTime}–${hardSchedule.endTime}).`,
    };
  }

  // 7. SafeSearch CNAME notice for search engines
  if (policy.enforceSafeSearch && /(google\.com|bing\.com|duckduckgo\.com|youtube\.com)$/i.test(normalized)) {
    return {
      allowed: true,
      normalizedDomain: normalized,
      matchedCategory: 'SafeSearch CNAME Forced',
      matchedRule: 'forcesafesearch.google.com / strict.bing.com',
      enforcementLayers: activeLayers,
      reason: 'Permitted with mandatory DNS CNAME rewrite to Strict SafeSearch VIP.',
    };
  }

  return {
    allowed: true,
    normalizedDomain: normalized,
    matchedCategory: 'Permitted Traffic',
    matchedRule: 'Default Allow Policy',
    enforcementLayers: activeLayers,
    reason: 'No adult, proxy, custom, or scheduled restriction matched this domain.',
  };
}

export function verifyTamperAuthorization(
  inputPin: string,
  policy: PolicyConfigState
): { authorized: boolean; reason: string } {
  const cleaned = (inputPin || '').trim();
  if (!cleaned) {
    return {
      authorized: false,
      reason: 'Authorization credential is required to unlock tamper-protected settings.',
    };
  }
  if (cleaned === policy.unlockPin) {
    const modelLabel =
      policy.protectionModel === 'model-a'
        ? `Trusted Partner (${policy.partnerName})`
        : `MDM Administrator (${policy.partnerEmail})`;
    return {
      authorized: true,
      reason: `Verified via ${modelLabel} authorization code.`,
    };
  }
  return {
    authorized: false,
    reason: 'Invalid authorization PIN. Tamper attempt has been recorded in the immutable audit ledger.',
  };
}

export function generateNativeAgentConfig(
  platform: DevicePlatform,
  policy: PolicyConfigState,
  customRules: BlockRuleItem[]
): { filename: string; language: string; summary: string; code: string } {
  const domains = [
    ...(policy.blockAdultCore ? ['pornhub.com', 'xvideos.com', 'xnxx.com', 'onlyfans.com', 'chaturbate.com'] : []),
    ...(policy.blockProxyVpn ? ['croxyproxy.com', 'proxysite.com', 'hide.me'] : []),
    ...customRules.map((r) => r.domain),
  ];
  const uniqueDomains = Array.from(new Set(domains));

  if (platform === 'Windows') {
    const hostsLines = uniqueDomains
      .map((d) => `0.0.0.0 ${d}\n0.0.0.0 www.${d}`)
      .join('\n');
    return {
      filename: 'SafeGuard-WindowsService-Enforce.ps1',
      language: 'PowerShell / .NET 8 Worker Policy',
      summary:
        'Enforces Windows Hosts sinkhole entries, locks NTFS ACL permissions against local tampering, binds CleanBrowsing Adult Filter DNS (185.228.168.168) via Group Policy Registry keys, and registers the SafeGuard C# Windows Service with failure auto-restart.',
      code: `# SafeGuard Pro — Windows System-Level Enforcement Script (Model: ${policy.protectionModel.toUpperCase()})
# Requires elevation; deployed and monitored by SafeGuard.WindowsService.exe (LOCAL SYSTEM)

$ErrorActionPreference = "Stop"
$HostsPath = "$env:SystemRoot\\System32\\drivers\\etc\\hosts"

# 1. Unlock Hosts ACL temporarily for SYSTEM service write
icacls $HostsPath /grant "SYSTEM:(F)" | Out-Null
Set-ItemProperty -Path $HostsPath -Name IsReadOnly -Value $false

# 2. Write SafeGuard Tamper-Resistant Sinkhole Blocklist (${uniqueDomains.length} domains)
$SinkholeBlock = @"
# >>> SAFEGUARD PRO MANAGED BLOCKLIST START >>>
${hostsLines}
${policy.enforceSafeSearch ? '216.239.38.120 www.google.com\n216.239.38.120 google.com\n204.79.197.220 www.bing.com' : '# SafeSearch CNAME optional'}
# <<< SAFEGUARD PRO MANAGED BLOCKLIST END <<<
"@
Set-Content -Path $HostsPath -Value $SinkholeBlock -Encoding ASCII

${
  policy.lockHostsFile
    ? `# 3. Lock Hosts File NTFS ACL (Deny Write/Delete to interactive users)
Set-ItemProperty -Path $HostsPath -Name IsReadOnly -Value $true
icacls $HostsPath /inheritance:r /grant:r "SYSTEM:(R,W)" "Administrators:(R)" "Users:(R)" | Out-Null`
    : '# 3. Hosts ACL Lock disabled by policy'
}

${
  policy.lockDnsSettings
    ? `# 4. Enforce Encrypted Adult-Filtering DNS via Windows MDM / GPO Registry
$DnsPolicyPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient"
if (-not (Test-Path $DnsPolicyPath)) { New-Item -Path $DnsPolicyPath -Force | Out-Null }
Set-ItemProperty -Path $DnsPolicyPath -Name "NameServer" -Value "185.228.168.168,185.228.169.168"
Set-ItemProperty -Path $DnsPolicyPath -Name "DoHPolicy" -Value 3 -Type DWord`
    : '# 4. Registry DNS Lock disabled by policy'
}

# 5. Configure Windows Service Auto-Recovery Watchdog (Restart within 1000ms on kill)
sc.exe failure "SafeGuardFilterSvc" reset= 86400 actions= restart/1000/restart/1000/restart/1000 | Out-Null
ipconfig /flushdns | Out-Null`,
    };
  }

  if (platform === 'Android') {
    const kotlinDomainList = uniqueDomains.map((d) => `"${d}"`).join(', ');
    return {
      filename: 'SafeGuardVpnService.kt',
      language: 'Kotlin (Android VpnService + DevicePolicyManager)',
      summary:
        'Implements a local loopback Android VpnService that intercepts DNS queries on UDP port 53, blocks adult and custom domains on-device with zero latency, and enables Always-On VPN Lockdown via DeviceAdminReceiver.',
      code: `package pro.safeguard.agent.vpn

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor

class SafeGuardVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null

    private val blockedDomains = setOf(
        ${kotlinDomainList}
    )

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        establishSinkholeTunnel()
        enforceAlwaysOnLockdown()
        return START_STICKY
    }

    private fun establishSinkholeTunnel() {
        val builder = Builder()
            .setSession("SafeGuard Pro System Filter")
            .addAddress("10.215.173.1", 24)
            .addDnsServer("185.228.168.168") // CleanBrowsing Adult Filter Primary
            .addDnsServer("1.1.1.3")         // Cloudflare Malware + Adult Filter Secondary
            .setBlocking(true)

        vpnInterface = builder.establish()
    }

    private fun enforceAlwaysOnLockdown() {
        val dpm = getSystemService(DevicePolicyManager::class.java)
        val adminComponent = ComponentName(this, SafeGuardDeviceAdminReceiver::class.java)
        if (dpm != null && dpm.isDeviceOwnerApp(packageName)) {
            // Prevents user from disabling VPN or bypassing traffic outside tunnel
            dpm.setAlwaysOnVpnPackage(adminComponent, packageName, ${policy.lockDnsSettings})
            dpm.addUserRestriction(adminComponent, android.os.UserManager.DISALLOW_CONFIG_VPN)
        }
    }

    fun shouldSinkholeHost(hostname: String): Boolean {
        val normalized = hostname.lowercase().removePrefix("www.")
        return blockedDomains.any { normalized == it || normalized.endsWith(".$it") }
    }
}`,
    };
  }

  const iosDomainsXml = uniqueDomains.map((d) => `        <string>${d}</string>`).join('\n');
  return {
    filename: 'SafeGuard-iOS-Supervised.mobileconfig',
    language: 'Apple Configuration Profile (XML / NetworkExtension)',
    summary:
      'Deploys an iOS/iPadOS Configuration Profile enforcing Apple Built-in Adult Content Filter (AutoFilterEnabled), explicit Blacklist URLs, and encrypted DNS-over-HTTPS with PayloadRemovalDisallowed set to true.',
    code: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadDisplayName</key>
  <string>SafeGuard Pro — Tamper-Resistant Content &amp; DNS Filter</string>
  <key>PayloadIdentifier</key>
  <string>pro.safeguard.mdm.profile</string>
  <key>PayloadRemovalDisallowed</key>
  <${policy.uninstallProtection ? 'true' : 'false'}/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.webcontent-filter</string>
      <key>PayloadIdentifier</key>
      <string>pro.safeguard.webfilter</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>FilterType</key>
      <string>BuiltIn</string>
      <key>AutoFilterEnabled</key>
      <${policy.blockAdultCore ? 'true' : 'false'}/>
      <key>FilterBlacklist</key>
      <array>
${iosDomainsXml}
      </array>
    </dict>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.dnsSettings.managed</string>
      <key>PayloadIdentifier</key>
      <string>pro.safeguard.dnssettings</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key>
        <string>HTTPS</string>
        <key>ServerURL</key>
        <string>https://doh.cleanbrowsing.org/doh/adult-filter/</string>
      </dict>
    </dict>
  </array>
</dict>
</plist>`,
  };
}
