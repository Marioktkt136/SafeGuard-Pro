import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SafeguardService } from './core/safeguard.service';
import {
  BlockRuleItem,
  PolicyConfigState,
  ProtectionModelType,
  RuleCategory,
  ScheduleStrictness,
  ScheduleWindowItem,
} from './core/blocking-engine';
import { PinModalComponent } from './components/pin-modal.component';
import { NativeAgentsViewComponent } from './components/native-agents-view.component';

export type NavTab = 'overview' | 'blocklists' | 'schedules' | 'agents' | 'tamper';

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule, PinModalComponent, NativeAgentsViewComponent],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  readonly safeguard = inject(SafeguardService);

  readonly activeTab = signal<NavTab>('overview');

  // Simulator state
  simulatorInput = 'https://www.pornhub.com';

  // Custom Blocklist state
  newRuleDomain = '';
  newRuleCategory: RuleCategory = 'Custom';
  newRuleStrictLock = true;
  newRuleNotes = '';
  readonly ruleFeedback = signal<string>('');
  readonly ruleError = signal<boolean>(false);
  readonly ruleSearchQuery = signal<string>('');
  readonly ruleCategoryFilter = signal<string>('ALL');

  // Schedule form state
  newScheduleName = '';
  newScheduleDays = 'Mon,Tue,Wed,Thu,Fri,Sat,Sun';
  newScheduleStart = '22:00';
  newScheduleEnd = '07:00';
  newScheduleStrictness: ScheduleStrictness = 'Hard Commitment Lock';
  readonly scheduleFeedback = signal<string>('');
  readonly scheduleError = signal<boolean>(false);

  // Tamper & Accountability Partner configuration form
  partnerNameInput = this.safeguard.policy().partnerName;
  partnerEmailInput = this.safeguard.policy().partnerEmail;
  cooldownMinutesInput = this.safeguard.policy().cooldownMinutes;
  newPinInput = this.safeguard.policy().unlockPin;
  readonly policyFeedback = signal<string>('');

  // Audit filter state
  readonly auditFilterType = signal<string>('ALL');
  readonly auditSearchQuery = signal<string>('');

  // PIN Authorization Modal state
  readonly pinModalOpen = signal<boolean>(false);
  readonly pinModalDescription = signal<string>('');
  private pendingAuthorizedCallback: (() => Promise<void>) | null = null;

  readonly filteredBlockRules = computed(() => {
    const q = this.ruleSearchQuery().trim().toLowerCase();
    const cat = this.ruleCategoryFilter();
    return this.safeguard.blockRules().filter((item) => {
      const matchesCat = cat === 'ALL' || item.category === cat;
      const matchesQuery =
        !q ||
        item.domain.toLowerCase().includes(q) ||
        item.notes.toLowerCase().includes(q) ||
        item.category.toLowerCase().includes(q);
      return matchesCat && matchesQuery;
    });
  });

  readonly filteredAuditLogs = computed(() => {
    const typeFilter = this.auditFilterType();
    const q = this.auditSearchQuery().trim().toLowerCase();
    return this.safeguard.auditLogs().filter((log) => {
      const matchesType = typeFilter === 'ALL' || log.eventType === typeFilter;
      const matchesQuery =
        !q ||
        log.target.toLowerCase().includes(q) ||
        log.deviceName.toLowerCase().includes(q) ||
        log.actionTaken.toLowerCase().includes(q);
      return matchesType && matchesQuery;
    });
  });

  setTab(tab: NavTab): void {
    this.activeTab.set(tab);
    if (typeof window !== 'undefined') {
      window.scrollTo({ top: 0, behavior: 'instant' });
    }
  }

  async handlePrimaryHeaderAction(): Promise<void> {
    if (this.safeguard.currentUser()) {
      await this.safeguard.signOutUser();
    } else {
      await this.safeguard.signInWithGoogle();
    }
  }

  async runDomainSimulation(preset?: string): Promise<void> {
    if (preset) {
      this.simulatorInput = preset;
    }
    await this.safeguard.simulateDomainCheck(this.simulatorInput);
  }

  async submitNewBlockRule(): Promise<void> {
    const res = await this.safeguard.addCustomBlockRule(
      this.newRuleDomain,
      this.newRuleCategory,
      this.newRuleStrictLock,
      this.newRuleNotes
    );
    if (!res.ok) {
      this.ruleError.set(true);
      this.ruleFeedback.set(res.error || 'Invalid domain rule.');
      return;
    }
    this.ruleError.set(false);
    this.ruleFeedback.set(`Added "${this.newRuleDomain.trim()}" to active blocklist and synchronized across endpoints.`);
    this.newRuleDomain = '';
    this.newRuleNotes = '';
  }

  async handleRemoveBlockRule(rule: BlockRuleItem): Promise<void> {
    const res = await this.safeguard.removeBlockRule(rule);
    if (!res.ok && res.requiresPin) {
      this.requestPinAuthorization(
        `Removing strict-locked domain "${rule.domain}" requires ${this.safeguard.policy().protectionModel === 'model-a' ? 'Trusted Partner' : 'Administrator'} PIN verification.`,
        async () => {
          await this.safeguard.removeBlockRule(rule);
        }
      );
    }
  }

  async submitNewSchedule(): Promise<void> {
    const res = await this.safeguard.addScheduleWindow(
      this.newScheduleName,
      this.newScheduleDays,
      this.newScheduleStart,
      this.newScheduleEnd,
      this.newScheduleStrictness
    );
    if (!res.ok) {
      this.scheduleError.set(true);
      this.scheduleFeedback.set(res.error || 'Could not create schedule.');
      return;
    }
    this.scheduleError.set(false);
    this.scheduleFeedback.set(`Schedule "${this.newScheduleName.trim()}" created and active.`);
    this.newScheduleName = '';
  }

  async handleToggleSchedule(sched: ScheduleWindowItem): Promise<void> {
    const res = await this.safeguard.toggleSchedule(sched);
    if (!res.ok && res.requiresPin) {
      this.requestPinAuthorization(
        `Disabling Hard Commitment schedule "${sched.name}" (${sched.startTime}–${sched.endTime}) requires Partner/Administrator PIN verification.`,
        async () => {
          await this.safeguard.toggleSchedule(sched);
        }
      );
    }
  }

  async handleTogglePolicyFlag(
    field: keyof PolicyConfigState,
    label: string
  ): Promise<void> {
    const currentVal = Boolean(this.safeguard.policy()[field]);
    // Turning OFF a protection flag when session is locked requires Partner/Admin PIN
    if (currentVal && !this.safeguard.sessionAuthorized()) {
      await this.safeguard.recordAuditEvent(
        'Tamper Attempt',
        'Critical',
        label,
        'Management Console',
        `Blocked attempt to disable "${label}" without Partner/Admin PIN`
      );
      this.requestPinAuthorization(
        `Disabling "${label}" lowers tamper-resistant protection and requires Partner/Administrator PIN authorization.`,
        async () => {
          await this.safeguard.updatePolicyField({ [field]: false });
        }
      );
      return;
    }
    await this.safeguard.updatePolicyField({ [field]: !currentVal });
  }

  async selectProtectionModel(model: ProtectionModelType): Promise<void> {
    if (this.safeguard.policy().protectionModel === model) return;
    await this.safeguard.updatePolicyField({ protectionModel: model });
    this.policyFeedback.set(
      model === 'model-a'
        ? 'Switched to Model A — Self-Control Protection (Trusted Accountability Partner + Cooldown).'
        : 'Switched to Model B — Administrator-Controlled Protection (Restricted User + MDM Enforcement).'
    );
  }

  async saveAccountabilitySettings(): Promise<void> {
    if (!this.safeguard.sessionAuthorized()) {
      this.requestPinAuthorization(
        'Updating Accountability Partner credentials or cooldown duration requires current PIN verification.',
        async () => {
          await this.persistAccountabilityForm();
        }
      );
      return;
    }
    await this.persistAccountabilityForm();
  }

  private async persistAccountabilityForm(): Promise<void> {
    await this.safeguard.updatePolicyField({
      partnerName: this.partnerNameInput,
      partnerEmail: this.partnerEmailInput,
      cooldownMinutes: Number(this.cooldownMinutesInput),
      unlockPin: this.newPinInput,
    });
    this.policyFeedback.set('Saved accountability partner & authorization policy.');
  }

  triggerUninstallGuardTest(): void {
    void this.safeguard.recordAuditEvent(
      'Tamper Attempt',
      'Critical',
      'Service Uninstallation / Stop Request',
      'DESKTOP-WIN11-PRO',
      'Uninstallation blocked by SafeGuard Watchdog — Partner/Admin authorization required'
    );
    this.requestPinAuthorization(
      'Uninstallation Protection Active: Stopping SafeGuardFilterSvc or removing system-level DNS/Hosts locks requires Partner/Admin PIN authorization.',
      async () => {
        this.policyFeedback.set('Authorization verified. Temporary maintenance window unlocked.');
      }
    );
  }

  requestPinAuthorization(description: string, onUnlocked?: () => Promise<void>): void {
    this.pinModalDescription.set(description);
    this.pendingAuthorizedCallback = onUnlocked ?? null;
    this.pinModalOpen.set(true);
  }

  async onPinUnlocked(): Promise<void> {
    if (this.pendingAuthorizedCallback) {
      const cb = this.pendingAuthorizedCallback;
      this.pendingAuthorizedCallback = null;
      await cb();
    }
  }

  exportAuditLogsCsv(): void {
    const rows = [
      ['Timestamp', 'Event Type', 'Severity', 'Target', 'Endpoint', 'Enforcement Action'],
      ...this.filteredAuditLogs().map((l) => [
        l.createdAt,
        l.eventType,
        l.severity,
        l.target,
        l.deviceName,
        l.actionTaken,
      ]),
    ];
    const csv = rows
      .map((r) => r.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      .join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'safeguard-pro-audit-ledger.csv';
    a.click();
    URL.revokeObjectURL(url);
  }
}
