import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SafeguardService } from '../core/safeguard.service';
import { DevicePlatform, generateNativeAgentConfig } from '../core/blocking-engine';

@Component({
  selector: 'app-native-agents-view',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="space-y-8">
      <!-- Top Section Header & Device Enrollment Form -->
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        <div class="lg:col-span-7 space-y-4">
          <p class="text-xs font-medium text-sky-400">
            Hybrid Cross-Platform Enforcement Architecture
          </p>
          <h2 class="text-2xl font-semibold text-slate-100 tracking-tight">
            Enrolled Endpoints &amp; Native System Daemons
          </h2>
          <p class="text-sm text-slate-400 leading-relaxed max-w-2xl">
            Because a cross-platform management UI cannot independently enforce operating-system restrictions, SafeGuard Pro pairs this centralized policy console with native OS components: a C#/.NET Windows Service with NTFS Hosts ACL locking, an Android Kotlin VpnService with Always-On Lockdown, and an iOS Supervised NetworkExtension profile.
          </p>

          <!-- Enrolled Devices Table -->
          <div class="mt-6 rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
            <div class="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
              <span class="text-xs font-semibold text-slate-200">
                Registered Protection Endpoints ({{ safeguard.devices().length }})
              </span>
              <span class="text-xs text-slate-400 font-mono tabular-nums">
                Sync Interval: 30s · DoH Resolver: 185.228.168.168
              </span>
            </div>
            <div class="overflow-x-auto">
              <table class="w-full text-left border-collapse">
                <thead>
                  <tr class="border-b border-slate-800/80 text-xs text-slate-400">
                    <th class="py-3 px-4 font-medium">Endpoint Hostname</th>
                    <th class="py-3 px-4 font-medium">OS &amp; Native Engine</th>
                    <th class="py-3 px-4 font-medium">Tamper Locks</th>
                    <th class="py-3 px-4 font-medium text-right">Integrity Status</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-800/60 text-sm">
                  @for (dev of safeguard.devices(); track dev.id) {
                    <tr class="hover:bg-slate-800/30 transition-colors">
                      <td class="py-3 px-4">
                        <div class="font-medium text-slate-100">{{ dev.name }}</div>
                        <div class="text-xs text-slate-400 font-mono tabular-nums">
                          {{ dev.agentVersion }} · Synced {{ dev.createdAt }}
                        </div>
                      </td>
                      <td class="py-3 px-4">
                        <div class="text-slate-200">{{ dev.platform }}</div>
                        <div class="text-xs text-slate-400">{{ dev.agentType }}</div>
                      </td>
                      <td class="py-3 px-4 text-xs text-slate-300">
                        <span>DNS Lock: {{ dev.dnsLockActive ? 'Enforced' : 'Off' }}</span>
                        <span aria-hidden="true"> · </span>
                        <span>Hosts/VPN: {{ dev.hostsLockActive ? 'Locked' : 'Off' }}</span>
                      </td>
                      <td class="py-3 px-4 text-right font-mono text-xs">
                        <span
                          [class.text-emerald-400]="dev.status === 'Protected'"
                          [class.text-amber-400]="dev.status === 'Sync Pending'"
                          [class.text-rose-400]="dev.status === 'Tamper Alert'"
                        >
                          {{ dev.status }}
                        </span>
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- Enroll New Endpoint Form -->
        <div class="lg:col-span-5 rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-4">
          <h3 class="text-base font-semibold text-slate-100">
            Register New Device Endpoint
          </h3>
          <p class="text-xs text-slate-400 leading-relaxed">
            Enroll a Windows PC, Android phone, or iOS device to synchronize your active adult-content blocklist, recurring schedules, and tamper-protection policies.
          </p>

          <form (ngSubmit)="handleEnrollDevice()" class="space-y-4 pt-1">
            <div>
              <label for="device-name-input" class="block text-xs font-medium text-slate-300 mb-1.5">
                Device Hostname or Label
              </label>
              <input
                id="device-name-input"
                name="newDeviceName"
                type="text"
                [(ngModel)]="newDeviceName"
                placeholder="e.g. THINKPAD-X1-CARBON or Galaxy-S25"
                class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
              />
            </div>

            <div>
              <label for="device-platform-select" class="block text-xs font-medium text-slate-300 mb-1.5">
                Target Operating System
              </label>
              <select
                id="device-platform-select"
                name="newDevicePlatform"
                [(ngModel)]="newDevicePlatform"
                class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
              >
                <option value="Windows">Windows 10/11 (C#/.NET Service + Hosts &amp; Registry Lock)</option>
                <option value="Android">Android 12+ (Kotlin VpnService + DeviceAdmin Lockdown)</option>
                <option value="iOS">iOS / iPadOS (Swift NetworkExtension + Supervised MDM Profile)</option>
              </select>
            </div>

            @if (enrollFeedback()) {
              <p
                class="text-xs font-medium"
                [class.text-rose-400]="enrollError()"
                [class.text-emerald-400]="!enrollError()"
              >
                {{ enrollFeedback() }}
              </p>
            }

            <button
              type="submit"
              class="w-full rounded-lg bg-sky-500 px-4 py-2.5 text-xs font-semibold text-slate-950 hover:bg-sky-400 transition-colors whitespace-nowrap shrink-0"
            >
              Enroll Endpoint &amp; Generate Agent Key
            </button>
          </form>
        </div>
      </div>

      <!-- Native Agent Code & Policy Generator -->
      <div class="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h3 class="text-base font-semibold text-slate-100">
              Native OS Enforcement Artifact Generator
            </h3>
            <p class="text-xs text-slate-400 mt-0.5">
              Live system-level scripts and native daemon configurations compiled from your current {{ safeguard.blockRules().length }} custom rules and tamper settings.
            </p>
          </div>

          <!-- Interactive Segmented Control -->
          <div class="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800">
            @for (plat of platforms; track plat) {
              <button
                type="button"
                (click)="selectPlatform(plat)"
                class="px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0"
                [class.bg-slate-800]="selectedPlatform() === plat"
                [class.text-slate-100]="selectedPlatform() === plat"
                [class.text-slate-400]="selectedPlatform() !== plat"
              >
                {{ plat }} Agent
              </button>
            }
          </div>
        </div>

        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-slate-300">
          <div>
            <span class="font-mono text-sky-400">{{ generatedArtifact().filename }}</span>
            <span aria-hidden="true"> · </span>
            <span>{{ generatedArtifact().language }}</span>
          </div>
          <div class="flex items-center gap-2">
            <button
              type="button"
              (click)="copyArtifactCode()"
              class="rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              {{ copied() ? 'Copied to Clipboard' : 'Copy Enforcement Code' }}
            </button>
            <button
              type="button"
              (click)="downloadArtifactFile()"
              class="rounded-lg bg-slate-100 px-3 py-1.5 text-xs font-semibold text-slate-950 hover:bg-white transition-colors whitespace-nowrap shrink-0"
            >
              Download {{ generatedArtifact().filename }}
            </button>
          </div>
        </div>

        <p class="text-xs text-slate-400 leading-relaxed">
          {{ generatedArtifact().summary }}
        </p>

        <pre class="rounded-lg border border-slate-800 bg-slate-950 p-4 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed max-h-96">{{ generatedArtifact().code }}</pre>
      </div>
    </div>
  `,
})
export class NativeAgentsViewComponent {
  readonly safeguard = inject(SafeguardService);

  readonly platforms: DevicePlatform[] = ['Windows', 'Android', 'iOS'];
  readonly selectedPlatform = signal<DevicePlatform>('Windows');
  readonly copied = signal<boolean>(false);

  newDeviceName = '';
  newDevicePlatform: DevicePlatform = 'Windows';
  readonly enrollFeedback = signal<string>('');
  readonly enrollError = signal<boolean>(false);

  readonly generatedArtifact = computed(() =>
    generateNativeAgentConfig(
      this.selectedPlatform(),
      this.safeguard.policy(),
      this.safeguard.blockRules()
    )
  );

  selectPlatform(platform: DevicePlatform): void {
    this.selectedPlatform.set(platform);
    this.copied.set(false);
  }

  async handleEnrollDevice(): Promise<void> {
    const res = await this.safeguard.enrollDevice(this.newDeviceName, this.newDevicePlatform);
    if (!res.ok) {
      this.enrollError.set(true);
      this.enrollFeedback.set(res.error || 'Could not enroll device.');
      return;
    }
    this.enrollError.set(false);
    this.enrollFeedback.set(`Enrolled "${this.newDeviceName.trim()}" (${this.newDevicePlatform}) and synchronized policy.`);
    this.newDeviceName = '';
  }

  async copyArtifactCode(): Promise<void> {
    try {
      await navigator.clipboard.writeText(this.generatedArtifact().code);
      this.copied.set(true);
    } catch {
      this.copied.set(true);
    }
  }

  downloadArtifactFile(): void {
    const artifact = this.generatedArtifact();
    const blob = new Blob([artifact.code], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = artifact.filename;
    a.click();
    URL.revokeObjectURL(url);
  }
}
