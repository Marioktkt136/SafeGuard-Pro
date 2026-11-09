import { ChangeDetectionStrategy, Component, EventEmitter, Input, Output, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SafeguardService } from '../core/safeguard.service';

@Component({
  selector: 'app-pin-modal',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (open) {
      <div
        class="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-xs p-4"
        role="dialog"
        aria-modal="true"
        aria-labelledby="pin-dialog-title"
      >
        <div class="w-full max-w-md rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
          <div class="flex items-start justify-between gap-4">
            <div>
              <p class="text-xs font-medium text-amber-400">
                Tamper-Resistant Protection Gate · {{ safeguard.policy().protectionModel === 'model-a' ? 'Model A Self-Control' : 'Model B Admin MDM' }}
              </p>
              <h2 id="pin-dialog-title" class="mt-1 text-lg font-semibold text-slate-100">
                Authorization Required
              </h2>
            </div>
            <button
              type="button"
              (click)="closeModal()"
              aria-label="Close authorization dialog"
              class="rounded-lg px-2.5 py-1 text-xs font-medium text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors whitespace-nowrap shrink-0"
            >
              Cancel
            </button>
          </div>

          <p class="mt-3 text-sm text-slate-300 leading-relaxed">
            {{ actionDescription || 'Modifying locked protection rules, disabling commitment schedules, or relaxing DNS/Hosts locks requires authorization from your designated accountability partner or administrator.' }}
          </p>

          <div class="mt-4 border-t border-slate-800 pt-4 text-xs text-slate-400 space-y-1">
            <div>
              Designated Authorizer: <span class="text-slate-200 font-medium">{{ safeguard.policy().partnerName }}</span>
              <span aria-hidden="true"> · </span>
              <span class="font-mono">{{ safeguard.policy().partnerEmail }}</span>
            </div>
            <div>
              Mandatory Cooldown Without PIN: <span class="font-mono tabular-nums text-slate-200">{{ safeguard.policy().cooldownMinutes }} min</span>
              <span aria-hidden="true"> · </span>
              <span>Demo PIN: <code class="font-mono text-sky-400">{{ safeguard.policy().unlockPin }}</code></span>
            </div>
          </div>

          <form (ngSubmit)="submitPin()" class="mt-5 space-y-4">
            <div>
              <label for="partner-pin-input" class="block text-xs font-medium text-slate-300 mb-1.5">
                Enter Partner / Administrator Authorization PIN
              </label>
              <input
                id="partner-pin-input"
                name="pinInput"
                type="password"
                [(ngModel)]="pinInput"
                autocomplete="off"
                placeholder="Enter 6-digit PIN (e.g. 482910)"
                class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm font-mono tabular-nums text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
              />
            </div>

            @if (feedbackMessage()) {
              <p
                class="text-xs font-medium"
                [class.text-rose-400]="!feedbackSuccess()"
                [class.text-emerald-400]="feedbackSuccess()"
              >
                {{ feedbackMessage() }}
              </p>
            }

            <div class="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                (click)="fillDemoPin()"
                class="rounded-lg border border-slate-700 bg-slate-800/70 px-3.5 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
              >
                Use Demo Partner PIN
              </button>
              <button
                type="submit"
                class="rounded-lg bg-sky-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-sky-400 transition-colors whitespace-nowrap shrink-0"
              >
                Verify &amp; Unlock Session
              </button>
            </div>
          </form>
        </div>
      </div>
    }
  `,
})
export class PinModalComponent {
  readonly safeguard = inject(SafeguardService);

  @Input() open = false;
  @Input() actionDescription = '';
  @Output() closed = new EventEmitter<void>();
  @Output() unlocked = new EventEmitter<void>();

  pinInput = '';
  readonly feedbackMessage = signal<string>('');
  readonly feedbackSuccess = signal<boolean>(false);

  fillDemoPin(): void {
    this.pinInput = this.safeguard.policy().unlockPin;
    this.feedbackMessage.set('');
  }

  async submitPin(): Promise<void> {
    const res = await this.safeguard.unlockSessionWithPin(this.pinInput);
    this.feedbackSuccess.set(res.authorized);
    this.feedbackMessage.set(res.reason);
    if (res.authorized) {
      this.pinInput = '';
      this.unlocked.emit();
      this.closed.emit();
    }
  }

  closeModal(): void {
    this.pinInput = '';
    this.feedbackMessage.set('');
    this.closed.emit();
  }
}
