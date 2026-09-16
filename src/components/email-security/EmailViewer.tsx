'use client';

import React, { useState } from 'react';
import { HighlightedPhrase } from './HighlightedPhrase';
import { AttachmentList } from './AttachmentList';
import {
  CornerUpLeft,
  MoreVertical,
  AlertCircle,
  Clock,
} from 'lucide-react';

interface EmailViewerProps {
  isScanning?: boolean;
}

export const EmailViewer: React.FC<EmailViewerProps> = ({ isScanning = false }) => {
  const [showMoreActions, setShowMoreActions] = useState(false);

  return (
    <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900/60 p-5 md:p-6 shadow-sm dark:shadow-none backdrop-blur-sm space-y-6">
      {/* Email Header / Sender Info Bar */}
      <div className="space-y-4 border-b border-zinc-200 dark:border-zinc-800/80 pb-4">
        {/* Subject & Status */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="rounded bg-red-100 dark:bg-red-950/60 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800/60 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider">
                Phishing Alert
              </span>
              <span className="text-[11px] text-zinc-500">Inbound Mail</span>
            </div>
            <h1 className="text-lg md:text-xl font-bold text-zinc-900 dark:text-zinc-100 tracking-tight leading-snug">
              Urgent: Your account will be permanently closed today
            </h1>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => alert('Simulated action: Reply is disabled for flagged phishing emails.')}
              className="flex items-center gap-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 px-3 py-1.5 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors cursor-pointer"
            >
              <CornerUpLeft className="h-3.5 w-3.5 text-zinc-400" />
              <span>Reply</span>
            </button>

            <div className="relative">
              <button
                onClick={() => setShowMoreActions((prev) => !prev)}
                className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-1.5 text-zinc-500 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors cursor-pointer"
                title="More Actions"
              >
                <MoreVertical className="h-4 w-4" />
              </button>
              {showMoreActions && (
                <div className="absolute right-0 top-full mt-1 z-20 w-44 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-1 shadow-xl text-xs">
                  <button
                    onClick={() => {
                      setShowMoreActions(false);
                      alert('Simulated headers exported.');
                    }}
                    className="w-full text-left rounded px-2 py-1.5 text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800"
                  >
                    View Raw Headers
                  </button>
                  <button
                    onClick={() => {
                      setShowMoreActions(false);
                      alert('Domain flagged in local sandbox.');
                    }}
                    className="w-full text-left rounded px-2 py-1.5 text-red-600 dark:text-red-400 hover:bg-zinc-100 dark:hover:bg-zinc-800"
                  >
                    Block Sender Domain
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Sender details row */}
        <div className="flex items-start justify-between gap-3 bg-zinc-50 dark:bg-zinc-950/60 rounded-lg p-3 border border-zinc-200 dark:border-zinc-800/80">
          <div className="flex items-center gap-3 min-w-0">
            {/* Sender Avatar */}
            <div className="relative flex h-10 w-10 items-center justify-center rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300 font-bold text-sm shrink-0">
              M
              <span className="absolute -top-1 -right-1 flex h-3.5 w-3.5 items-center justify-center rounded-full bg-red-500 text-[8px] text-white">
                !
              </span>
            </div>

            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <p className="font-bold text-xs text-zinc-900 dark:text-zinc-100 truncate">Microsoft Account Security</p>
                <span className="rounded bg-red-100 dark:bg-red-950/40 border border-red-200 dark:border-red-900/50 px-1.5 py-0.5 text-[9px] font-medium text-red-700 dark:text-red-400">
                  Unverified Domain
                </span>
              </div>
              <p className="text-[11px] font-mono text-zinc-500 dark:text-zinc-400 truncate">
                security-alert@microsoft-account-check.example
              </p>
            </div>
          </div>

          <div className="text-right text-[11px] text-zinc-500 shrink-0 flex items-center gap-1">
            <Clock className="h-3 w-3 text-zinc-400" />
            <span>Today, 10:24 AM</span>
          </div>
        </div>
      </div>

      {/* Email Body with Exact Text & Suspicious Phrase Highlights */}
      <div className="space-y-4 text-xs md:text-sm text-zinc-700 dark:text-zinc-300 leading-relaxed font-sans">
        <p>Hello,</p>

        <p>We detected unusual activity on your account.</p>

        <p>
          Your account will be{' '}
          <HighlightedPhrase
            phrase="permanently closed today"
            explanation="Urgency and fear tactic: this pressures the recipient to act before verifying the message."
          />{' '}
          unless you verify your identity{' '}
          <HighlightedPhrase
            phrase="immediately"
            explanation="Pressure language: scammers often use urgency to prevent careful verification."
          />
          .
        </p>

        {/* Suspicious Link Container */}
        <div className="my-3 rounded-lg border border-red-200 dark:border-red-900/50 bg-red-50 dark:bg-red-950/20 p-3.5 transition-colors hover:border-red-300 dark:hover:border-red-800">
          <div className="flex items-center justify-between text-xs mb-1">
            <span className="text-[10px] font-bold uppercase tracking-wider text-red-600 dark:text-red-400 flex items-center gap-1">
              <AlertCircle className="h-3 w-3" />
              Suspicious Verification Link
            </span>
            <span className="text-[10px] font-mono text-zinc-500">Target: microsoft-account-check.example</span>
          </div>
          <p className="text-xs text-zinc-800 dark:text-zinc-200">
            <span className="text-red-600 dark:text-red-300 font-semibold underline decoration-red-400 decoration-wavy underline-offset-2">
              Click here
            </span>{' '}
            to{' '}
            <HighlightedPhrase
              phrase="verify your password"
              explanation="Credential request: legitimate services should not ask you to provide your password through an email link."
            />{' '}
            and restore access.
          </p>
        </div>

        <p>
          If you do not complete this process{' '}
          <HighlightedPhrase
            phrase="within 10 minutes"
            explanation="Artificial deadline: a short deadline is used to force rushed action."
          />
          , your account may be suspended.
        </p>

        <div className="pt-2 text-zinc-500 dark:text-zinc-400">
          <p>Thank you,</p>
          <p className="font-semibold text-zinc-700 dark:text-zinc-300">Microsoft Account Security Team</p>
        </div>
      </div>

      {/* Attachment Section */}
      <AttachmentList isScanning={isScanning} />
    </div>
  );
};
