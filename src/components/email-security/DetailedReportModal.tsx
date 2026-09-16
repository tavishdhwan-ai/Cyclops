'use client';

import React from 'react';
import { Modal } from '../ui/Modal';
import { Badge } from '../ui/Badge';
import { mockAttachments } from './AttachmentList';
import {
  ShieldAlert,
  AlertTriangle,
  FileText,
  CheckCircle2,
  ShieldCheck,
  Info,
  Lock,
} from 'lucide-react';

interface DetailedReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  reviewStatus: 'pending' | 'reviewed';
}

export const DetailedReportModal: React.FC<DetailedReportModalProps> = ({
  isOpen,
  onClose,
  reviewStatus,
}) => {
  const detectedSignals = [
    { title: 'Sender impersonation', severity: 'High', description: 'Sender domain does not match official Microsoft infrastructure.' },
    { title: 'Suspicious link', severity: 'High', description: 'Verification target URL points to non-Microsoft domain.' },
    { title: 'Credential request', severity: 'Critical', description: 'Email solicits password entry via external link.' },
    { title: 'Urgency language', severity: 'Medium', description: 'Short timeframe used to pressure recipient into action.' },
    { title: 'Payment-related risk', severity: 'High', description: 'Attachment payload contains unexpected payment wire details.' },
    { title: 'Attachment risk', severity: 'Critical', description: 'Multiple attachments contain suspicious external links & macros.' },
  ];

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="SentinelAI Comprehensive Email Threat Report"
      subtitle="Detailed Security Telemetry & Inspection Findings • Simulated Demo Analysis"
      maxWidth="2xl"
    >
      <div className="space-y-6 max-h-[75vh] overflow-y-auto pr-1">
        {/* Banner Notice */}
        <div className="rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 p-3 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2 text-red-700 dark:text-red-300 font-semibold">
            <ShieldAlert className="h-4 w-4 text-red-500 dark:text-red-400" />
            <span>High Risk Threat Detected (Score: 8.7 / 10)</span>
          </div>
          <span className="rounded bg-zinc-100 dark:bg-zinc-950 px-2 py-0.5 text-[10px] text-zinc-600 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-800 font-mono">
            Demo Data
          </span>
        </div>

        {/* Section 1: Email Summary */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400 flex items-center gap-1.5 border-b border-zinc-200 dark:border-zinc-800 pb-1.5">
            <FileText className="h-3.5 w-3.5" />
            Email Summary
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 space-y-1">
              <span className="text-[10px] font-semibold text-zinc-500 uppercase">Sender Information</span>
              <p className="font-semibold text-zinc-900 dark:text-zinc-100">Microsoft Account Security</p>
              <p className="text-[11px] font-mono text-zinc-500 dark:text-zinc-400 truncate">
                security-alert@microsoft-account-check.example
              </p>
            </div>
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 space-y-1">
              <span className="text-[10px] font-semibold text-zinc-500 uppercase">Subject & Status</span>
              <p className="font-semibold text-zinc-900 dark:text-zinc-100 truncate">Urgent: Your account will be permanently closed today</p>
              <div className="flex items-center justify-between pt-1">
                <span className="text-[11px] text-zinc-500">Scan Status:</span>
                <span className="rounded bg-zinc-200 dark:bg-zinc-900 px-2 py-0.5 text-[10px] font-semibold text-zinc-700 dark:text-zinc-300 border border-zinc-300 dark:border-zinc-800">
                  {reviewStatus === 'reviewed' ? 'Reviewed' : 'Analysis Complete'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Section 2: Detected Signals */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400 flex items-center gap-1.5 border-b border-zinc-200 dark:border-zinc-800 pb-1.5">
            <AlertTriangle className="h-3.5 w-3.5 text-amber-500 dark:text-amber-400" />
            Detected Signals Checklist ({detectedSignals.length})
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {detectedSignals.map((sig, idx) => (
              <div
                key={idx}
                className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-2.5 flex items-start gap-2 text-xs"
              >
                <div className="mt-0.5 rounded-full p-0.5 bg-red-100 dark:bg-red-950/80 border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 shrink-0">
                  <CheckCircle2 className="h-3 w-3" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center justify-between gap-1">
                    <p className="font-semibold text-zinc-800 dark:text-zinc-200 truncate">{sig.title}</p>
                    <Badge level={sig.severity}>{sig.severity}</Badge>
                  </div>
                  <p className="text-[11px] text-zinc-600 dark:text-zinc-400 mt-0.5 leading-tight">{sig.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Section 3: Attachment Summary */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400 flex items-center gap-1.5 border-b border-zinc-200 dark:border-zinc-800 pb-1.5">
            <Lock className="h-3.5 w-3.5" />
            Attachment Scan Summary ({mockAttachments.length} Scanned)
          </h4>
          <div className="space-y-2">
            {mockAttachments.map((att) => (
              <div
                key={att.id}
                className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-xs text-zinc-800 dark:text-zinc-200">{att.fileName}</span>
                    <span className="rounded bg-zinc-200 dark:bg-zinc-900 px-1.5 py-0.5 text-[10px] font-mono text-zinc-600 dark:text-zinc-400 border border-zinc-300 dark:border-zinc-800">
                      {att.fileType}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-zinc-800 dark:text-zinc-200">
                      {att.threatScore} / 10
                    </span>
                    <Badge level={att.riskLevel}>{att.riskLevel}</Badge>
                  </div>
                </div>
                <p className="text-[11px] text-zinc-600 dark:text-zinc-400">
                  <strong>Findings:</strong> {att.findings.join(' • ')}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* Section 4: Final Recommendation */}
        <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/80 p-4 space-y-2">
          <div className="flex items-center gap-2 text-xs font-bold text-zinc-900 dark:text-zinc-100">
            <ShieldCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
            Final Security Recommendation
          </div>
          <p className="text-xs text-zinc-700 dark:text-zinc-300 leading-relaxed font-medium">
            Verify the sender through an independent trusted channel before interacting with this email or its attachments.
          </p>
        </div>

        {/* Disclaimer Footer */}
        <div className="rounded-lg border border-zinc-200 dark:border-zinc-800/80 bg-zinc-100 dark:bg-zinc-950 p-3 text-center space-y-1">
          <p className="text-[11px] font-semibold text-zinc-600 dark:text-zinc-400">
            Simulated demo analysis — Demo data — no real email or attachment was scanned
          </p>
          <p className="text-[10px] text-zinc-500">
            Risk estimate — not a guarantee of safety. SentinelAI Phase 1 Prototype.
          </p>
        </div>

        {/* Close Button */}
        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="rounded-lg bg-zinc-900 dark:bg-zinc-100 text-zinc-100 dark:text-zinc-900 px-4 py-2 text-xs font-semibold hover:bg-zinc-800 dark:hover:bg-white transition-colors cursor-pointer"
          >
            Close Report
          </button>
        </div>
      </div>
    </Modal>
  );
};
