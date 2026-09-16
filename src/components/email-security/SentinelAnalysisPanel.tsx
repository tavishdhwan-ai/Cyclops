'use client';

import React, { useState } from 'react';
import { SentinelEmailFinding } from '../../types';
import { Badge } from '../ui/Badge';
import {
  ShieldAlert,
  AlertTriangle,
  UserX,
  Link2Off,
  KeyRound,
  Clock,
  UserCheck,
  ChevronDown,
  ChevronUp,
  CheckCircle,
  RotateCw,
  FileCheck,
} from 'lucide-react';

interface SentinelAnalysisPanelProps {
  isScanning: boolean;
  scanProgress: number;
  scanStep: string;
  onRescan: () => void;
  onOpenReport: () => void;
  reviewStatus: 'pending' | 'reviewed';
  onMarkReviewed: () => void;
}

export const mockFindings: SentinelEmailFinding[] = [
  {
    id: 'f-1',
    title: 'Sender impersonation',
    severity: 'High',
    explanation: 'The sender claims to represent Microsoft but uses an unrelated domain.',
    iconName: 'UserX',
  },
  {
    id: 'f-2',
    title: 'Suspicious link',
    severity: 'High',
    explanation: 'The verification link does not match the claimed company domain.',
    iconName: 'Link2Off',
  },
  {
    id: 'f-3',
    title: 'Credential request',
    severity: 'Critical',
    explanation: 'The email asks the recipient to verify or provide a password.',
    iconName: 'KeyRound',
  },
  {
    id: 'f-4',
    title: 'Urgency language',
    severity: 'Medium',
    explanation: 'The message uses fear and a short deadline to pressure the user.',
    iconName: 'Clock',
  },
  {
    id: 'f-5',
    title: 'Possible account takeover attempt',
    severity: 'High',
    explanation: 'The message encourages the user to enter account information through an email link.',
    iconName: 'UserCheck',
  },
];

export const SentinelAnalysisPanel: React.FC<SentinelAnalysisPanelProps> = ({
  isScanning,
  scanProgress,
  scanStep,
  onRescan,
  onOpenReport,
  reviewStatus,
  onMarkReviewed,
}) => {
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  const getFindingIcon = (iconName?: string) => {
    switch (iconName) {
      case 'UserX':
        return <UserX className="h-4 w-4 text-red-500 dark:text-red-400 shrink-0" />;
      case 'Link2Off':
        return <Link2Off className="h-4 w-4 text-red-500 dark:text-red-400 shrink-0" />;
      case 'KeyRound':
        return <KeyRound className="h-4 w-4 text-purple-600 dark:text-purple-400 shrink-0" />;
      case 'Clock':
        return <Clock className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0" />;
      case 'UserCheck':
        return <UserCheck className="h-4 w-4 text-red-500 dark:text-red-400 shrink-0" />;
      default:
        return <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0" />;
    }
  };

  const toggleFindingExpand = (id: string) => {
    setExpandedFindingId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900/60 p-5 md:p-6 shadow-sm dark:shadow-none backdrop-blur-sm space-y-5">
      {/* SentinelAI Panel Title */}
      <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800/80 pb-3">
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-md border border-zinc-300 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100">
            <ShieldAlert className="h-4 w-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 tracking-tight">SentinelAI Threat Intelligence</h2>
            <p className="text-[11px] text-zinc-500 dark:text-zinc-400">Grammarly-like Email Guard</p>
          </div>
        </div>
        <span className="rounded-full border border-zinc-200 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-950 px-2.5 py-0.5 text-[10px] font-medium text-zinc-600 dark:text-zinc-400">
          Simulated demo analysis
        </span>
      </div>

      {/* SCANNING STATE vs COMPLETED STATE */}
      {isScanning ? (
        <div className="py-8 px-4 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950/80 space-y-4 text-center">
          <div className="flex justify-center">
            <div className="relative flex items-center justify-center h-12 w-12 rounded-full border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900">
              <RotateCw className="h-6 w-6 text-zinc-700 dark:text-zinc-200 animate-spin" />
            </div>
          </div>
          <div className="space-y-1">
            <p className="text-xs font-bold text-zinc-900 dark:text-zinc-100">Scanning email and attachments…</p>
            <p className="text-[11px] text-zinc-500 dark:text-zinc-400">{scanStep}</p>
          </div>
          {/* Restrained Progress Bar */}
          <div className="w-full max-w-xs mx-auto space-y-1">
            <div className="h-1.5 w-full bg-zinc-200 dark:bg-zinc-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-zinc-800 dark:bg-zinc-200 transition-all duration-200 ease-out"
                style={{ width: `${scanProgress}%` }}
              />
            </div>
            <p className="text-[10px] font-mono text-zinc-500">{scanProgress}% completed</p>
          </div>
        </div>
      ) : (
        <>
          {/* Status Header */}
          <div className="flex items-center justify-between bg-zinc-50 dark:bg-zinc-950/80 border border-zinc-200 dark:border-zinc-800 rounded-lg px-3.5 py-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-emerald-600 dark:text-emerald-400">
              <CheckCircle className="h-4 w-4" />
              <span>Analysis complete</span>
            </div>
            <span className="text-[10px] text-zinc-500 dark:text-zinc-400 font-mono">
              Status: {reviewStatus === 'reviewed' ? 'Reviewed' : 'Action Required'}
            </span>
          </div>

          {/* OVERALL EMAIL THREAT SCORE */}
          <div className="rounded-xl border border-red-200 dark:border-red-900/40 bg-red-50 dark:bg-red-950/20 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-[10px] font-bold uppercase tracking-wider text-red-600 dark:text-red-400">
                  Overall Email Threat Score
                </span>
                <div className="flex items-baseline gap-2 mt-0.5">
                  <span className="text-2xl font-extrabold text-zinc-900 dark:text-zinc-100 font-mono">8.7</span>
                  <span className="text-xs text-zinc-500 dark:text-zinc-400 font-mono">/ 10</span>
                </div>
              </div>

              <div className="text-right space-y-1">
                <Badge level="critical" size="md">
                  HIGH RISK
                </Badge>
                <p className="text-[10px] text-zinc-500 dark:text-zinc-400">Phishing Confidence: 94%</p>
              </div>
            </div>

            {/* Risk bar */}
            <div className="space-y-1">
              <div className="flex justify-between text-[10px] text-zinc-500 dark:text-zinc-400">
                <span>0 Low</span>
                <span>5 Med</span>
                <span className="text-red-600 dark:text-red-400 font-semibold">8.7 High Risk</span>
                <span>10 Crit</span>
              </div>
              <div className="h-2 w-full bg-zinc-200 dark:bg-zinc-900 rounded-full overflow-hidden border border-zinc-200 dark:border-zinc-800 relative">
                <div
                  className="h-full bg-linear-to-r from-emerald-500 via-amber-500 to-red-500 transition-all duration-500"
                  style={{ width: '87%' }}
                />
              </div>
            </div>

            {/* Explanation */}
            <p className="text-xs text-zinc-700 dark:text-zinc-300 leading-relaxed pt-1">
              This email contains multiple phishing indicators, including sender impersonation, urgency language, a credential request, and a suspicious link.
            </p>

            {/* Disclaimer */}
            <div className="border-t border-red-200 dark:border-red-900/30 pt-2 text-[10px] text-zinc-500 dark:text-zinc-400 flex items-center justify-between">
              <span>Risk estimate — not a guarantee of safety.</span>
              <span className="font-mono">Demo data</span>
            </div>
          </div>

          {/* SENTINELAI FINDINGS SECTION */}
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800 pb-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
                Security Findings ({mockFindings.length})
              </h3>
              <span className="text-[10px] text-zinc-500">Click row to expand details</span>
            </div>

            <div className="space-y-2">
              {mockFindings.map((finding) => {
                const isExpanded = expandedFindingId === finding.id;

                return (
                  <div
                    key={finding.id}
                    onClick={() => toggleFindingExpand(finding.id)}
                    className="hover-card cursor-pointer rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950/70 p-3 transition-all duration-200 hover:border-zinc-300 dark:hover:border-zinc-700"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-start gap-2.5 min-w-0">
                        {getFindingIcon(finding.iconName)}
                        <div>
                          <div className="flex items-center gap-2">
                            <p className="font-semibold text-xs text-zinc-900 dark:text-zinc-200">{finding.title}</p>
                            <Badge level={finding.severity}>{finding.severity}</Badge>
                          </div>
                          <p className="text-[11px] text-zinc-600 dark:text-zinc-400 mt-1 leading-snug">
                            {finding.explanation}
                          </p>
                        </div>
                      </div>

                      <button
                        type="button"
                        className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300 p-0.5 shrink-0"
                        aria-label="Expand finding details"
                      >
                        {isExpanded ? (
                          <ChevronUp className="h-3.5 w-3.5" />
                        ) : (
                          <ChevronDown className="h-3.5 w-3.5" />
                        )}
                      </button>
                    </div>

                    {isExpanded && (
                      <div className="mt-2.5 border-t border-zinc-200 dark:border-zinc-800/80 pt-2 text-[11px] text-zinc-600 dark:text-zinc-400 space-y-1">
                        <p>
                          <strong>Mitigation Action:</strong> SentinelAI recommends blocking external links and reporting domain to tenant admin.
                        </p>
                        <p className="text-[10px] text-zinc-500">
                          Signal ID: {finding.id} • Risk contribution +1.8
                        </p>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* RECOMMENDATION AREA */}
          <div className="space-y-3 pt-2">
            <div className="rounded-xl border border-amber-200 dark:border-amber-900/50 bg-amber-50 dark:bg-amber-950/20 p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-amber-700 dark:text-amber-300">
                <AlertTriangle className="h-4 w-4 text-amber-500 dark:text-amber-400 shrink-0" />
                <span>Security Recommendation</span>
              </div>
              <p className="text-xs text-zinc-800 dark:text-zinc-200 leading-snug font-medium">
                Do not click links, download attachments, or reply until the sender is verified.
              </p>
            </div>

            {/* Action Buttons */}
            <div className="flex flex-col gap-2">
              <button
                onClick={onOpenReport}
                className="w-full flex items-center justify-center gap-2 rounded-lg bg-zinc-900 dark:bg-zinc-100 text-zinc-100 dark:text-zinc-900 py-2 px-3 text-xs font-semibold hover:bg-zinc-800 dark:hover:bg-white transition-colors cursor-pointer"
              >
                <FileCheck className="h-3.5 w-3.5" />
                <span>View Detailed Report</span>
              </button>

              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={onMarkReviewed}
                  className={`flex items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-medium transition-colors cursor-pointer ${
                    reviewStatus === 'reviewed'
                      ? 'border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300'
                      : 'border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-100'
                  }`}
                >
                  <CheckCircle className="h-3.5 w-3.5 text-emerald-500 dark:text-emerald-400" />
                  <span>{reviewStatus === 'reviewed' ? 'Reviewed ✓' : 'Mark as Reviewed'}</span>
                </button>

                <button
                  onClick={onRescan}
                  className="flex items-center justify-center gap-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 px-3 py-2 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors cursor-pointer"
                >
                  <RotateCw className="h-3.5 w-3.5 text-amber-500 dark:text-amber-400" />
                  <span>Rescan Email</span>
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Persistent Disclaimer Label */}
      <div className="border-t border-zinc-200 dark:border-zinc-800/80 pt-3 text-center space-y-0.5">
        <p className="text-[10px] font-semibold text-zinc-500 dark:text-zinc-400">
          Demo data — no real email or attachment was scanned
        </p>
        <p className="text-[10px] text-zinc-400 dark:text-zinc-500">SentinelAI Small Business Cyber Guard Prototype</p>
      </div>
    </div>
  );
};
