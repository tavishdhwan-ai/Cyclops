'use client';

import React from 'react';
import {
  AlertTriangle,
  ShieldCheck,
  AlertOctagon,
  ArrowDown,
  Info,
  Clock,
  Layers,
  CheckCircle2,
} from 'lucide-react';

export type UnifiedVerdict = 'malicious' | 'suspicious' | 'clean' | 'incomplete';

export interface FindingsCounts {
  critical: number;
  high: number;
  warning: number;
  info: number;
  unavailable?: number;
}

interface ScanResultSummaryProps {
  verdict: UnifiedVerdict;
  targetName?: string;
  title?: string;
  targetType?: 'URL' | 'Document' | 'Email' | 'url' | 'document' | 'email';
  timestamp?: string;
  subtitle?: string;
  threatScore?: number; // 0 - 10 scale
  threatScoreMax?: number; // default 10.0 or 100
  summaryExplanation?: string;
  verdictExplanation?: string;
  findingsCounts?: FindingsCounts;
  counts?: FindingsCounts;
  scanStatus?: string;
  onScrollToFindings?: () => void;
  isLiveScan?: boolean;
}

export const ScanResultSummary: React.FC<ScanResultSummaryProps> = ({
  verdict,
  targetName,
  title,
  targetType = 'URL',
  timestamp = '',
  subtitle = '',
  threatScore,
  threatScoreMax = 10.0,
  summaryExplanation,
  verdictExplanation,
  findingsCounts,
  counts,
  scanStatus = 'Full passive scan completed',
  onScrollToFindings,
  isLiveScan = false,
}) => {
  const resolvedTargetName = targetName || title || 'Target';
  const resolvedTargetType = (targetType || 'URL').toUpperCase();
  const resolvedTimestamp = timestamp || subtitle || 'Recently scanned';
  const resolvedExplanation =
    summaryExplanation ||
    verdictExplanation ||
    (verdict === 'malicious'
      ? 'Critical threat indicators detected. The target should be quarantined immediately.'
      : verdict === 'suspicious'
      ? 'Anomalous or suspicious patterns observed. Proceed with caution and verify independently.'
      : verdict === 'clean'
      ? 'Completed checks found no known threats across inspected threat intelligence sources and heuristic rules.'
      : 'Scan could not complete all verification checks. Target integrity cannot be confirmed.');
  const resolvedCounts = findingsCounts || counts || { critical: 0, high: 0, warning: 0, info: 0, unavailable: 0 };
  // Restrained status styling adhering strictly to monochromatic B2B SaaS specs
  const config = {
    malicious: {
      title: 'Malicious',
      subheading: 'High-confidence threat signals identified',
      borderClass: 'border-red-300 dark:border-red-900/60 bg-red-50/60 dark:bg-red-950/30',
      badgeClass: 'border-red-300 dark:border-red-800 bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300',
      iconClass: 'text-red-600 dark:text-red-400 bg-red-100 dark:bg-red-950 border-red-200 dark:border-red-900/50',
      Icon: AlertOctagon,
      scoreColor: 'text-red-600 dark:text-red-400',
    },
    suspicious: {
      title: 'Suspicious',
      subheading: 'Anomalous signals detected; exercise caution',
      borderClass: 'border-amber-300 dark:border-amber-900/60 bg-amber-50/60 dark:bg-amber-950/30',
      badgeClass: 'border-amber-300 dark:border-amber-800 bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300',
      iconClass: 'text-amber-600 dark:text-amber-400 bg-amber-100 dark:bg-amber-950 border-amber-200 dark:border-amber-900/50',
      Icon: AlertTriangle,
      scoreColor: 'text-amber-600 dark:text-amber-400',
    },
    clean: {
      title: 'No threats detected',
      subheading: 'Completed checks found no known threats',
      borderClass: 'border-emerald-300 dark:border-emerald-900/60 bg-emerald-50/60 dark:bg-emerald-950/30',
      badgeClass: 'border-emerald-300 dark:border-emerald-800 bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300',
      iconClass: 'text-emerald-600 dark:text-emerald-400 bg-emerald-100 dark:bg-emerald-950 border-emerald-200 dark:border-emerald-900/50',
      Icon: ShieldCheck,
      scoreColor: 'text-emerald-600 dark:text-emerald-400',
    },
    incomplete: {
      title: 'Scan incomplete',
      subheading: 'Some inspection stages could not be finalized',
      borderClass: 'border-zinc-300 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/50',
      badgeClass: 'border-zinc-300 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300',
      iconClass: 'text-zinc-600 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-800 border-zinc-200 dark:border-zinc-700',
      Icon: Info,
      scoreColor: 'text-zinc-600 dark:text-zinc-400',
    },
  }[verdict];

  const { Icon } = config;
  const totalFindings =
    resolvedCounts.critical + resolvedCounts.high + resolvedCounts.warning + resolvedCounts.info;

  return (
    <div
      role="region"
      aria-label="Scan Result Summary"
      className={`rounded-xl border p-5 sm:p-6 transition-all shadow-xs ${config.borderClass}`}
    >
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        {/* Left Side: Large Status Icon + Clear Verdict */}
        <div className="flex items-start gap-4">
          <div
            className={`h-12 w-12 sm:h-14 sm:w-14 rounded-xl border flex items-center justify-center shrink-0 shadow-xs ${config.iconClass}`}
          >
            <Icon className="h-7 w-7 sm:h-8 sm:w-8" />
          </div>

          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[11px] font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                Overall Verdict
              </span>
              <span
                className={`rounded-md border px-2.5 py-0.5 text-xs font-bold uppercase tracking-wide ${config.badgeClass}`}
              >
                {config.title}
              </span>
              {isLiveScan && (
                <span className="rounded-md border border-emerald-200 dark:border-emerald-800 bg-white dark:bg-zinc-900 px-2 py-0.5 text-[10px] font-semibold text-emerald-700 dark:text-emerald-400">
                  Live Engine
                </span>
              )}
            </div>

            <h2 className="text-xl sm:text-2xl font-black text-zinc-900 dark:text-zinc-100 tracking-tight font-sans">
              {config.title}
            </h2>

            <p className="text-xs sm:text-sm text-zinc-700 dark:text-zinc-300 font-medium max-w-2xl leading-relaxed">
              {resolvedExplanation}
            </p>

            {verdict === 'clean' && (
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400 flex items-center gap-1.5 pt-0.5">
                <Info className="h-3.5 w-3.5 shrink-0" />
                <span>Notice: Completed checks found no known threats. This does not guarantee the target is completely safe.</span>
              </p>
            )}

            <div className="flex flex-wrap items-center gap-4 text-xs text-zinc-500 dark:text-zinc-400 pt-1 font-mono">
              <span className="truncate max-w-md text-zinc-700 dark:text-zinc-300 font-semibold">
                {resolvedTargetType}: {resolvedTargetName}
              </span>
              <span>•</span>
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" /> {resolvedTimestamp}
              </span>
              <span>•</span>
              <span className="flex items-center gap-1">
                <Layers className="h-3 w-3" /> {scanStatus}
              </span>
            </div>
          </div>
        </div>

        {/* Right Side: Threat Index & Action Button */}
        <div className="flex flex-row lg:flex-col items-center lg:items-end justify-between gap-3 shrink-0 pt-3 lg:pt-0 border-t lg:border-t-0 border-zinc-200/60 dark:border-zinc-800/60">
          {threatScore !== undefined && (
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-4 py-2 text-center shadow-xs">
              <span className="text-[10px] font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400 block">
                Threat Index
              </span>
              <span className={`text-xl sm:text-2xl font-black font-mono ${config.scoreColor}`}>
                {threatScore.toFixed(1)} / {threatScoreMax.toFixed(1)}
              </span>
            </div>
          )}

          {onScrollToFindings && (
            <button
              onClick={onScrollToFindings}
              className="flex items-center gap-1.5 rounded-lg bg-zinc-900 dark:bg-zinc-100 hover:bg-zinc-800 dark:hover:bg-zinc-200 px-4 py-2 text-xs font-semibold text-white dark:text-zinc-900 shadow-xs transition-colors shrink-0"
            >
              <span>Review Findings ({totalFindings})</span>
              <ArrowDown className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Findings Breakdown Metric Pills */}
      <div className="mt-5 pt-4 border-t border-zinc-200/80 dark:border-zinc-800/80 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-[11px] font-semibold text-zinc-600 dark:text-zinc-400 uppercase tracking-wider mr-1">
            Findings Breakdown:
          </span>

          <span className="inline-flex items-center gap-1.5 rounded-md border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/40 px-2.5 py-1 text-xs font-bold text-red-700 dark:text-red-300">
            <span className="h-1.5 w-1.5 rounded-full bg-red-500"></span>
            Critical: {resolvedCounts.critical}
          </span>

          <span className="inline-flex items-center gap-1.5 rounded-md border border-orange-200 dark:border-orange-900/60 bg-orange-50 dark:bg-orange-950/40 px-2.5 py-1 text-xs font-semibold text-orange-700 dark:text-orange-300">
            <span className="h-1.5 w-1.5 rounded-full bg-orange-500"></span>
            High: {resolvedCounts.high}
          </span>

          <span className="inline-flex items-center gap-1.5 rounded-md border border-amber-200 dark:border-amber-900/60 bg-amber-50 dark:bg-amber-950/40 px-2.5 py-1 text-xs font-semibold text-amber-700 dark:text-amber-300">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-500"></span>
            Warnings: {resolvedCounts.warning}
          </span>

          <span className="inline-flex items-center gap-1.5 rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-2.5 py-1 text-xs font-medium text-zinc-700 dark:text-zinc-300">
            <span className="h-1.5 w-1.5 rounded-full bg-zinc-400"></span>
            Informational: {resolvedCounts.info}
          </span>

          {resolvedCounts.unavailable !== undefined && resolvedCounts.unavailable > 0 && (
            <span className="inline-flex items-center gap-1.5 rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-800 px-2.5 py-1 text-xs font-medium text-zinc-500 dark:text-zinc-400">
              Unavailable: {resolvedCounts.unavailable}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 text-[11px] text-zinc-500 dark:text-zinc-400">
          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
          <span>Calculated from active inspection response</span>
        </div>
      </div>
    </div>
  );
};
