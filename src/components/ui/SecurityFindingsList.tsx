'use client';

import React, { useState, useMemo } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronUp,
  ShieldAlert,
  ArrowRight,
  Code2,
  Filter,
  CheckCircle,
  AlertCircle,
  ListChecks,
} from 'lucide-react';
import { DocumentChecksSummary } from '../../types';

export type FindingSeverity = 'critical' | 'high' | 'warning' | 'info';

export interface SecurityFindingItem {
  id: string;
  severity: FindingSeverity;
  title: string;
  detected: string; // What was detected
  whyItMatters: string; // Why it matters
  evidence: string | string[];
  affectedTarget?: string; // URL, parameter, file part, page
  detectionMethod?: string;
  recommendedAction: string;
  technicalDetails?: Record<string, unknown> | object | string;
  category?: string;
  description?: string;
  impact?: string;
}

interface SecurityFindingsListProps {
  findings: SecurityFindingItem[];
  title?: string;
  subtitle?: string;
  checksSummary?: DocumentChecksSummary;
}

export const SecurityFindingsList: React.FC<SecurityFindingsListProps> = ({
  findings,
  title = 'What We Found',
  subtitle,
  checksSummary,
}) => {
  const [activeFilter, setActiveFilter] = useState<FindingSeverity | 'all'>('all');
  const [expandedDetails, setExpandedDetails] = useState<Record<string, boolean>>({});
  const [showChecksDrawer, setShowChecksDrawer] = useState(false);

  // Compute counts for interactive filtering
  const counts = useMemo(() => {
    return {
      all: findings.length,
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
      warning: findings.filter((f) => f.severity === 'warning').length,
      info: findings.filter((f) => f.severity === 'info').length,
    };
  }, [findings]);

  // Filtered findings list
  const filteredFindings = useMemo(() => {
    if (activeFilter === 'all') return findings;
    return findings.filter((f) => f.severity === activeFilter);
  }, [findings, activeFilter]);

  const resolvedSubtitle = useMemo(() => {
    if (subtitle) return subtitle;
    if (checksSummary) {
      const parts = [`${checksSummary.completed} check${checksSummary.completed === 1 ? '' : 's'} completed`];
      if (checksSummary.skipped > 0) parts.push(`${checksSummary.skipped} skipped`);
      if (checksSummary.unavailable > 0) parts.push(`${checksSummary.unavailable} unavailable`);
      if (checksSummary.failed > 0) parts.push(`${checksSummary.failed} failed`);
      return `Analysis status: ${parts.join(', ')}.`;
    }
    return 'Issues identified across static parsing, threat feeds, and structural heuristics.';
  }, [subtitle, checksSummary]);

  const toggleTechnicalEvidence = (id: string) => {
    setExpandedDetails((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const getSeverityBadge = (sev: FindingSeverity) => {
    switch (sev) {
      case 'critical':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-md border border-red-300 dark:border-red-900/60 bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300 px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider">
            <AlertOctagon className="h-3.5 w-3.5 text-red-600 dark:text-red-400" />
            Critical
          </span>
        );
      case 'high':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-md border border-orange-300 dark:border-orange-900/60 bg-orange-100 dark:bg-orange-950 text-orange-800 dark:text-orange-300 px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider">
            <ShieldAlert className="h-3.5 w-3.5 text-orange-600 dark:text-orange-400" />
            High Risk
          </span>
        );
      case 'warning':
        return (
          <span className="inline-flex items-center gap-1.5 rounded-md border border-amber-300 dark:border-amber-900/60 bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider">
            <AlertTriangle className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
            Warning
          </span>
        );
      case 'info':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 rounded-md border border-zinc-300 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider">
            <Info className="h-3.5 w-3.5 text-zinc-500" />
            Informational
          </span>
        );
    }
  };

  const getCardBorder = (sev: FindingSeverity) => {
    switch (sev) {
      case 'critical':
        return 'border-l-4 border-l-red-500 border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900';
      case 'high':
        return 'border-l-4 border-l-orange-500 border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900';
      case 'warning':
        return 'border-l-4 border-l-amber-500 border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900';
      case 'info':
      default:
        return 'border-l-4 border-l-zinc-400 border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900';
    }
  };

  return (
    <div className="space-y-4" id="security-findings-section">
      {/* Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-200 dark:border-zinc-800 pb-3">
        <div>
          <h3 className="text-base font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
            <AlertOctagon className="h-4.5 w-4.5 text-zinc-700 dark:text-zinc-300" />
            <span>{title}</span>
            <span className="rounded-full border border-zinc-200 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-800 px-2 py-0.5 text-xs font-mono font-semibold text-zinc-700 dark:text-zinc-300">
              {findings.length}
            </span>
          </h3>
          <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">{resolvedSubtitle}</p>
        </div>

        {/* Checks Drawer Toggle & Severity Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          {checksSummary && checksSummary.total_checks > 0 && (
            <button
              onClick={() => setShowChecksDrawer((prev) => !prev)}
              className={`flex items-center gap-1 rounded-md px-2.5 py-1 text-xs font-semibold border transition-colors mr-1 cursor-pointer ${
                showChecksDrawer
                  ? 'border-zinc-900 bg-zinc-900 text-white dark:border-zinc-100 dark:bg-zinc-100 dark:text-zinc-900'
                  : 'border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800'
              }`}
            >
              <ListChecks className="h-3.5 w-3.5" />
              <span>Checks ({checksSummary.completed}/{checksSummary.total_checks})</span>
              {showChecksDrawer ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            </button>
          )}

          <span className="text-[11px] font-semibold text-zinc-500 uppercase tracking-wider mr-1 flex items-center gap-1">
            <Filter className="h-3 w-3" /> Filter:
          </span>

          <button
            onClick={() => setActiveFilter('all')}
            className={`rounded-md px-2.5 py-1 font-semibold transition-colors cursor-pointer ${
              activeFilter === 'all'
                ? 'bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900 shadow-xs'
                : 'border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800'
            }`}
          >
            All ({counts.all})
          </button>

          <button
            onClick={() => setActiveFilter('critical')}
            className={`rounded-md px-2.5 py-1 font-semibold transition-colors cursor-pointer ${
              activeFilter === 'critical'
                ? 'bg-red-600 text-white shadow-xs'
                : 'border border-red-200 dark:border-red-900/50 bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300 hover:bg-red-100'
            }`}
          >
            Critical ({counts.critical})
          </button>

          <button
            onClick={() => setActiveFilter('high')}
            className={`rounded-md px-2.5 py-1 font-semibold transition-colors cursor-pointer ${
              activeFilter === 'high'
                ? 'bg-orange-600 text-white shadow-xs'
                : 'border border-orange-200 dark:border-orange-900/50 bg-orange-50 dark:bg-orange-950/30 text-orange-700 dark:text-orange-300 hover:bg-orange-100'
            }`}
          >
            High ({counts.high})
          </button>

          <button
            onClick={() => setActiveFilter('warning')}
            className={`rounded-md px-2.5 py-1 font-semibold transition-colors cursor-pointer ${
              activeFilter === 'warning'
                ? 'bg-amber-600 text-white shadow-xs'
                : 'border border-amber-200 dark:border-amber-900/50 bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300 hover:bg-amber-100'
            }`}
          >
            Warnings ({counts.warning})
          </button>

          <button
            onClick={() => setActiveFilter('info')}
            className={`rounded-md px-2.5 py-1 font-semibold transition-colors cursor-pointer ${
              activeFilter === 'info'
                ? 'bg-zinc-700 text-white shadow-xs'
                : 'border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100'
            }`}
          >
            Info ({counts.info})
          </button>
        </div>
      </div>

      {/* Checks Detail Drawer */}
      {showChecksDrawer && checksSummary && (
        <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-4 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-200 dark:border-zinc-800/80 pb-2">
            <div className="flex items-center gap-2">
              <ListChecks className="h-4 w-4 text-zinc-600 dark:text-zinc-400" />
              <span className="text-xs font-bold text-zinc-900 dark:text-zinc-100 uppercase tracking-wider">
                Analysis Modules & Checks Breakdown ({checksSummary.total_checks} Total)
              </span>
            </div>
            <div className="flex items-center gap-2 text-[11px] font-mono">
              <span className="text-emerald-600 dark:text-emerald-400 font-semibold">{checksSummary.completed} completed</span>
              <span>•</span>
              <span className="text-zinc-500">{checksSummary.skipped} skipped</span>
              {checksSummary.unavailable > 0 && (
                <>
                  <span>•</span>
                  <span className="text-amber-600 dark:text-amber-400 font-semibold">{checksSummary.unavailable} unavailable</span>
                </>
              )}
              {checksSummary.failed > 0 && (
                <>
                  <span>•</span>
                  <span className="text-red-600 dark:text-red-400 font-semibold">{checksSummary.failed} failed</span>
                </>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
            {checksSummary.checks.map((check) => (
              <div
                key={check.id}
                className="rounded-lg border border-zinc-200 dark:border-zinc-800/80 bg-white dark:bg-zinc-900 p-2.5 space-y-1"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-zinc-900 dark:text-zinc-100 truncate">{check.name}</span>
                  <span
                    className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                      check.status === 'completed'
                        ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/40'
                        : check.status === 'skipped'
                        ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-700'
                        : check.status === 'unavailable'
                        ? 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-900/40'
                        : 'bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-900/40'
                    }`}
                  >
                    {check.status}
                  </span>
                </div>
                <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-snug">{check.description}</p>
                {check.findings_count > 0 && (
                  <p className="text-[10px] font-mono text-amber-600 dark:text-amber-400">
                    Flagged: {check.findings_count} threat indicator(s)
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Partial Scan Warning Banner (when some checks were unavailable or failed, but findings exist) */}
      {checksSummary && (checksSummary.failed > 0 || checksSummary.unavailable > 0) && filteredFindings.length > 0 && (
        <div className="rounded-xl border border-amber-200 dark:border-amber-900/50 bg-amber-50/50 dark:bg-amber-950/20 p-3.5 flex items-start gap-3">
          <AlertTriangle className="h-4.5 w-4.5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1 text-xs text-zinc-800 dark:text-zinc-200">
            <div className="flex items-center gap-2">
              <span className="font-bold text-amber-900 dark:text-amber-200">Partial scan assessment</span>
              <span className="text-[10px] font-semibold uppercase tracking-wider text-amber-700 dark:text-amber-400">
                ({checksSummary.unavailable + checksSummary.failed} check(s) could not run)
              </span>
            </div>
            <p className="text-[11px] text-zinc-600 dark:text-zinc-400">
              {checksSummary.checks
                .filter((c) => c.status === 'unavailable' || c.status === 'failed')
                .map((c) => `${c.name}: ${c.description}`)
                .join(' • ')}
            </p>
          </div>
        </div>
      )}

      {/* Findings Rows / Empty States */}
      {filteredFindings.length === 0 ? (
        activeFilter !== 'all' ? (
          /* Severity filter active with no matching items */
          <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 p-8 text-center bg-zinc-50 dark:bg-zinc-950 space-y-2">
            <Info className="h-6 w-6 text-zinc-400 mx-auto" />
            <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-100">
              No {activeFilter.toUpperCase()} severity findings detected
            </p>
            <p className="text-[11px] text-zinc-500 max-w-sm mx-auto">
              None of the {findings.length} identified findings match this filter.
            </p>
            <button
              onClick={() => setActiveFilter('all')}
              className="mt-2 text-xs font-semibold text-zinc-700 dark:text-zinc-300 underline cursor-pointer"
            >
              Reset filter to view all findings ({findings.length})
            </button>
          </div>
        ) : checksSummary && checksSummary.completed === 0 ? (
          /* Requirement 8: If zero checks ran, display neutral warning */
          <div className="rounded-xl border border-zinc-300 dark:border-zinc-700 p-8 text-center bg-zinc-50 dark:bg-zinc-950 space-y-2">
            <AlertCircle className="h-8 w-8 text-zinc-500 dark:text-zinc-400 mx-auto mb-2" />
            <p className="text-sm font-bold text-zinc-900 dark:text-zinc-100">
              No security checks were completed. This document has not been assessed.
            </p>
            <p className="text-xs text-zinc-500 max-w-md mx-auto">
              No inspection modules executed on this file. Structural integrity and safety cannot be verified.
            </p>
          </div>
        ) : checksSummary && (checksSummary.failed > 0 || checksSummary.unavailable > 0) ? (
          /* Requirement 9: Partial scan / incomplete checks with 0 findings */
          <div className="rounded-xl border border-amber-300 dark:border-amber-900/60 p-8 text-center bg-amber-50/50 dark:bg-amber-950/20 space-y-3">
            <AlertTriangle className="h-8 w-8 text-amber-500 mx-auto" />
            <div>
              <div className="inline-flex items-center gap-1.5 rounded-full border border-amber-300 dark:border-amber-800 bg-amber-100 dark:bg-amber-950/60 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-amber-800 dark:text-amber-300 mb-1.5">
                Scan Incomplete
              </div>
              <p className="text-sm font-bold text-zinc-900 dark:text-zinc-100">
                Partial scan — Some security checks could not be completed
              </p>
              <p className="text-xs text-zinc-600 dark:text-zinc-400 max-w-md mx-auto mt-1">
                Completed checks found no threats, but {checksSummary.unavailable + checksSummary.failed} check(s) were unavailable or failed.
              </p>
            </div>

            <div className="max-w-md mx-auto text-left rounded-lg border border-amber-200 dark:border-amber-900/40 bg-white/80 dark:bg-zinc-900/80 p-3 text-xs space-y-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-amber-700 dark:text-amber-400">
                Affected Checks:
              </span>
              {checksSummary.checks
                .filter((c) => c.status === 'unavailable' || c.status === 'failed')
                .map((c) => (
                  <div key={c.id} className="text-zinc-700 dark:text-zinc-300 text-[11px]">
                    • <strong>{c.name}:</strong> {c.description}
                  </div>
                ))}
            </div>
          </div>
        ) : (
          /* Requirements 7 & 10: Scan completed successfully with zero threats detected */
          <div className="rounded-xl border border-emerald-200 dark:border-emerald-900/50 p-8 text-center bg-emerald-50/40 dark:bg-emerald-950/20 space-y-3">
            <CheckCircle className="h-8 w-8 text-emerald-500 mx-auto" />
            <div className="space-y-1">
              <p className="text-base font-bold text-zinc-900 dark:text-zinc-100">
                No threats detected by the completed checks.
              </p>
              <p className="text-xs text-zinc-600 dark:text-zinc-400 max-w-md mx-auto">
                {checksSummary
                  ? `All ${checksSummary.completed} applicable security checks completed successfully with no malicious indicators detected.`
                  : 'All completed security checks found no known threats across inspected parameters.'}
              </p>
            </div>

            {/* Limitations disclosure */}
            <div className="max-w-xl mx-auto rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white/80 dark:bg-zinc-900/80 p-3.5 text-left text-xs space-y-1.5">
              <div className="flex items-center gap-1.5 text-zinc-700 dark:text-zinc-300 font-semibold text-[11px] uppercase tracking-wider">
                <Info className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
                <span>Coverage & Limitations Disclosure</span>
              </div>
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
                Completed checks found no known threats. This does not guarantee the target is completely safe. Static inspection cannot guarantee immunity against novel zero-day exploits or runtime memory evasion. No active code was executed.
              </p>
              {checksSummary?.limitations && checksSummary.limitations.length > 0 && (
                <div className="pt-1.5 border-t border-zinc-200/60 dark:border-zinc-800/60 space-y-1 text-[11px] text-zinc-600 dark:text-zinc-400">
                  {checksSummary.limitations.slice(0, 3).map((lim, idx) => (
                    <div key={idx}>• {lim}</div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )
      ) : (
        <div className="space-y-3.5">
          {filteredFindings.map((finding) => {
            const isTechnicalExpanded = expandedDetails[finding.id] || finding.severity === 'critical';

            return (
              <div
                key={finding.id}
                className={`rounded-xl border p-4 sm:p-5 shadow-xs transition-colors space-y-3 ${getCardBorder(
                  finding.severity
                )}`}
              >
                {/* 1. Header: Severity Badge, Title, Detection Method */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-200/70 dark:border-zinc-800/70 pb-3">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    {getSeverityBadge(finding.severity)}
                    <h4 className="text-sm sm:text-base font-bold text-zinc-900 dark:text-zinc-100 font-sans tracking-tight">
                      {finding.title}
                    </h4>
                  </div>
                  {finding.detectionMethod && (
                    <span className="text-[11px] font-mono text-zinc-500 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-800 px-2 py-0.5 rounded shrink-0">
                      Method: {finding.detectionMethod}
                    </span>
                  )}
                </div>

                {/* 2 & 3. What Was Detected & Why It Matters */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 space-y-1">
                    <span className="text-[10px] uppercase font-bold text-zinc-500 dark:text-zinc-400 tracking-wider">
                      What was detected
                    </span>
                    <p className="text-zinc-800 dark:text-zinc-200 leading-relaxed font-medium">
                      {finding.detected}
                    </p>
                  </div>

                  <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 space-y-1">
                    <span className="text-[10px] uppercase font-bold text-zinc-500 dark:text-zinc-400 tracking-wider">
                      Why it matters
                    </span>
                    <p className="text-zinc-700 dark:text-zinc-300 leading-relaxed font-medium">
                      {finding.whyItMatters}
                    </p>
                  </div>
                </div>

                {/* 4. Supporting Evidence Snippets */}
                {finding.evidence && (
                  <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 text-xs space-y-1">
                    <span className="text-[10px] uppercase font-bold text-zinc-500 dark:text-zinc-400 tracking-wider">
                      Supporting Evidence
                    </span>
                    {Array.isArray(finding.evidence) ? (
                      <ul className="list-disc list-inside space-y-0.5 font-mono text-[11px] text-zinc-800 dark:text-zinc-200">
                        {finding.evidence.map((ev, idx) => (
                          <li key={idx} className="break-all">
                            {ev}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="font-mono text-[11px] text-zinc-800 dark:text-zinc-200 break-all">
                        {finding.evidence}
                      </p>
                    )}
                  </div>
                )}

                {/* 5. Recommended Action */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-1">
                  <div className="flex items-center gap-1.5 text-xs text-zinc-700 dark:text-zinc-300">
                    <ArrowRight className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
                    <span>
                      <strong>Recommended Action:</strong> {finding.recommendedAction}
                    </span>
                  </div>

                  {finding.technicalDetails && (
                    <button
                      onClick={() => toggleTechnicalEvidence(finding.id)}
                      className="inline-flex items-center gap-1 text-[11px] font-semibold text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-200 underline shrink-0 cursor-pointer"
                    >
                      <Code2 className="h-3 w-3" />
                      <span>{isTechnicalExpanded ? 'Hide technical details' : 'View technical details'}</span>
                      {isTechnicalExpanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                    </button>
                  )}
                </div>

                {/* Expandable Technical Details */}
                {finding.technicalDetails && isTechnicalExpanded && (
                  <div className="mt-2 pt-2 border-t border-zinc-200 dark:border-zinc-800">
                    <pre className="p-3 rounded-lg bg-zinc-900 text-zinc-200 font-mono text-[11px] overflow-x-auto max-h-48 leading-relaxed">
                      {typeof finding.technicalDetails === 'string'
                        ? finding.technicalDetails
                        : JSON.stringify(finding.technicalDetails, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
