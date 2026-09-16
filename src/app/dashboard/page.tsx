'use client';

import React from 'react';
import Link from 'next/link';
import { useDemoContext } from '../../context/DemoContext';
import { Card } from '../../components/ui/Card';
import { Badge } from '../../components/ui/Badge';
import {
  Mail,
  Globe,
  FileCheck2,
  AlertTriangle,
  ArrowRight,
  Sparkles,
  Zap,
  Activity as ActivityIcon,
  CheckCircle2,
} from 'lucide-react';

export default function DashboardPage() {
  const { stats, emails, alerts, activities, setIsQuickScanOpen } = useDemoContext();

  const activeAlerts = alerts.filter((a) => a.status === 'active');
  const recentEmails = emails.slice(0, 4);
  const recentActivities = activities.slice(0, 5);

  return (
    <div className="space-y-6">
      {/* Top Banner Notice */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900/60 p-4 backdrop-blur-sm shadow-xs dark:shadow-none">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-zinc-300 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">
            <Sparkles className="h-4 w-4 text-amber-500 dark:text-zinc-200" />
          </div>
          <div>
            <h2 className="text-xs font-semibold text-zinc-900 dark:text-zinc-200">SentinelAI Small Business Guard</h2>
            <p className="text-[11px] text-zinc-600 dark:text-zinc-400">
              Interactive frontend prototype mode. All risk scores and threat telemetry use local simulated demo data.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Link
            href="/emails"
            className="flex items-center gap-1.5 rounded-lg border border-zinc-300 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800 px-3 py-1.5 text-xs font-semibold text-zinc-900 dark:text-zinc-100 hover:bg-zinc-200 dark:hover:bg-zinc-700 transition-colors shadow-xs"
          >
            <Mail className="h-3.5 w-3.5 text-red-500 dark:text-red-400" />
            <span>Open Email Security Demo</span>
          </Link>
          <button
            onClick={() => setIsQuickScanOpen(true)}
            className="flex items-center gap-1.5 rounded-lg bg-zinc-900 dark:bg-zinc-100 px-3 py-1.5 text-xs font-semibold text-zinc-100 dark:text-zinc-900 hover:bg-zinc-800 dark:hover:bg-white transition-colors cursor-pointer"
          >
            <Zap className="h-3.5 w-3.5" />
            Quick Scan
          </button>
        </div>
      </div>

      {/* Top Stat Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Overall Risk Score */}
        <Card className="flex flex-col justify-between">
          <div className="flex items-start justify-between">
            <span className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Overall Security Score</span>
            <div className="rounded-md border border-emerald-300 dark:border-emerald-900/50 bg-emerald-50 dark:bg-emerald-950/40 p-1.5 text-emerald-600 dark:text-emerald-400">
              <CheckCircle2 className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-4">
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold tracking-tight text-zinc-900 dark:text-zinc-100">
                {stats.riskScore}
              </span>
              <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400">/ 100</span>
              <span className="ml-auto rounded-full bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-200 dark:border-emerald-900/60 px-2 py-0.5 text-[10px] font-semibold text-emerald-700 dark:text-emerald-400">
                {stats.scoreGrade} Posture
              </span>
            </div>
            <div className="mt-2 h-1.5 w-full rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden">
              <div
                className="h-full rounded-full bg-emerald-500 dark:bg-emerald-400"
                style={{ width: `${stats.riskScore}%` }}
              />
            </div>
          </div>
        </Card>

        {/* Metric 2: Emails Analyzed */}
        <Card className="flex flex-col justify-between">
          <div className="flex items-start justify-between">
            <span className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Emails Monitored</span>
            <div className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-800/80 p-1.5 text-zinc-600 dark:text-zinc-400">
              <Mail className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-extrabold tracking-tight text-zinc-900 dark:text-zinc-100">
              {stats.emailsAnalyzed.toLocaleString()}
            </div>
            <p className="mt-1 text-[11px] text-zinc-600 dark:text-zinc-400 flex items-center gap-1">
              <span className="text-red-600 dark:text-red-400 font-semibold">{stats.threatsBlocked} threats</span> blocked this month
            </p>
          </div>
        </Card>

        {/* Metric 3: Scanned URLs & Docs */}
        <Card className="flex flex-col justify-between">
          <div className="flex items-start justify-between">
            <span className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Scanned Links & Files</span>
            <div className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-800/80 p-1.5 text-zinc-600 dark:text-zinc-400">
              <Globe className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-4">
            <div className="text-3xl font-extrabold tracking-tight text-zinc-900 dark:text-zinc-100">
              {(stats.urlsScanned + stats.documentsChecked).toLocaleString()}
            </div>
            <p className="mt-1 text-[11px] text-zinc-600 dark:text-zinc-400">
              {stats.urlsScanned} URLs • {stats.documentsChecked} Files
            </p>
          </div>
        </Card>

        {/* Metric 4: Active Alerts */}
        <Card className="flex flex-col justify-between">
          <div className="flex items-start justify-between">
            <span className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Active Security Alerts</span>
            <div className="rounded-md border border-amber-300 dark:border-amber-900/50 bg-amber-50 dark:bg-amber-950/40 p-1.5 text-amber-600 dark:text-amber-400">
              <AlertTriangle className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-4">
            <div className="flex items-baseline justify-between">
              <span className="text-3xl font-extrabold tracking-tight text-zinc-900 dark:text-zinc-100">
                {activeAlerts.length}
              </span>
              <Link
                href="/alerts"
                className="text-xs text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-200 flex items-center gap-1 font-medium"
              >
                View all <ArrowRight className="h-3 w-3" />
              </Link>
            </div>
            <p className="mt-1 text-[11px] text-zinc-600 dark:text-zinc-400">
              {activeAlerts.filter((a) => a.severity === 'critical').length} critical risk needing review
            </p>
          </div>
        </Card>
      </div>

      {/* Main Grid: Risk Breakdown Card + Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Score Breakdown Card */}
        <Card className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800/80 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Security Risk Breakdown</h3>
              <p className="text-xs text-zinc-600 dark:text-zinc-400">Real-time evaluation across 4 defense pillars</p>
            </div>
            <Badge level="safe">Posture: Optimal</Badge>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
            {/* Pillar 1 */}
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800/80 bg-zinc-50 dark:bg-zinc-950/60 p-3.5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-zinc-800 dark:text-zinc-300">Phishing Defense</span>
                <span className="text-xs font-bold text-emerald-600 dark:text-emerald-400">{stats.phishingDefenseScore}%</span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden">
                <div className="h-full bg-emerald-500 dark:bg-emerald-400 rounded-full" style={{ width: `${stats.phishingDefenseScore}%` }} />
              </div>
              <p className="mt-2 text-[11px] text-zinc-600 dark:text-zinc-400">Inbound email verification and header checks active.</p>
            </div>

            {/* Pillar 2 */}
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800/80 bg-zinc-50 dark:bg-zinc-950/60 p-3.5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-zinc-800 dark:text-zinc-300">URL Reputation</span>
                <span className="text-xs font-bold text-emerald-600 dark:text-emerald-400">{stats.urlReputationScore}%</span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden">
                <div className="h-full bg-emerald-500 dark:bg-emerald-400 rounded-full" style={{ width: `${stats.urlReputationScore}%` }} />
              </div>
              <p className="mt-2 text-[11px] text-zinc-600 dark:text-zinc-400">Browser extension & DNS resolver guard active.</p>
            </div>

            {/* Pillar 3 */}
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800/80 bg-zinc-50 dark:bg-zinc-950/60 p-3.5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-zinc-800 dark:text-zinc-300">Document Safety</span>
                <span className="text-xs font-bold text-emerald-600 dark:text-emerald-400">{stats.documentSafetyScore}%</span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden">
                <div className="h-full bg-emerald-500 dark:bg-emerald-400 rounded-full" style={{ width: `${stats.documentSafetyScore}%` }} />
              </div>
              <p className="mt-2 text-[11px] text-zinc-600 dark:text-zinc-400">VBA Macro stripping and trojan detection enabled.</p>
            </div>

            {/* Pillar 4 */}
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800/80 bg-zinc-50 dark:bg-zinc-950/60 p-3.5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-zinc-800 dark:text-zinc-300">Employee Awareness</span>
                <span className="text-xs font-bold text-amber-600 dark:text-amber-400">{stats.employeeAwarenessScore}%</span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden">
                <div className="h-full bg-amber-500 dark:bg-amber-400 rounded-full" style={{ width: `${stats.employeeAwarenessScore}%` }} />
              </div>
              <p className="mt-2 text-[11px] text-zinc-600 dark:text-zinc-400">2 employees require quarterly phishing refresher training.</p>
            </div>
          </div>

          <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-950/80 p-3 flex items-center justify-between text-xs">
            <span className="text-zinc-800 dark:text-zinc-300 font-medium">AI Recommendation: Enforce mandatory 2FA on 3 staff emails.</span>
            <Link href="/settings" className="text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100 font-semibold shrink-0 ml-2">
              Fix in Settings →
            </Link>
          </div>
        </Card>

        {/* Quick Actions Card */}
        <Card className="flex flex-col justify-between space-y-4">
          <div className="border-b border-zinc-200 dark:border-zinc-800/80 pb-3">
            <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Quick Security Launchers</h3>
            <p className="text-xs text-zinc-600 dark:text-zinc-400">Execute instant threat checks</p>
          </div>

          <div className="space-y-2.5 flex-1">
            <button
              onClick={() => setIsQuickScanOpen(true)}
              className="flex w-full items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950/60 p-3 text-left hover:border-zinc-300 dark:hover:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-900 transition-colors cursor-pointer"
            >
              <div className="flex items-center gap-3">
                <div className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-2 text-zinc-700 dark:text-zinc-300">
                  <Globe className="h-4 w-4" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-900 dark:text-zinc-200">Scan Suspicious Link</p>
                  <p className="text-[10px] text-zinc-500 dark:text-zinc-400">Check domain age & SSL</p>
                </div>
              </div>
              <ArrowRight className="h-3.5 w-3.5 text-zinc-400 dark:text-zinc-500" />
            </button>

            <button
              onClick={() => setIsQuickScanOpen(true)}
              className="flex w-full items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950/60 p-3 text-left hover:border-zinc-300 dark:hover:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-900 transition-colors cursor-pointer"
            >
              <div className="flex items-center gap-3">
                <div className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-2 text-zinc-700 dark:text-zinc-300">
                  <FileCheck2 className="h-4 w-4" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-900 dark:text-zinc-200">Analyze Document</p>
                  <p className="text-[10px] text-zinc-500 dark:text-zinc-400">Inspect macros & executables</p>
                </div>
              </div>
              <ArrowRight className="h-3.5 w-3.5 text-zinc-400 dark:text-zinc-500" />
            </button>

            <Link
              href="/emails"
              className="flex w-full items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950/60 p-3 text-left hover:border-zinc-300 dark:hover:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-900 transition-colors"
            >
              <div className="flex items-center gap-3">
                <div className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-2 text-zinc-700 dark:text-zinc-300">
                  <Mail className="h-4 w-4" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-900 dark:text-zinc-200">Inspect Flagged Emails</p>
                  <p className="text-[10px] text-zinc-500 dark:text-zinc-400">Review phishing headers</p>
                </div>
              </div>
              <ArrowRight className="h-3.5 w-3.5 text-zinc-400 dark:text-zinc-500" />
            </Link>
          </div>
        </Card>
      </div>

      {/* Grid: Recent Emails + Active Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Email Checks */}
        <Card className="space-y-4">
          <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800/80 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Recent Email Threat Checks</h3>
              <p className="text-xs text-zinc-600 dark:text-zinc-400">Inbound mail analyzed by SentinelAI</p>
            </div>
            <Link href="/emails" className="text-xs text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-200 font-medium">
              View all →
            </Link>
          </div>

          <div className="space-y-2">
            {recentEmails.map((email) => (
              <div
                key={email.id}
                className="flex items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800/60 bg-zinc-50 dark:bg-zinc-950/40 p-3 hover:border-zinc-300 dark:hover:border-zinc-700 transition-colors"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="h-8 w-8 rounded-full bg-zinc-100 dark:bg-zinc-800 border border-zinc-300 dark:border-zinc-700 flex items-center justify-center text-xs font-bold text-zinc-700 dark:text-zinc-300 shrink-0">
                    {email.sender.charAt(0)}
                  </div>
                  <div className="truncate">
                    <div className="flex items-center gap-2">
                      <p className="truncate text-xs font-semibold text-zinc-900 dark:text-zinc-200">{email.subject}</p>
                    </div>
                    <p className="truncate text-[11px] text-zinc-500 dark:text-zinc-400">{email.senderEmail}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0 ml-3">
                  <Badge level={email.riskLevel}>{email.riskLevel}</Badge>
                  <span className="text-[10px] text-zinc-500">{email.timestamp}</span>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Active Security Alerts */}
        <Card className="space-y-4">
          <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800/80 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Active Security Alerts</h3>
              <p className="text-xs text-zinc-600 dark:text-zinc-400">Requires review or mitigation</p>
            </div>
            <Link href="/alerts" className="text-xs text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-200 font-medium">
              View all ({alerts.length}) →
            </Link>
          </div>

          <div className="space-y-2">
            {activeAlerts.length > 0 ? (
              activeAlerts.map((alert) => (
                <div
                  key={alert.id}
                  className="rounded-lg border border-zinc-200 dark:border-zinc-800/80 bg-zinc-50 dark:bg-zinc-950/50 p-3 flex items-start justify-between gap-3"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <Badge level={alert.severity}>{alert.severity}</Badge>
                      <h4 className="text-xs font-semibold text-zinc-900 dark:text-zinc-200">{alert.title}</h4>
                    </div>
                    <p className="text-[11px] text-zinc-600 dark:text-zinc-400 line-clamp-1">{alert.description}</p>
                    <p className="text-[10px] text-zinc-500">Affected: {alert.affectedEmployee}</p>
                  </div>
                  <Link
                    href="/alerts"
                    className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-2 py-1 text-[11px] font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-100 shrink-0"
                  >
                    Inspect
                  </Link>
                </div>
              ))
            ) : (
              <div className="py-8 text-center text-xs text-zinc-500">
                <CheckCircle2 className="h-6 w-6 text-emerald-500 dark:text-emerald-400 mx-auto mb-2" />
                No active security alerts. All systems clean.
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Security Activity Timeline */}
      <Card className="space-y-4">
        <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800/80 pb-3">
          <div className="flex items-center gap-2">
            <ActivityIcon className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Live Security Activity Log</h3>
          </div>
          <Link href="/activity" className="text-xs text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-200 font-medium">
            Full Audit Log →
          </Link>
        </div>

        <div className="space-y-3">
          {recentActivities.map((act) => (
            <div
              key={act.id}
              className="flex items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800/50 bg-zinc-50 dark:bg-zinc-950/30 px-3.5 py-2.5 text-xs"
            >
              <div className="flex items-center gap-3">
                <div className="h-7 w-7 rounded-full bg-zinc-100 dark:bg-zinc-800 border border-zinc-300 dark:border-zinc-700 flex items-center justify-center text-xs font-medium text-zinc-700 dark:text-zinc-300">
                  {act.employeeName.charAt(0)}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-zinc-900 dark:text-zinc-200">{act.employeeName}</span>
                    <span className="text-zinc-400">•</span>
                    <span className="text-zinc-600 dark:text-zinc-400">{act.title}</span>
                  </div>
                  <p className="text-[11px] text-zinc-500">{act.description}</p>
                </div>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <Badge level={act.severity}>{act.severity}</Badge>
                <span className="text-[10px] text-zinc-500">{act.timestamp}</span>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
