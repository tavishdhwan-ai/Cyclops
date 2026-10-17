'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useDemoContext } from '../context/DemoContext';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import {
  Globe,
  Mail,
  FileSearch,
  ArrowRight,
  ShieldCheck,
  AlertTriangle,
  AlertOctagon,
  CheckCircle2,
  Clock,
  Sparkles,
  ExternalLink,
  Search,
  ShieldAlert,
  HelpCircle,
  FileText,
} from 'lucide-react';

export default function HomePage() {
  const router = useRouter();
  const { urlScans, docScans, emails, scanUrl } = useDemoContext();
  const [quickUrl, setQuickUrl] = useState('');
  const [isSubmittingUrl, setIsSubmittingUrl] = useState(false);

  // Derive real statistics from actual user session data (no fake stats)
  const totalScans = urlScans.length + docScans.length + emails.length;

  const dangerousCount =
    urlScans.filter((s) => s.verdict === 'malicious').length +
    docScans.filter((d) => d.verdict === 'malicious').length +
    emails.filter((e) => e.riskLevel === 'critical').length;

  const suspiciousCount =
    urlScans.filter((s) => s.verdict === 'suspicious').length +
    docScans.filter((d) => d.verdict === 'suspicious').length +
    emails.filter((e) => e.riskLevel === 'warning').length;

  const cleanCount =
    urlScans.filter((s) => s.verdict === 'clean').length +
    docScans.filter((d) => d.verdict === 'clean').length +
    emails.filter((e) => e.riskLevel === 'safe').length;

  // Recent activity aggregated from real items
  const recentItems = [
    ...urlScans.map((s) => ({
      id: s.id,
      title: s.url,
      type: 'Link' as const,
      timestamp: s.timestamp,
      outcome: s.verdict,
      outcomeLabel:
        s.verdict === 'malicious'
          ? 'Dangerous signs found'
          : s.verdict === 'suspicious'
          ? 'Suspicious activity detected'
          : 'No threats detected',
      riskLevel: s.riskLevel,
      href: '/url-scanner',
    })),
    ...docScans.map((d) => ({
      id: d.id,
      title: d.fileName,
      type: 'Document' as const,
      timestamp: d.timestamp,
      outcome: d.verdict,
      outcomeLabel:
        d.verdict === 'malicious'
          ? 'Dangerous signs found'
          : d.verdict === 'suspicious'
          ? 'Suspicious activity detected'
          : 'No threats detected',
      riskLevel: d.riskLevel,
      href: '/document-scanner',
    })),
    ...emails.map((e) => ({
      id: e.id,
      title: e.subject,
      type: 'Email' as const,
      timestamp: e.timestamp,
      outcome: e.riskLevel === 'critical' ? 'malicious' : e.riskLevel === 'warning' ? 'suspicious' : 'clean',
      outcomeLabel:
        e.riskLevel === 'critical'
          ? 'Dangerous signs found'
          : e.riskLevel === 'warning'
          ? 'Suspicious activity detected'
          : 'No threats detected',
      riskLevel: e.riskLevel,
      href: '/emails',
    })),
  ].slice(0, 5);

  const handleQuickUrlSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickUrl.trim()) return;
    setIsSubmittingUrl(true);
    try {
      await scanUrl(quickUrl.trim());
      router.push('/url-scanner');
    } catch {
      router.push('/url-scanner');
    } finally {
      setIsSubmittingUrl(false);
    }
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto pb-12">
      {/* 1. Hero Hub Header */}
      <div className="rounded-2xl border border-[#E5E5E5] dark:border-zinc-800 bg-[#FFFFFF] dark:bg-zinc-900/60 p-6 sm:p-8 backdrop-blur-sm shadow-xs">
        <div className="max-w-2xl space-y-3">
          <div className="inline-flex items-center gap-2 rounded-full border border-[#E5E5E5] dark:border-zinc-700 bg-[#FAFAFA] dark:bg-zinc-800 px-3 py-1 text-xs font-semibold text-[#111111] dark:text-[#FFFFFF]">
            <ShieldCheck className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
            <span>Personal Security Assistant</span>
          </div>

          <h1 className="text-2xl sm:text-3xl font-extrabold text-[#111111] dark:text-[#FFFFFF] tracking-tight">
            Your online safety, in one place.
          </h1>

          <p className="text-sm text-[#737373] dark:text-zinc-300 leading-relaxed">
            Cyclops protects everyday individuals from online scams, dangerous links, phishing emails, and harmful document downloads. Paste a link or upload a file to check it before you interact.
          </p>
        </div>
      </div>

      {/* 2. Three Prominent Action Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Action 1: Check a Link */}
        <Card className="flex flex-col justify-between p-5 space-y-4 hover:border-[#111111] dark:hover:border-zinc-600 transition-colors" interactive={false}>
          <div className="space-y-3">
            <div className="h-10 w-10 rounded-xl border border-[#E5E5E5] dark:border-zinc-700 bg-[#FAFAFA] dark:bg-zinc-800 flex items-center justify-center text-[#111111] dark:text-[#FFFFFF]">
              <Globe className="h-5 w-5 text-[#111111] dark:text-[#FFFFFF]" />
            </div>
            <div>
              <h2 className="text-base font-bold text-[#111111] dark:text-[#FFFFFF]">Check a Link</h2>
              <p className="text-xs text-[#737373] dark:text-zinc-400 mt-1 leading-relaxed">
                Check any website address for lookalike domains, fake login screens, and known scam databases.
              </p>
            </div>

            {/* Quick URL input */}
            <form onSubmit={handleQuickUrlSubmit} className="pt-1">
              <div className="relative">
                <input
                  type="text"
                  value={quickUrl}
                  onChange={(e) => setQuickUrl(e.target.value)}
                  placeholder="Paste URL (e.g. site.com)"
                  className="w-full rounded-lg border border-[#E5E5E5] dark:border-zinc-800 bg-[#FAFAFA] dark:bg-zinc-950 px-3 py-1.5 text-xs text-[#111111] dark:text-[#FFFFFF] placeholder-[#737373] focus:border-[#111111] dark:focus:border-white focus:outline-hidden"
                />
              </div>
            </form>
          </div>

          <div className="pt-2 border-t border-[#E5E5E5] dark:border-zinc-800/80">
            {quickUrl.trim() ? (
              <button
                onClick={handleQuickUrlSubmit}
                disabled={isSubmittingUrl}
                className="w-full flex items-center justify-center gap-1.5 rounded-lg bg-[#111111] text-[#FFFFFF] dark:bg-[#FFFFFF] dark:text-[#111111] py-2 text-xs font-semibold hover:bg-zinc-800 dark:hover:bg-zinc-200 transition-colors cursor-pointer"
              >
                <span>{isSubmittingUrl ? 'Checking...' : 'Check This Link'}</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            ) : (
              <Link
                href="/url-scanner"
                className="flex items-center justify-between text-xs font-semibold text-[#111111] dark:text-[#FFFFFF] hover:underline pt-1"
              >
                <span>Open Link Scanner</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            )}
          </div>
        </Card>

        {/* Action 2: Check an Email */}
        <Card className="flex flex-col justify-between p-5 space-y-4 hover:border-[#111111] dark:hover:border-zinc-600 transition-colors" interactive={false}>
          <div className="space-y-3">
            <div className="h-10 w-10 rounded-xl border border-[#E5E5E5] dark:border-zinc-700 bg-[#FAFAFA] dark:bg-zinc-800 flex items-center justify-center text-[#111111] dark:text-[#FFFFFF]">
              <Mail className="h-5 w-5 text-[#111111] dark:text-[#FFFFFF]" />
            </div>
            <div>
              <h2 className="text-base font-bold text-[#111111] dark:text-[#FFFFFF]">Check an Email</h2>
              <p className="text-xs text-[#737373] dark:text-zinc-400 mt-1 leading-relaxed">
                Inspect suspicious emails for spoofed sender addresses, urgent payment pressure, and deceptive links.
              </p>
            </div>

            <div className="rounded-lg bg-[#FAFAFA] dark:bg-zinc-950 p-2.5 border border-[#E5E5E5] dark:border-zinc-800/80 text-[11px] text-[#737373]">
              <span className="font-semibold text-[#111111] dark:text-zinc-200 block">Detects:</span>
              <span>Fake bank alerts, spoofed invoices, credential traps</span>
            </div>
          </div>

          <div className="pt-2 border-t border-[#E5E5E5] dark:border-zinc-800/80">
            <Link
              href="/emails"
              className="flex items-center justify-between text-xs font-semibold text-[#111111] dark:text-[#FFFFFF] hover:underline pt-1"
            >
              <span>Inspect Suspicious Email</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        </Card>

        {/* Action 3: Scan a Document */}
        <Card className="flex flex-col justify-between p-5 space-y-4 hover:border-[#111111] dark:hover:border-zinc-600 transition-colors" interactive={false}>
          <div className="space-y-3">
            <div className="h-10 w-10 rounded-xl border border-[#E5E5E5] dark:border-zinc-700 bg-[#FAFAFA] dark:bg-zinc-800 flex items-center justify-center text-[#111111] dark:text-[#FFFFFF]">
              <FileSearch className="h-5 w-5 text-[#111111] dark:text-[#FFFFFF]" />
            </div>
            <div>
              <h2 className="text-base font-bold text-[#111111] dark:text-[#FFFFFF]">Scan a Document</h2>
              <p className="text-xs text-[#737373] dark:text-zinc-400 mt-1 leading-relaxed">
                Inspect PDFs, spreadsheets, and files for hidden VBA macros, double extensions, and suspicious scripts.
              </p>
            </div>

            <div className="rounded-lg bg-[#FAFAFA] dark:bg-zinc-950 p-2.5 border border-[#E5E5E5] dark:border-zinc-800/80 text-[11px] text-[#737373]">
              <span className="font-semibold text-[#111111] dark:text-zinc-200 block">Supports:</span>
              <span>.PDF, .DOCX, .XLSM, .HTML, and email attachments</span>
            </div>
          </div>

          <div className="pt-2 border-t border-[#E5E5E5] dark:border-zinc-800/80">
            <Link
              href="/document-scanner"
              className="flex items-center justify-between text-xs font-semibold text-[#111111] dark:text-[#FFFFFF] hover:underline pt-1"
            >
              <span>Open Document Scanner</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        </Card>
      </div>

      {/* 3. Overview of Recent Checks & Findings (Actual data) */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-[#111111] dark:text-[#FFFFFF]">Security Overview</h2>
            <p className="text-xs text-[#737373]">Summary of completed checks in your current session.</p>
          </div>
          <Link
            href="/history"
            className="text-xs font-medium text-[#737373] hover:text-[#111111] dark:hover:text-[#FFFFFF] flex items-center gap-1"
          >
            <span>View All History</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>

        {totalScans > 0 ? (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-4 rounded-xl border border-[#E5E5E5] dark:border-zinc-800 bg-[#FFFFFF] dark:bg-zinc-900 shadow-xs space-y-1">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-[#737373] block">
                Total Checks Run
              </span>
              <span className="text-2xl font-black text-[#111111] dark:text-[#FFFFFF] block">
                {totalScans}
              </span>
              <span className="text-[11px] text-[#737373] block">
                Across links, files, and emails
              </span>
            </div>

            <div className="p-4 rounded-xl border border-red-200 dark:border-red-900/50 bg-red-50/50 dark:bg-red-950/20 shadow-xs space-y-1">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-red-700 dark:text-red-400 block">
                Dangerous Signs
              </span>
              <span className="text-2xl font-black text-red-600 dark:text-red-400 block">
                {dangerousCount}
              </span>
              <span className="text-[11px] text-[#737373] block">
                Confirmed threat indicators
              </span>
            </div>

            <div className="p-4 rounded-xl border border-amber-200 dark:border-amber-900/50 bg-amber-50/50 dark:bg-amber-950/20 shadow-xs space-y-1">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-amber-700 dark:text-amber-400 block">
                Suspicious Activity
              </span>
              <span className="text-2xl font-black text-amber-600 dark:text-amber-400 block">
                {suspiciousCount}
              </span>
              <span className="text-[11px] text-[#737373] block">
                Anomalous patterns to verify
              </span>
            </div>

            <div className="p-4 rounded-xl border border-emerald-200 dark:border-emerald-900/50 bg-emerald-50/50 dark:bg-emerald-950/20 shadow-xs space-y-1">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-emerald-700 dark:text-emerald-400 block">
                No Threats Detected
              </span>
              <span className="text-2xl font-black text-emerald-600 dark:text-emerald-400 block">
                {cleanCount}
              </span>
              <span className="text-[11px] text-[#737373] block">
                Passed completed checks
              </span>
            </div>
          </div>
        ) : (
          <div className="rounded-xl border border-dashed border-[#E5E5E5] dark:border-zinc-800 p-8 text-center text-xs text-[#737373] space-y-2">
            <CheckCircle2 className="h-8 w-8 text-[#737373] mx-auto opacity-50 mb-1" />
            <p className="font-semibold text-[#111111] dark:text-[#FFFFFF]">No checks performed yet</p>
            <p>Use the actions above to check your first link, email, or document file.</p>
          </div>
        )}
      </div>

      {/* 4. Recent Scan History Section */}
      {recentItems.length > 0 && (
        <Card className="space-y-4" interactive={false}>
          <div className="flex items-center justify-between border-b border-[#E5E5E5] dark:border-zinc-800 pb-3">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-[#737373]" />
              <h2 className="text-sm font-bold text-[#111111] dark:text-[#FFFFFF]">Recent Checks</h2>
            </div>
            <Link
              href="/history"
              className="text-xs text-[#737373] hover:text-[#111111] dark:hover:text-[#FFFFFF] font-medium"
            >
              Full History →
            </Link>
          </div>

          <div className="divide-y divide-[#E5E5E5] dark:divide-zinc-800/80">
            {recentItems.map((item) => (
              <div
                key={item.id}
                className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div className="min-w-0 space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.2 text-[10px] font-semibold text-[#737373]">
                      {item.type}
                    </span>
                    <span className="font-semibold text-[#111111] dark:text-[#FFFFFF] truncate font-mono">
                      {item.title}
                    </span>
                  </div>
                  <p className="text-[11px] text-[#737373]">{item.timestamp}</p>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <Badge level={item.riskLevel}>{item.outcomeLabel}</Badge>
                  <Link
                    href={item.href}
                    className="text-xs font-semibold text-[#111111] dark:text-[#FFFFFF] hover:underline"
                  >
                    View
                  </Link>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* 5. Helpful, Actionable Safety Advice */}
      <div className="space-y-4 pt-2">
        <div>
          <h2 className="text-base font-bold text-[#111111] dark:text-[#FFFFFF]">Practical Safety Advice</h2>
          <p className="text-xs text-[#737373]">Simple habits to keep your accounts and devices protected.</p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="rounded-xl border border-[#E5E5E5] dark:border-zinc-800 bg-[#FFFFFF] dark:bg-zinc-900 p-4 space-y-2">
            <div className="flex items-center gap-2 text-xs font-bold text-[#111111] dark:text-[#FFFFFF]">
              <Globe className="h-4 w-4 text-[#737373]" />
              <h3>Spotting Lookalike Links</h3>
            </div>
            <p className="text-xs text-[#737373] dark:text-zinc-300 leading-relaxed">
              Always check the actual domain name before typing passwords. Scammers often use misleading subdomains like <code className="font-mono bg-zinc-100 dark:bg-zinc-800 px-1 rounded text-[11px]">paypal.com.verify-user.cc</code> where the real website is the last part before the slash.
            </p>
          </div>

          <div className="rounded-xl border border-[#E5E5E5] dark:border-zinc-800 bg-[#FFFFFF] dark:bg-zinc-900 p-4 space-y-2">
            <div className="flex items-center gap-2 text-xs font-bold text-[#111111] dark:text-[#FFFFFF]">
              <Mail className="h-4 w-4 text-[#737373]" />
              <h3>Recognizing Artificial Urgency</h3>
            </div>
            <p className="text-xs text-[#737373] dark:text-zinc-300 leading-relaxed">
              Phishing messages usually create panic with phrases like “Account suspended in 2 hours” or “Unpaid tax penalty”. Legitimate companies rarely demand immediate action without prior notification.
            </p>
          </div>

          <div className="rounded-xl border border-[#E5E5E5] dark:border-zinc-800 bg-[#FFFFFF] dark:bg-zinc-900 p-4 space-y-2">
            <div className="flex items-center gap-2 text-xs font-bold text-[#111111] dark:text-[#FFFFFF]">
              <FileSearch className="h-4 w-4 text-[#737373]" />
              <h3>Never Enable Macros on Unexpected Files</h3>
            </div>
            <p className="text-xs text-[#737373] dark:text-zinc-300 leading-relaxed">
              If an Office file prompts you to &ldquo;Enable Content&rdquo; or &ldquo;Enable Macros&rdquo; to read an invoice or contract, do not click it. Modern documents do not require macros to display plain text.
            </p>
          </div>

          <div className="rounded-xl border border-[#E5E5E5] dark:border-zinc-800 bg-[#FFFFFF] dark:bg-zinc-900 p-4 space-y-2">
            <div className="flex items-center gap-2 text-xs font-bold text-[#111111] dark:text-[#FFFFFF]">
              <ShieldCheck className="h-4 w-4 text-[#737373]" />
              <h3>Check Before You Interact</h3>
            </div>
            <p className="text-xs text-[#737373] dark:text-zinc-300 leading-relaxed">
              When receiving an unexpected link or download from a message or email, paste it into Cyclops first. We examine certificates, reputations, and structures in a safe, non-executing environment.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
