'use client';

import React, { useState, useMemo } from 'react';
import Link from 'next/link';
import { useDemoContext } from '../../context/DemoContext';
import { Card } from '../../components/ui/Card';
import { Badge } from '../../components/ui/Badge';
import {
  History,
  Globe,
  FileText,
  Mail,
  Search,
  ArrowRight,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock,
  Filter,
} from 'lucide-react';

type ScanTypeFilter = 'all' | 'url' | 'document' | 'email';
type OutcomeFilter = 'all' | 'dangerous' | 'suspicious' | 'clean';

interface UnifiedScanItem {
  id: string;
  type: 'url' | 'document' | 'email';
  title: string;
  subtitle: string;
  timestamp: string;
  outcome: 'malicious' | 'suspicious' | 'clean' | 'incomplete';
  outcomeLabel: string;
  riskLevel: 'critical' | 'warning' | 'safe' | 'neutral';
  summary: string;
  viewHref: string;
}

export default function HistoryPage() {
  const { urlScans, docScans, emails } = useDemoContext();
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState<ScanTypeFilter>('all');
  const [outcomeFilter, setOutcomeFilter] = useState<OutcomeFilter>('all');

  // Build unified items from actual state
  const allItems: UnifiedScanItem[] = useMemo(() => {
    const items: UnifiedScanItem[] = [];

    // URL Scans
    urlScans.forEach((scan) => {
      let outcomeLabel = 'No threats detected';
      let outcome: 'malicious' | 'suspicious' | 'clean' | 'incomplete' = 'clean';
      if (scan.verdict === 'malicious' || scan.verdict === 'phishing') {
        outcomeLabel = 'Dangerous signs found';
        outcome = 'malicious';
      } else if (scan.verdict === 'suspicious') {
        outcomeLabel = 'Suspicious activity detected';
        outcome = 'suspicious';
      } else if (scan.verdict === 'clean' || scan.verdict === 'safe') {
        outcomeLabel = 'No threats detected';
        outcome = 'clean';
      } else {
        outcomeLabel = 'Scan incomplete';
        outcome = 'incomplete';
      }

      items.push({
        id: scan.id,
        type: 'url',
        title: scan.url,
        subtitle: scan.domainInfo?.domain || scan.url,
        timestamp: scan.timestamp,
        outcome,
        outcomeLabel,
        riskLevel: scan.riskLevel,
        summary: scan.plain_english_explanation || scan.summary || 'URL scan completed.',
        viewHref: '/url-scanner',
      });
    });

    // Document Scans
    docScans.forEach((doc) => {
      let outcomeLabel = 'No threats detected';
      let outcome: 'malicious' | 'suspicious' | 'clean' | 'incomplete' = 'clean';
      if (doc.verdict === 'malicious') {
        outcomeLabel = 'Dangerous signs found';
        outcome = 'malicious';
      } else if (doc.verdict === 'suspicious') {
        outcomeLabel = 'Suspicious activity detected';
        outcome = 'suspicious';
      } else if (doc.verdict === 'clean') {
        outcomeLabel = 'No threats detected';
        outcome = 'clean';
      } else {
        outcomeLabel = 'Scan incomplete';
        outcome = 'incomplete';
      }

      items.push({
        id: doc.id,
        type: 'document',
        title: doc.fileName,
        subtitle: `${doc.fileType} • ${doc.fileSize}`,
        timestamp: doc.timestamp,
        outcome,
        outcomeLabel,
        riskLevel: doc.riskLevel,
        summary: doc.aiSummary || doc.recommendedAction || 'Document security inspection completed.',
        viewHref: '/document-scanner',
      });
    });

    // Emails
    emails.forEach((email) => {
      let outcomeLabel = 'No threats detected';
      let outcome: 'malicious' | 'suspicious' | 'clean' = 'clean';
      if (email.riskLevel === 'critical') {
        outcomeLabel = 'Dangerous signs found';
        outcome = 'malicious';
      } else if (email.riskLevel === 'warning') {
        outcomeLabel = 'Suspicious activity detected';
        outcome = 'suspicious';
      }

      items.push({
        id: email.id,
        type: 'email',
        title: email.subject,
        subtitle: `From: ${email.sender} <${email.senderEmail}>`,
        timestamp: email.timestamp,
        outcome,
        outcomeLabel,
        riskLevel: email.riskLevel,
        summary: email.aiAnalysisSummary || email.bodySnippet || 'Email security inspection completed.',
        viewHref: '/emails',
      });
    });

    return items;
  }, [urlScans, docScans, emails]);

  // Filter items
  const filteredItems = useMemo(() => {
    return allItems.filter((item) => {
      const matchesSearch =
        item.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.subtitle.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.summary.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesType = typeFilter === 'all' || item.type === typeFilter;

      let matchesOutcome = true;
      if (outcomeFilter === 'dangerous') matchesOutcome = item.outcome === 'malicious';
      else if (outcomeFilter === 'suspicious') matchesOutcome = item.outcome === 'suspicious';
      else if (outcomeFilter === 'clean') matchesOutcome = item.outcome === 'clean';

      return matchesSearch && matchesType && matchesOutcome;
    });
  }, [allItems, searchTerm, typeFilter, outcomeFilter]);

  const getTypeIcon = (type: UnifiedScanItem['type']) => {
    switch (type) {
      case 'url':
        return <Globe className="h-4 w-4" />;
      case 'document':
        return <FileText className="h-4 w-4" />;
      case 'email':
        return <Mail className="h-4 w-4" />;
    }
  };

  const getTypeLabel = (type: UnifiedScanItem['type']) => {
    switch (type) {
      case 'url':
        return 'Link';
      case 'document':
        return 'Document';
      case 'email':
        return 'Email';
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#E5E5E5] dark:border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-[#111111] dark:text-[#FFFFFF] flex items-center gap-2 tracking-tight">
            <History className="h-5 w-5 text-[#737373]" />
            Scan History
          </h1>
          <p className="text-xs text-[#737373] mt-1">
            Your personal record of checked links, inspected emails, and analyzed documents.
          </p>
        </div>
        <div className="rounded-md border border-[#E5E5E5] dark:border-zinc-800 bg-[#FAFAFA] dark:bg-zinc-900 px-3 py-1 text-xs text-[#737373]">
          {allItems.length} {allItems.length === 1 ? 'total check' : 'total checks'} recorded
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-[#737373]" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by URL, document name, or email subject..."
            className="w-full rounded-lg border border-[#E5E5E5] dark:border-zinc-800 bg-[#FFFFFF] dark:bg-zinc-900 pl-9 pr-4 py-2 text-xs text-[#111111] dark:text-[#FFFFFF] placeholder-[#737373] focus:border-[#111111] dark:focus:border-[#FFFFFF] focus:outline-hidden"
          />
        </div>

        {/* Type Filter Buttons */}
        <div className="flex items-center gap-1 rounded-lg border border-[#E5E5E5] dark:border-zinc-800 bg-[#FAFAFA] dark:bg-zinc-950 p-1">
          <span className="text-[11px] text-[#737373] ml-1.5 mr-1 flex items-center gap-1">
            <Filter className="h-3 w-3" /> Type:
          </span>
          {(['all', 'url', 'document', 'email'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`rounded-md px-2.5 py-1 text-xs capitalize transition-colors cursor-pointer ${
                typeFilter === t
                  ? 'bg-white dark:bg-zinc-800 text-[#111111] dark:text-[#FFFFFF] font-semibold shadow-xs'
                  : 'text-[#737373] hover:text-[#111111] dark:hover:text-[#FFFFFF]'
              }`}
            >
              {t === 'all' ? 'All' : t === 'url' ? 'Links' : t === 'document' ? 'Docs' : 'Emails'}
            </button>
          ))}
        </div>

        {/* Outcome Filter Buttons */}
        <div className="flex items-center gap-1 rounded-lg border border-[#E5E5E5] dark:border-zinc-800 bg-[#FAFAFA] dark:bg-zinc-950 p-1">
          <span className="text-[11px] text-[#737373] ml-1.5 mr-1">Outcome:</span>
          {[
            { id: 'all', label: 'All' },
            { id: 'dangerous', label: 'Dangerous' },
            { id: 'suspicious', label: 'Suspicious' },
            { id: 'clean', label: 'Clean' },
          ].map((out) => (
            <button
              key={out.id}
              onClick={() => setOutcomeFilter(out.id as OutcomeFilter)}
              className={`rounded-md px-2 py-1 text-xs transition-colors cursor-pointer ${
                outcomeFilter === out.id
                  ? 'bg-white dark:bg-zinc-800 text-[#111111] dark:text-[#FFFFFF] font-semibold shadow-xs'
                  : 'text-[#737373] hover:text-[#111111] dark:hover:text-[#FFFFFF]'
              }`}
            >
              {out.label}
            </button>
          ))}
        </div>
      </div>

      {/* History Items List */}
      <Card className="p-0 overflow-hidden" interactive={false}>
        <div className="divide-y divide-[#E5E5E5] dark:divide-zinc-800/80">
          {filteredItems.length > 0 ? (
            filteredItems.map((item) => (
              <div
                key={item.id}
                className="p-4 hover:bg-[#FAFAFA] dark:hover:bg-zinc-900/60 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              >
                <div className="flex items-start gap-3.5 min-w-0 flex-1">
                  <div className="h-9 w-9 rounded-lg border border-[#E5E5E5] dark:border-zinc-800 bg-[#FAFAFA] dark:bg-zinc-900 flex items-center justify-center text-[#737373] shrink-0 mt-0.5">
                    {getTypeIcon(item.type)}
                  </div>
                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 text-[10px] font-semibold text-[#737373] uppercase tracking-wider">
                        {getTypeLabel(item.type)}
                      </span>
                      <h3 className="text-xs font-bold text-[#111111] dark:text-[#FFFFFF] truncate font-mono">
                        {item.title}
                      </h3>
                    </div>
                    <p className="text-[11px] text-[#737373] line-clamp-1">
                      {item.summary}
                    </p>
                    <div className="flex items-center gap-3 text-[10px] text-[#737373]">
                      <span>{item.subtitle}</span>
                      <span>•</span>
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" /> {item.timestamp}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0 sm:self-center">
                  <Badge level={item.riskLevel}>{item.outcomeLabel}</Badge>
                  <Link
                    href={item.viewHref}
                    className="flex items-center gap-1 text-xs font-medium text-[#111111] dark:text-[#FFFFFF] hover:underline"
                  >
                    <span>View Scanner</span>
                    <ArrowRight className="h-3.5 w-3.5" />
                  </Link>
                </div>
              </div>
            ))
          ) : (
            <div className="py-14 text-center text-xs text-[#737373] space-y-2">
              <History className="h-8 w-8 text-[#737373] mx-auto opacity-50 mb-2" />
              <p className="font-semibold text-[#111111] dark:text-[#FFFFFF]">No scan history found</p>
              <p>
                {searchTerm || typeFilter !== 'all' || outcomeFilter !== 'all'
                  ? 'Try adjusting your search terms or filter selection.'
                  : 'Start by checking a link, analyzing an email, or scanning a document.'}
              </p>
              {allItems.length === 0 && (
                <div className="pt-2 flex justify-center gap-2">
                  <Link
                    href="/url-scanner"
                    className="rounded-lg bg-[#111111] text-white dark:bg-white dark:text-[#111111] px-3 py-1.5 text-xs font-semibold"
                  >
                    Check a Link
                  </Link>
                </div>
              )}
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
