'use client';

import React, { useState } from 'react';
import { useDemoContext } from '../../context/DemoContext';
import { Card } from '../../components/ui/Card';
import { Badge } from '../../components/ui/Badge';
import { Modal } from '../../components/ui/Modal';
import { SecurityEmail, RiskLevel } from '../../types';
import {
  Search,
  Mail,
  ShieldAlert,
  ShieldCheck,
  ExternalLink,
  Paperclip,
  CheckCircle,
  AlertTriangle,
  Info,
  Filter,
} from 'lucide-react';

export default function EmailsPage() {
  const { emails, quarantineEmail, markEmailSafe, reportEmailPhishing } = useDemoContext();
  const [searchTerm, setSearchTerm] = useState('');
  const [riskFilter, setRiskFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedEmail, setSelectedEmail] = useState<SecurityEmail | null>(null);

  const filteredEmails = emails.filter((email) => {
    const matchesSearch =
      email.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
      email.sender.toLowerCase().includes(searchTerm.toLowerCase()) ||
      email.senderEmail.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRisk = riskFilter === 'all' || email.riskLevel === riskFilter;
    const matchesStatus = statusFilter === 'all' || email.status === statusFilter;
    return matchesSearch && matchesRisk && matchesStatus;
  });

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-100 flex items-center gap-2">
            <Mail className="h-5 w-5 text-zinc-400" />
            Inbound Email Security Inspection
          </h1>
          <p className="text-xs text-zinc-400 mt-1">
            SentinelAI automatically checks sender signatures, domain age, links, and attachments.
          </p>
        </div>
        <div className="rounded-md border border-zinc-800 bg-zinc-900 px-3 py-1 text-[11px] text-zinc-400">
          Demo Mode • Simulated Analysis
        </div>
      </div>

      {/* Filter & Search Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-zinc-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search email sender, subject, or domain..."
            className="w-full rounded-lg border border-zinc-800 bg-zinc-900/80 pl-9 pr-4 py-2 text-xs text-zinc-100 placeholder-zinc-500 focus:border-zinc-700 focus:outline-hidden"
          />
        </div>

        {/* Filters */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 sm:pb-0">
          <div className="flex items-center gap-1 rounded-lg border border-zinc-800 bg-zinc-950 p-1">
            <Filter className="h-3.5 w-3.5 text-zinc-500 ml-1.5" />
            <span className="text-[11px] text-zinc-400 mr-1">Risk:</span>
            {['all', 'critical', 'warning', 'safe'].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setRiskFilter(lvl)}
                className={`rounded-md px-2 py-1 text-xs capitalize transition-colors ${
                  riskFilter === lvl
                    ? 'bg-zinc-800 text-zinc-100 font-medium'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 rounded-lg border border-zinc-800 bg-zinc-950 p-1">
            <span className="text-[11px] text-zinc-400 ml-1.5 mr-1">Status:</span>
            {['all', 'flagged', 'quarantined', 'clean'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`rounded-md px-2 py-1 text-xs capitalize transition-colors ${
                  statusFilter === st
                    ? 'bg-zinc-800 text-zinc-100 font-medium'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Email Table */}
      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-zinc-800 bg-zinc-950/80 text-zinc-400 uppercase text-[10px] tracking-wider">
              <tr>
                <th className="px-4 py-3">Sender & Subject</th>
                <th className="px-4 py-3">Risk Level</th>
                <th className="px-4 py-3">Detected Signals</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {filteredEmails.length > 0 ? (
                filteredEmails.map((email) => (
                  <tr
                    key={email.id}
                    onClick={() => setSelectedEmail(email)}
                    className="hover-card cursor-pointer hover:bg-zinc-800/40 transition-colors"
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        <div className="h-8 w-8 rounded-full bg-zinc-800 border border-zinc-700 flex items-center justify-center font-bold text-zinc-300 shrink-0">
                          {email.sender.charAt(0)}
                        </div>
                        <div className="min-w-0">
                          <p className="font-semibold text-zinc-200 truncate">{email.subject}</p>
                          <p className="text-[11px] text-zinc-400 truncate">{email.sender} &lt;{email.senderEmail}&gt;</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <Badge level={email.riskLevel}>{email.riskLevel}</Badge>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {email.detectedSignals.slice(0, 2).map((sig, i) => (
                          <span
                            key={i}
                            className="rounded border border-zinc-800 bg-zinc-950 px-1.5 py-0.5 text-[10px] text-zinc-400"
                          >
                            {sig}
                          </span>
                        ))}
                        {email.detectedSignals.length > 2 && (
                          <span className="text-[10px] text-zinc-500 self-center">
                            +{email.detectedSignals.length - 2} more
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-semibold capitalize ${
                          email.status === 'quarantined'
                            ? 'bg-amber-950/50 text-amber-400 border border-amber-900/50'
                            : email.status === 'flagged'
                            ? 'bg-red-950/50 text-red-400 border border-red-900/50'
                            : 'bg-zinc-900 text-zinc-400 border border-zinc-800'
                        }`}
                      >
                        {email.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right text-zinc-500 whitespace-nowrap">
                      {email.timestamp}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-zinc-500 text-xs">
                    No emails match the current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Email Detail Inspection Modal */}
      {selectedEmail && (
        <Modal
          isOpen={!!selectedEmail}
          onClose={() => setSelectedEmail(null)}
          title="Email Threat Technical Analysis"
          subtitle={`Message ID: ${selectedEmail.id} • Analyzed by SentinelAI`}
          maxWidth="2xl"
        >
          <div className="space-y-5">
            {/* Header info */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-zinc-400">Subject</span>
                <Badge level={selectedEmail.riskLevel}>{selectedEmail.riskLevel}</Badge>
              </div>
              <p className="text-sm font-bold text-zinc-100">{selectedEmail.subject}</p>
              <div className="text-xs text-zinc-400 border-t border-zinc-800/80 pt-2 flex flex-wrap justify-between gap-2">
                <span>
                  <strong>From:</strong> {selectedEmail.sender} ({selectedEmail.senderEmail})
                </span>
                <span>{selectedEmail.timestamp}</span>
              </div>
            </div>

            {/* AI Explanation Box */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/80 p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-zinc-200">
                <Info className="h-4 w-4 text-zinc-400" />
                SentinelAI Threat Explanation
              </div>
              <p className="text-xs text-zinc-300 leading-relaxed">{selectedEmail.aiAnalysisSummary}</p>
            </div>

            {/* Technical Authentication Grid */}
            <div className="grid grid-cols-4 gap-2 text-center text-xs">
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-2">
                <p className="text-[10px] text-zinc-500">SPF Validation</p>
                <p
                  className={`font-semibold uppercase ${
                    selectedEmail.spfStatus === 'pass'
                      ? 'text-emerald-400'
                      : selectedEmail.spfStatus === 'fail'
                      ? 'text-red-400'
                      : 'text-zinc-400'
                  }`}
                >
                  {selectedEmail.spfStatus}
                </p>
              </div>
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-2">
                <p className="text-[10px] text-zinc-500">DKIM Signature</p>
                <p
                  className={`font-semibold uppercase ${
                    selectedEmail.dkimStatus === 'pass'
                      ? 'text-emerald-400'
                      : selectedEmail.dkimStatus === 'fail'
                      ? 'text-red-400'
                      : 'text-zinc-400'
                  }`}
                >
                  {selectedEmail.dkimStatus}
                </p>
              </div>
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-2">
                <p className="text-[10px] text-zinc-500">DMARC Policy</p>
                <p
                  className={`font-semibold uppercase ${
                    selectedEmail.dmarcStatus === 'pass'
                      ? 'text-emerald-400'
                      : selectedEmail.dmarcStatus === 'fail'
                      ? 'text-red-400'
                      : 'text-zinc-400'
                  }`}
                >
                  {selectedEmail.dmarcStatus}
                </p>
              </div>
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-2">
                <p className="text-[10px] text-zinc-500">Domain Age</p>
                <p className="font-semibold text-zinc-200">{selectedEmail.domainAge}</p>
              </div>
            </div>

            {/* Embedded Links */}
            {selectedEmail.linksFound.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-zinc-300 flex items-center gap-1.5">
                  <ExternalLink className="h-3.5 w-3.5 text-zinc-400" />
                  Embedded Links Analysis ({selectedEmail.linksFound.length})
                </h4>
                <div className="space-y-1.5">
                  {selectedEmail.linksFound.map((link, idx) => (
                    <div
                      key={idx}
                      className="rounded-lg border border-zinc-800 bg-zinc-950 p-2.5 flex items-center justify-between text-xs gap-3"
                    >
                      <span className="font-mono text-[11px] text-zinc-300 truncate">{link.url}</span>
                      <Badge level={link.risk}>{link.risk}</Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Attachments */}
            {selectedEmail.attachmentsFound.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-zinc-300 flex items-center gap-1.5">
                  <Paperclip className="h-3.5 w-3.5 text-zinc-400" />
                  Attachments ({selectedEmail.attachmentsFound.length})
                </h4>
                <div className="space-y-1.5">
                  {selectedEmail.attachmentsFound.map((att, idx) => (
                    <div
                      key={idx}
                      className="rounded-lg border border-zinc-800 bg-zinc-950 p-2.5 flex items-center justify-between text-xs"
                    >
                      <div>
                        <p className="font-semibold text-zinc-200">{att.name}</p>
                        <p className="text-[10px] text-zinc-500">{att.size} • {att.type}</p>
                      </div>
                      <Badge level={att.risk}>{att.risk}</Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Demo Notice Banner */}
            <div className="rounded-md border border-zinc-800 bg-zinc-950/60 p-2.5 text-center text-[11px] text-zinc-500">
              ⚡ Frontend Demo Mode • Actions alter local session state only.
            </div>

            {/* Action Buttons */}
            <div className="flex flex-wrap items-center justify-end gap-2 border-t border-zinc-800 pt-4">
              <button
                onClick={() => {
                  markEmailSafe(selectedEmail.id);
                  setSelectedEmail(null);
                }}
                className="rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100"
              >
                Mark as Safe
              </button>
              <button
                onClick={() => {
                  quarantineEmail(selectedEmail.id);
                  setSelectedEmail(null);
                }}
                className="rounded-lg border border-amber-900/50 bg-amber-950/40 px-3 py-1.5 text-xs font-semibold text-amber-300 hover:bg-amber-900/60"
              >
                Quarantine Email
              </button>
              <button
                onClick={() => {
                  reportEmailPhishing(selectedEmail.id);
                  setSelectedEmail(null);
                }}
                className="rounded-lg bg-red-900/80 px-3 py-1.5 text-xs font-semibold text-red-100 hover:bg-red-800"
              >
                Report Phishing & Block
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
