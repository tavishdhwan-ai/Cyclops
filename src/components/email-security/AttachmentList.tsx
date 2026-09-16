'use client';

import React, { useState } from 'react';
import { AttachmentScanItem } from '../../types';
import { Badge } from '../ui/Badge';
import {
  FileText,
  FileCode,
  Image as ImageIcon,
  Calendar,
  Ticket,
  ChevronDown,
  ChevronUp,
  ShieldAlert,
  Info,
  Paperclip,
} from 'lucide-react';

export const mockAttachments: AttachmentScanItem[] = [
  {
    id: 'att-1',
    fileName: 'invoice.pdf',
    fileType: 'PDF',
    threatScore: 8.4,
    riskLevel: 'HIGH',
    findings: ['External payment link', 'Invoice impersonation', 'Suspicious payment request'],
    recommendation: 'Do not open or download this attachment until its source is verified.',
    status: 'Analysis complete',
  },
  {
    id: 'att-2',
    fileName: 'payment-details.docx',
    fileType: 'DOCX',
    threatScore: 9.1,
    riskLevel: 'CRITICAL',
    findings: ['Suspicious external link', 'Sensitive information request', 'Unexpected payment instructions'],
    recommendation: 'Do not open or download this attachment until its source is verified.',
    status: 'Analysis complete',
  },
  {
    id: 'att-3',
    fileName: 'receipt.jpg',
    fileType: 'JPG',
    threatScore: 2.1,
    riskLevel: 'LOW',
    findings: ['No obvious technical indicators', 'Image contains payment-related text'],
    recommendation: 'Low threat risk, but exercise standard caution before downloading.',
    status: 'Analysis complete',
  },
  {
    id: 'att-4',
    fileName: 'meeting-invite.ics',
    fileType: 'ICS',
    threatScore: 6.8,
    riskLevel: 'MEDIUM',
    findings: ['Untrusted meeting link', 'Unknown organizer'],
    recommendation: 'Verify calendar invite source before accepting or clicking embedded links.',
    status: 'Analysis complete',
  },
  {
    id: 'att-5',
    fileName: 'event-pass.pkpass',
    fileType: 'PKPASS',
    threatScore: 1.8,
    riskLevel: 'LOW',
    findings: ['No obvious suspicious indicators in this demo'],
    recommendation: 'Safe pass format with standard security signatures.',
    status: 'Analysis complete',
  },
];

interface AttachmentListProps {
  isScanning?: boolean;
}

export const AttachmentList: React.FC<AttachmentListProps> = ({ isScanning = false }) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const getFileIcon = (fileType: string) => {
    switch (fileType.toUpperCase()) {
      case 'PDF':
        return <FileText className="h-4 w-4 text-red-500 dark:text-red-400" />;
      case 'DOCX':
        return <FileCode className="h-4 w-4 text-blue-500 dark:text-blue-400" />;
      case 'JPG':
      case 'PNG':
        return <ImageIcon className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />;
      case 'ICS':
        return <Calendar className="h-4 w-4 text-amber-600 dark:text-amber-400" />;
      case 'PKPASS':
        return <Ticket className="h-4 w-4 text-purple-600 dark:text-purple-400" />;
      default:
        return <FileText className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />;
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="space-y-3 border-t border-zinc-200 dark:border-zinc-800/80 pt-4 mt-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Paperclip className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          <h3 className="text-xs font-semibold text-zinc-800 dark:text-zinc-200">
            Email Attachments ({mockAttachments.length})
          </h3>
          <span className="rounded bg-zinc-100 dark:bg-zinc-900 px-2 py-0.5 text-[10px] font-medium text-zinc-600 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-800">
            Individual File Scans
          </span>
        </div>
        <span className="text-[11px] text-zinc-500">Simulated Demo Analysis</span>
      </div>

      <div className="space-y-2">
        {mockAttachments.map((att) => {
          const isExpanded = expandedId === att.id;
          const isHighRisk = att.riskLevel === 'CRITICAL' || att.riskLevel === 'HIGH';

          return (
            <div
              key={att.id}
              className={`rounded-lg border transition-all duration-200 hover-card ${
                isHighRisk
                  ? 'border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900/80 hover:border-red-200 dark:hover:border-red-900/50'
                  : 'border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900/50 hover:border-zinc-300 dark:hover:border-zinc-700'
              }`}
            >
              {/* Main row summary */}
              <div className="flex flex-wrap items-center justify-between gap-3 p-3">
                <div className="flex items-center gap-3 min-w-0 flex-1">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 shrink-0">
                    {getFileIcon(att.fileType)}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <p className="font-semibold text-xs text-zinc-900 dark:text-zinc-100 truncate">{att.fileName}</p>
                      <span className="rounded bg-zinc-100 dark:bg-zinc-950 px-1.5 py-0.5 text-[10px] font-mono text-zinc-600 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-800">
                        {att.fileType}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[10px] text-zinc-500 dark:text-zinc-400">
                        Status:{' '}
                        <span className="text-zinc-700 dark:text-zinc-300 font-medium">
                          {isScanning ? 'Scanning...' : att.status}
                        </span>
                      </span>
                    </div>
                  </div>
                </div>

                {/* Threat score & View Report Button */}
                <div className="flex items-center gap-3 shrink-0">
                  {isScanning ? (
                    <div className="flex items-center gap-2 text-xs text-zinc-500 dark:text-zinc-400">
                      <div className="h-3 w-3 animate-spin rounded-full border-2 border-zinc-300 dark:border-zinc-500 border-t-transparent" />
                      <span>Scanning file...</span>
                    </div>
                  ) : (
                    <>
                      <div className="text-right">
                        <div className="flex items-center gap-1.5">
                          <span className="text-xs font-bold font-mono text-zinc-800 dark:text-zinc-200">
                            {att.threatScore} / 10
                          </span>
                          <Badge level={att.riskLevel}>{att.riskLevel}</Badge>
                        </div>
                      </div>

                      <button
                        onClick={() => toggleExpand(att.id)}
                        className="flex items-center gap-1 rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 px-2.5 py-1 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors cursor-pointer"
                      >
                        <span>{isExpanded ? 'Hide Report' : 'View Report'}</span>
                        {isExpanded ? (
                          <ChevronUp className="h-3.5 w-3.5 text-zinc-500 dark:text-zinc-400" />
                        ) : (
                          <ChevronDown className="h-3.5 w-3.5 text-zinc-500 dark:text-zinc-400" />
                        )}
                      </button>
                    </>
                  )}
                </div>
              </div>

              {/* Detailed Report Drawer */}
              {isExpanded && !isScanning && (
                <div className="border-t border-zinc-200 dark:border-zinc-800/80 bg-zinc-50 dark:bg-zinc-950/90 p-3.5 space-y-3 rounded-b-lg">
                  <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800/60 pb-2">
                    <span className="text-xs font-semibold text-zinc-800 dark:text-zinc-200 flex items-center gap-1.5">
                      <ShieldAlert className="h-3.5 w-3.5 text-amber-500 dark:text-amber-400" />
                      Simulated Attachment Analysis
                    </span>
                    <span className="text-[10px] text-zinc-400 font-mono">ID: {att.id}</span>
                  </div>

                  {/* Findings */}
                  <div>
                    <p className="text-[11px] font-semibold text-zinc-500 dark:text-zinc-400 mb-1.5 uppercase tracking-wider">
                      Detected Attachment Indicators:
                    </p>
                    <ul className="space-y-1">
                      {att.findings.map((f, i) => (
                        <li key={i} className="flex items-center gap-2 text-xs text-zinc-700 dark:text-zinc-300">
                          <span className="h-1.5 w-1.5 rounded-full bg-red-500 dark:bg-red-400 shrink-0" />
                          <span>{f}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Recommendation */}
                  <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900/60 p-2.5">
                    <p className="text-[11px] font-semibold text-zinc-700 dark:text-zinc-300 flex items-center gap-1.5">
                      <Info className="h-3.5 w-3.5 text-blue-500 dark:text-blue-400" />
                      Recommendation
                    </p>
                    <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">{att.recommendation}</p>
                  </div>

                  {/* Safety Note */}
                  <p className="text-[10px] text-zinc-500 italic">
                    Attachments are shown as simulated scans in this prototype. Real file sandboxing will be added in a later phase.
                  </p>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
