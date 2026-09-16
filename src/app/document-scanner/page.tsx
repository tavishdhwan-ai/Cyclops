'use client';

import React, { useState } from 'react';
import { useDemoContext } from '../../context/DemoContext';
import { Card } from '../../components/ui/Card';
import { Badge } from '../../components/ui/Badge';
import { DocumentScanResult } from '../../types';
import {
  FileSearch,
  UploadCloud,
  FileText,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  FileCode,
  Lock,
  Download,
  History,
} from 'lucide-react';

export default function DocumentScannerPage() {
  const { docScans, scanDocument, showToast } = useDemoContext();
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState('');
  const [activeDoc, setActiveDoc] = useState<DocumentScanResult | null>(docScans[0] || null);

  const handleSimulatedUpload = async (fileName: string, fileSize: string = '2.1 MB') => {
    setSelectedFile(fileName);
    setIsScanning(true);

    setScanStage('Calculating SHA-256 hash & inspecting headers...');
    await new Promise((res) => setTimeout(res, 600));

    setScanStage('Decompiling VBA macros & binary payloads...');
    await new Promise((res) => setTimeout(res, 600));

    setScanStage('Cross-checking against global antivirus signatures...');
    await new Promise((res) => setTimeout(res, 600));

    const result = await scanDocument(fileName, fileSize);
    setActiveDoc(result);
    setIsScanning(false);
    setScanStage('');
  };

  const handleDropAreaClick = () => {
    handleSimulatedUpload('Vendor_Invoice_Q3.pdf.exe', '1.8 MB');
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-200 dark:border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
            <FileSearch className="h-5 w-5 text-zinc-500 dark:text-zinc-400" />
            Document Safety & Malicious Macro Scanner
          </h1>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
            Detect hidden VBA scripts, double-extension binaries, and malicious embedded links in email attachments.
          </p>
        </div>
        <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 px-3 py-1 text-[11px] text-zinc-500 dark:text-zinc-400">
          Frontend Sandbox Demo
        </div>
      </div>

      {/* Upload Dropzone Simulation */}
      <Card className="space-y-4">
        <div
          onClick={handleDropAreaClick}
          className="border-2 border-dashed border-zinc-300 dark:border-zinc-800 hover:border-zinc-400 dark:hover:border-zinc-600 rounded-xl p-8 text-center cursor-pointer bg-zinc-50/60 dark:bg-zinc-950/60 hover:bg-zinc-100/40 dark:hover:bg-zinc-900/40 transition-colors space-y-3"
        >
          <div className="h-12 w-12 rounded-full border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-900 flex items-center justify-center mx-auto text-zinc-400 dark:text-zinc-300">
            <UploadCloud className="h-6 w-6" />
          </div>
          <div>
            <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-200">
              Click to simulate document upload or drag & drop files
            </p>
            <p className="text-xs text-zinc-500 mt-0.5">
              Supports .PDF, .DOCX, .XLSM, .ZIP, and .EXE files (up to 50 MB)
            </p>
          </div>
        </div>

        {/* Quick Sample Presets */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-zinc-200 dark:border-zinc-800/60">
          <span className="text-[11px] text-zinc-500 dark:text-zinc-400">Test Sample Files:</span>
          <button
            onClick={() => handleSimulatedUpload('Vendor_Invoice_Q3.pdf.exe', '1.8 MB')}
            className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-2.5 py-1 text-xs text-zinc-600 dark:text-zinc-400 hover:border-zinc-500 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-200"
          >
            ⚠️ Executable Trojan (.pdf.exe)
          </button>
          <button
            onClick={() => handleSimulatedUpload('Quarterly_Report_2026.xlsm', '4.2 MB')}
            className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-2.5 py-1 text-xs text-zinc-600 dark:text-zinc-400 hover:border-zinc-500 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-200"
          >
            ⚠️ Obfuscated Macro (.xlsm)
          </button>
          <button
            onClick={() => handleSimulatedUpload('SentinelAI_Employee_Policy.pdf', '820 KB')}
            className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-2.5 py-1 text-xs text-zinc-600 dark:text-zinc-400 hover:border-zinc-500 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-200"
          >
            ✅ Clean PDF File
          </button>
        </div>
      </Card>

      {/* Loading Scanning State */}
      {isScanning && (
        <Card className="text-center py-8 space-y-3">
          <Loader2 className="h-7 w-7 text-zinc-400 dark:text-zinc-300 animate-spin mx-auto" />
          <div>
            <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-200">
              Deconstructing File: <span className="font-mono text-zinc-500 dark:text-zinc-300">{selectedFile}</span>
            </p>
            <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">{scanStage}</p>
          </div>
        </Card>
      )}

      {/* Active Document Result Display */}
      {!isScanning && activeDoc && (
        <Card className="space-y-6 border-zinc-200 dark:border-zinc-700/60">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-200 dark:border-zinc-800 pb-4">
            <div className="flex items-start gap-3">
              <div className="h-10 w-10 rounded-lg bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 flex items-center justify-center text-zinc-500 dark:text-zinc-300 shrink-0 mt-1">
                <FileText className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-base font-bold text-zinc-900 dark:text-zinc-100 font-mono">{activeDoc.fileName}</h2>
                  <Badge level={activeDoc.riskLevel}>{activeDoc.verdict.toUpperCase()}</Badge>
                </div>
                <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                  Size: {activeDoc.fileSize} • Type: {activeDoc.fileType}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={() =>
                  showToast('Quarantine Activated', `${activeDoc.fileName} isolated from local disk.`, 'warning')
                }
                className="rounded-lg border border-amber-900/50 bg-amber-950/40 px-3 py-1.5 text-xs font-semibold text-amber-300 hover:bg-amber-900/60"
              >
                Quarantine File
              </button>
            </div>
          </div>

          {/* Technical Hash & Properties */}
          <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 space-y-1.5 text-xs">
            <p className="text-[10px] uppercase font-semibold tracking-wider text-zinc-500">
              Cryptographic SHA-256 Hash
            </p>
            <p className="font-mono text-[11px] text-zinc-700 dark:text-zinc-300 break-all">{activeDoc.fileHash}</p>
          </div>

          {/* AI Safety Summary */}
          <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-4 space-y-2">
            <div className="text-xs font-semibold text-zinc-900 dark:text-zinc-200">SentinelAI Safety Verdict</div>
            <p className="text-xs text-zinc-700 dark:text-zinc-300 leading-relaxed">{activeDoc.aiSummary}</p>
          </div>

          {/* Detected Signals */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-zinc-900 dark:text-zinc-300">File Inspection Signals</h3>
            <div className="space-y-1.5">
              {activeDoc.detectedSignals.map((sig, idx) => (
                <div
                  key={idx}
                  className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-2.5 flex items-center justify-between text-xs"
                >
                  <span className="text-zinc-700 dark:text-zinc-300">{sig}</span>
                  <Badge level={activeDoc.riskLevel}>{activeDoc.riskLevel}</Badge>
                </div>
              ))}
            </div>
          </div>

          {/* Action Recommendation */}
          <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 flex items-center justify-between text-xs">
            <div>
              <span className="text-[10px] text-zinc-500 uppercase font-semibold">Recommended Action</span>
              <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-0.5">{activeDoc.recommendedAction}</p>
            </div>
          </div>
        </Card>
      )}

      {/* Recent Scans History */}
      <Card className="space-y-4">
        <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800 pb-3">
          <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
            <History className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            Recent Document Audits
          </h3>
        </div>

        <div className="divide-y divide-zinc-200 dark:divide-zinc-800/60">
          {docScans.map((doc) => (
            <div
              key={doc.id}
              onClick={() => setActiveDoc(doc)}
              className="flex items-center justify-between py-2.5 px-2 rounded-lg hover:bg-zinc-50 dark:hover:bg-zinc-800/40 cursor-pointer transition-colors"
            >
              <div className="min-w-0 pr-4">
                <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-200 truncate font-mono">{doc.fileName}</p>
                <p className="text-[11px] text-zinc-500">
                  {doc.fileSize} • {doc.fileType}
                </p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <Badge level={doc.riskLevel}>{doc.verdict}</Badge>
                <span className="text-[10px] text-zinc-500">{doc.timestamp}</span>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
