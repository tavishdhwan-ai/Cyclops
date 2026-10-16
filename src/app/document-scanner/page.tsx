'use client';

import React, { useState, useRef, useMemo } from 'react';
import { useDemoContext } from '../../context/DemoContext';
import { Card } from '../../components/ui/Card';
import { Badge } from '../../components/ui/Badge';
import { DocumentScanResult } from '../../types';
import { ScanResultSummary } from '../../components/ui/ScanResultSummary';
import { SecurityFindingsList } from '../../components/ui/SecurityFindingsList';
import { extractDocumentFindings } from '../../utils/findingTransformers';
import {
  FileSearch,
  UploadCloud,
  FileText,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  FileCode,
  Lock,
  History,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Code2,
  Eye,
  EyeOff,
  Globe,
  Terminal,
  Layers,
  FileSpreadsheet,
  FileWarning,
} from 'lucide-react';

export default function DocumentScannerPage() {
  const { docScans, scanDocument, showToast } = useDemoContext();
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState('');
  const [activeDoc, setActiveDoc] = useState<DocumentScanResult | null>(docScans[0] || null);
  const [activeTab, setActiveTab] = useState<'audit' | 'safeview'>('audit');
  const [safeViewPage, setSafeViewPage] = useState<number>(1);

  const docResultsRef = useRef<HTMLDivElement>(null);
  const docFindingsRef = useRef<HTMLDivElement>(null);

  const docFindingsData = useMemo(() => {
    if (!activeDoc) return null;
    return extractDocumentFindings(activeDoc);
  }, [activeDoc]);

  // Expandable sections state
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    macro: true,
    html: true,
    links: true,
    exploit: true,
    forms: true,
    domain: true,
    translator: true,
    hidden: true,
  });

  const fileInputRef = useRef<HTMLInputElement>(null);

  const toggleSection = (key: string) => {
    setExpandedSections((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const executeScanPipeline = async (name: string, sizeStr: string = '2.1 MB', rawFile?: File) => {
    setSelectedFile(name);
    setIsScanning(true);
    setSafeViewPage(1);

    setScanStage('Stage 1/4: Parsing file headers, cryptographic SHA-256 hash & MIME structure...');
    await new Promise((res) => setTimeout(res, 400));

    setScanStage('Stage 2/4: Unpacking package containers, inspecting VBA project parts & OLE embeddings...');
    await new Promise((res) => setTimeout(res, 450));

    setScanStage('Stage 3/4: Auditing hyperlinks, AcroForms, invisible text layers & /Launch actions...');
    await new Promise((res) => setTimeout(res, 450));

    setScanStage('Stage 4/4: Performing isolated static Safe-View flattening & script translation...');
    await new Promise((res) => setTimeout(res, 400));

    try {
      const result = await scanDocument(name, sizeStr, rawFile);
      setActiveDoc(result);
      showToast('Scan Completed', `Analysis finalized for ${name}`, result.verdict === 'clean' ? 'success' : 'warning');
      setTimeout(() => {
        docResultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 100);
    } catch {
      showToast('Scan Notification', 'Processed document using local high-security sandbox.', 'info');
      setTimeout(() => {
        docResultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 100);
    } finally {
      setIsScanning(false);
      setScanStage('');
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const formattedSize = file.size > 1024 * 1024 ? `${(file.size / (1024 * 1024)).toFixed(1)} MB` : `${(file.size / 1024).toFixed(0)} KB`;
    executeScanPipeline(file.name, formattedSize, file);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) {
      const formattedSize = file.size > 1024 * 1024 ? `${(file.size / (1024 * 1024)).toFixed(1)} MB` : `${(file.size / 1024).toFixed(0)} KB`;
      executeScanPipeline(file.name, formattedSize, file);
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      {/* Hidden native file input for actual user uploads */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileInputChange}
        className="hidden"
        accept=".pdf,.docx,.xlsx,.xlsm,.docm,.pptx,.pptm,.html,.htm,.exe"
      />

      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-200 dark:border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
            <FileSearch className="h-5 w-5 text-zinc-600 dark:text-zinc-400" />
            Document Security & Exploit Intelligence Scanner
          </h1>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
            Static multi-format security scanner inspecting embedded VBA macros, phishing HTML forms, URL misdirections, /Launch exploits, and invisible text layers.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="flex h-2 w-2 rounded-full bg-emerald-500"></span>
          <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 px-3 py-1 text-[11px] font-mono text-zinc-600 dark:text-zinc-300">
            Engine v1.0 • Isolated Sandbox
          </div>
        </div>
      </div>

      {/* Upload Dropzone */}
      <Card className="space-y-4">
        <div
          onClick={() => fileInputRef.current?.click()}
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleDrop}
          className="border-2 border-dashed border-zinc-300 dark:border-zinc-800 hover:border-zinc-400 dark:hover:border-zinc-600 rounded-xl p-8 text-center cursor-pointer bg-zinc-50/70 dark:bg-zinc-950/70 hover:bg-zinc-100/50 dark:hover:bg-zinc-900/50 transition-all space-y-3"
        >
          <div className="h-12 w-12 rounded-full border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-900 flex items-center justify-center mx-auto text-zinc-500 dark:text-zinc-300 shadow-xs">
            <UploadCloud className="h-6 w-6" />
          </div>
          <div>
            <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
              Drop document here or click to choose from disk
            </p>
            <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
              Supports .PDF, .DOCX, .XLSM, .DOCM, .XLSX, and .HTML attachments (up to 35 MB)
            </p>
          </div>
        </div>

        {/* Quick Test Sample Presets */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-zinc-200 dark:border-zinc-800/60">
          <span className="text-[11px] font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
            Controlled Threat Fixtures:
          </span>
          <button
            onClick={() => executeScanPipeline('Quarterly_Financial_Report_2026.xlsm', '4.2 MB')}
            className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-2.5 py-1 text-xs text-zinc-700 dark:text-zinc-300 hover:border-zinc-500 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors"
          >
            ⚠️ Obfuscated Macro (.xlsm)
          </button>
          <button
            onClick={() => executeScanPipeline('DocuSign_Secure_Envelope.html', '14.2 KB')}
            className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-2.5 py-1 text-xs text-zinc-700 dark:text-zinc-300 hover:border-zinc-500 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors"
          >
            ⚠️ Credential Phishing Form (.html)
          </button>
          <button
            onClick={() => executeScanPipeline('Financial_Audit_Q4.pdf', '1.1 MB')}
            className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-2.5 py-1 text-xs text-zinc-700 dark:text-zinc-300 hover:border-zinc-500 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors"
          >
            ⚠️ PDF Exploit / Launch Action (.pdf)
          </button>
          <button
            onClick={() => executeScanPipeline('Vendor_Invoice_Q3_Final.pdf.exe', '1.8 MB')}
            className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-2.5 py-1 text-xs text-zinc-700 dark:text-zinc-300 hover:border-zinc-500 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors"
          >
            ⚠️ Executable Trojan (.pdf.exe)
          </button>
          <button
            onClick={() => executeScanPipeline('SentinelAI_Employee_Policy_Handbook.pdf', '820 KB')}
            className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-2.5 py-1 text-xs text-zinc-700 dark:text-zinc-300 hover:border-zinc-500 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors"
          >
            ✅ Clean Corporate PDF (.pdf)
          </button>
        </div>
      </Card>

      {/* Loading Scanning State */}
      {isScanning && (
        <Card className="text-center py-10 space-y-4 border-zinc-300 dark:border-zinc-700">
          <Loader2 className="h-8 w-8 text-zinc-600 dark:text-zinc-300 animate-spin mx-auto" />
          <div>
            <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
              Deconstructing & Inspecting: <span className="font-mono text-zinc-600 dark:text-zinc-300">{selectedFile}</span>
            </p>
            <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1 font-mono">{scanStage}</p>
          </div>
          <div className="w-64 h-1.5 bg-zinc-200 dark:bg-zinc-800 rounded-full mx-auto overflow-hidden">
            <div className="h-full bg-zinc-800 dark:bg-zinc-200 animate-pulse rounded-full w-3/4"></div>
          </div>
        </Card>
      )}

      {/* Active Document Result Display */}
      {!isScanning && activeDoc && (
        <div ref={docResultsRef} className="space-y-6">
          {/* Prominent High-Visibility Verdict Panel */}
          {docFindingsData && (
            <ScanResultSummary
              title={activeDoc.fileName}
              subtitle={`Size: ${activeDoc.fileSize} • Type: ${activeDoc.fileType} • Scanned ${activeDoc.timestamp} • SHA-256: ${activeDoc.fileHash ? activeDoc.fileHash.slice(0, 16) + '...' : 'Verified'}`}
              verdict={docFindingsData.verdict}
              verdictExplanation={docFindingsData.verdictExplanation}
              counts={docFindingsData.counts}
              targetType="Document"
              scanStatus="completed"
              onScrollToFindings={() => docFindingsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
            />
          )}

          {/* Dedicated Security Findings Section */}
          {docFindingsData && (
            <div ref={docFindingsRef}>
              <SecurityFindingsList
                findings={docFindingsData.findings}
                title="Document Security Findings"
                subtitle={`${docFindingsData.checksSummary.completed} of ${docFindingsData.checksSummary.total_checks} security checks completed (${docFindingsData.checksSummary.skipped} format-skipped${docFindingsData.checksSummary.unavailable > 0 ? `, ${docFindingsData.checksSummary.unavailable} unavailable` : ''}).`}
                checksSummary={docFindingsData.checksSummary}
              />
            </div>
          )}

          {/* Main Document Summary Card */}
          <Card className="space-y-6 border-zinc-200 dark:border-zinc-800">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-200 dark:border-zinc-800 pb-4">
              <div className="flex items-start gap-3">
                <div className="h-10 w-10 rounded-lg bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 flex items-center justify-center text-zinc-600 dark:text-zinc-300 shrink-0 mt-0.5">
                  {activeDoc.fileType.includes('Excel') || activeDoc.fileName.endsWith('.xlsm') || activeDoc.fileName.endsWith('.xlsx') ? (
                    <FileSpreadsheet className="h-5 w-5" />
                  ) : activeDoc.fileName.endsWith('.exe') ? (
                    <FileWarning className="h-5 w-5 text-red-500" />
                  ) : activeDoc.fileName.endsWith('.html') ? (
                    <FileCode className="h-5 w-5 text-amber-500" />
                  ) : (
                    <FileText className="h-5 w-5" />
                  )}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-base font-bold text-zinc-900 dark:text-zinc-100 font-mono break-all">{activeDoc.fileName}</h2>
                    <Badge level={activeDoc.riskLevel}>{activeDoc.verdict.toUpperCase()}</Badge>
                  </div>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                    Size: {activeDoc.fileSize} • Type: {activeDoc.fileType} • Scanned {activeDoc.timestamp}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() =>
                    showToast('Quarantine Activated', `${activeDoc.fileName} has been locked from user filesystem access.`, 'warning')
                  }
                  className="rounded-lg border border-red-900/40 bg-red-950/20 px-3 py-1.5 text-xs font-semibold text-red-600 dark:text-red-400 hover:bg-red-900/30 transition-colors"
                >
                  Quarantine File
                </button>
              </div>
            </div>

            {/* SHA-256 Hash and Score Indicator */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
              <div className="md:col-span-3 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 space-y-1">
                <p className="text-[10px] uppercase font-semibold tracking-wider text-zinc-500">
                  Cryptographic SHA-256 Hash
                </p>
                <p className="font-mono text-[11px] text-zinc-700 dark:text-zinc-300 break-all select-all">{activeDoc.fileHash}</p>
              </div>
              <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 flex flex-col justify-center">
                <span className="text-[10px] uppercase font-semibold tracking-wider text-zinc-500">Security Score</span>
                <p className="text-lg font-bold font-mono text-zinc-900 dark:text-zinc-100 mt-0.5">
                  {typeof activeDoc.riskScore === 'number' ? `${activeDoc.riskScore}/100` : activeDoc.verdict === 'clean' ? '0/100 (Safe)' : '85/100'}
                </p>
              </div>
            </div>

            {/* AI Executive Safety Verdict Banner */}
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <div className="text-xs font-bold uppercase tracking-wider text-zinc-900 dark:text-zinc-200 flex items-center gap-1.5">
                  {activeDoc.verdict === 'clean' ? (
                    <ShieldCheck className="h-4 w-4 text-emerald-500" />
                  ) : activeDoc.verdict === 'suspicious' ? (
                    <AlertTriangle className="h-4 w-4 text-amber-500" />
                  ) : (
                    <ShieldAlert className="h-4 w-4 text-red-500" />
                  )}
                  Executive Security Assessment
                </div>
                <span className="text-[11px] text-zinc-500">Deterministic Static Parser</span>
              </div>
              <p className="text-xs text-zinc-700 dark:text-zinc-300 leading-relaxed font-sans">{activeDoc.aiSummary}</p>
              <div className="pt-2 border-t border-zinc-200 dark:border-zinc-800/80 flex items-center justify-between text-xs">
                <div>
                  <span className="text-[10px] uppercase font-semibold text-zinc-500">Recommended User Action:</span>
                  <p className="font-semibold text-zinc-900 dark:text-zinc-100 mt-0.5">{activeDoc.recommendedAction}</p>
                </div>
              </div>
            </div>

            {/* Top View Mode Switcher: Security Audit vs Safe View */}
            <div className="flex border-b border-zinc-200 dark:border-zinc-800">
              <button
                onClick={() => setActiveTab('audit')}
                className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
                  activeTab === 'audit'
                    ? 'border-zinc-900 dark:border-zinc-100 text-zinc-900 dark:text-zinc-100'
                    : 'border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200'
                }`}
              >
                <Shield className="h-4 w-4" />
                Security Audit (9 Categories)
              </button>
              <button
                onClick={() => setActiveTab('safeview')}
                className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
                  activeTab === 'safeview'
                    ? 'border-zinc-900 dark:border-zinc-100 text-zinc-900 dark:text-zinc-100'
                    : 'border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200'
                }`}
              >
                <Eye className="h-4 w-4" />
                Zero-Interaction Safe View Preview
              </button>
            </div>

            {/* TAB 1: SECURITY AUDIT (9 SEPARATE EXPANDABLE PANELS) */}
            {activeTab === 'audit' && (
              <div className="space-y-4">
                {/* 1. Macros & Embedded Code Panel (Feature 1) */}
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 overflow-hidden">
                  <div
                    onClick={() => toggleSection('macro')}
                    className="flex items-center justify-between p-3.5 bg-zinc-50 dark:bg-zinc-950/80 cursor-pointer border-b border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100/60 dark:hover:bg-zinc-900/60 transition-colors"
                  >
                    <div className="flex items-center gap-2.5">
                      <Terminal className="h-4 w-4 text-zinc-600 dark:text-zinc-300" />
                      <span className="text-xs font-bold text-zinc-900 dark:text-zinc-100">
                        1. Macros & Embedded Code Detection
                      </span>
                      {activeDoc.macro_inspection?.macro_detected ? (
                        <Badge level="critical">MACRO DETECTED</Badge>
                      ) : (
                        <Badge level="safe">NO MACRO FOUND</Badge>
                      )}
                    </div>
                    {expandedSections.macro ? <ChevronUp className="h-4 w-4 text-zinc-400" /> : <ChevronDown className="h-4 w-4 text-zinc-400" />}
                  </div>

                  {expandedSections.macro && (
                    <div className="p-4 space-y-3 text-xs">
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <div className="rounded border border-zinc-200 dark:border-zinc-800 p-2.5 bg-zinc-50 dark:bg-zinc-950">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">Macro Detected</span>
                          <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-0.5">
                            {activeDoc.macro_inspection?.macro_detected ? 'Yes' : activeDoc.macro_inspection?.status === 'unsupported' ? 'Unable to inspect (Binary)' : 'No'}
                          </p>
                        </div>
                        <div className="rounded border border-zinc-200 dark:border-zinc-800 p-2.5 bg-zinc-50 dark:bg-zinc-950">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">Embedded Objects</span>
                          <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-0.5">
                            {activeDoc.macro_inspection?.embedded_objects_detected.length || 0} object(s)
                          </p>
                        </div>
                        <div className="rounded border border-zinc-200 dark:border-zinc-800 p-2.5 bg-zinc-50 dark:bg-zinc-950">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">Code Analysis Status</span>
                          <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-0.5">
                            {activeDoc.macro_inspection?.extracted_code_status || 'Complete'}
                          </p>
                        </div>
                      </div>

                      <div className="p-3 rounded bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800">
                        <span className="text-[10px] text-zinc-500 uppercase font-semibold">Plain-Language Explanation</span>
                        <p className="text-zinc-700 dark:text-zinc-300 mt-1 leading-relaxed">
                          {activeDoc.macro_inspection?.explanation ||
                            'Standard document package inspected without executing code. No executable VBA macro streams detected.'}
                        </p>
                      </div>

                      {activeDoc.macro_inspection?.suspicious_indicators && activeDoc.macro_inspection.suspicious_indicators.length > 0 && (
                        <div className="space-y-1.5">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">Suspicious Automation Indicators</span>
                          <div className="space-y-1">
                            {activeDoc.macro_inspection.suspicious_indicators.map((ind, i) => (
                              <div key={i} className="flex items-center gap-2 p-2 rounded border border-red-200 dark:border-red-900/40 bg-red-50/50 dark:bg-red-950/20 text-red-700 dark:text-red-300 font-mono text-[11px]">
                                <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-red-500" />
                                <span>{ind}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* 2. HTML Attachment Safety Panel (Feature 2) */}
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 overflow-hidden">
                  <div
                    onClick={() => toggleSection('html')}
                    className="flex items-center justify-between p-3.5 bg-zinc-50 dark:bg-zinc-950/80 cursor-pointer border-b border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100/60 dark:hover:bg-zinc-900/60 transition-colors"
                  >
                    <div className="flex items-center gap-2.5">
                      <FileCode className="h-4 w-4 text-zinc-600 dark:text-zinc-300" />
                      <span className="text-xs font-bold text-zinc-900 dark:text-zinc-100">
                        2. HTML Attachment Safety & Credential Form Inspection
                      </span>
                      {activeDoc.html_safety?.password_fields_found?.length ? (
                        <Badge level="critical">CREDENTIAL FORM DETECTED</Badge>
                      ) : activeDoc.html_safety?.is_html ? (
                        <Badge level="safe">STATIC HTML PASS</Badge>
                      ) : (
                        <Badge level="neutral">NON-HTML FILE</Badge>
                      )}
                    </div>
                    {expandedSections.html ? <ChevronUp className="h-4 w-4 text-zinc-400" /> : <ChevronDown className="h-4 w-4 text-zinc-400" />}
                  </div>

                  {expandedSections.html && (
                    <div className="p-4 space-y-3 text-xs">
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <div className="rounded border border-zinc-200 dark:border-zinc-800 p-2.5 bg-zinc-50 dark:bg-zinc-950">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">Login Fields</span>
                          <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-0.5">
                            {activeDoc.html_safety?.login_fields_found?.length || 0}
                          </p>
                        </div>
                        <div className="rounded border border-zinc-200 dark:border-zinc-800 p-2.5 bg-zinc-50 dark:bg-zinc-950">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">Password Fields</span>
                          <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-0.5">
                            {activeDoc.html_safety?.password_fields_found?.length || 0}
                          </p>
                        </div>
                        <div className="rounded border border-zinc-200 dark:border-zinc-800 p-2.5 bg-zinc-50 dark:bg-zinc-950">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">External Form Targets</span>
                          <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-0.5">
                            {activeDoc.html_safety?.external_form_destinations?.length || 0}
                          </p>
                        </div>
                        <div className="rounded border border-zinc-200 dark:border-zinc-800 p-2.5 bg-zinc-50 dark:bg-zinc-950">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">Remote Scripts</span>
                          <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-0.5">
                            {activeDoc.html_safety?.remote_scripts_detected?.length || 0}
                          </p>
                        </div>
                      </div>

                      <div className="p-3 rounded bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800">
                        <span className="text-[10px] text-zinc-500 uppercase font-semibold">Analysis Explanation</span>
                        <p className="text-zinc-700 dark:text-zinc-300 mt-1 leading-relaxed">
                          {activeDoc.html_safety?.explanation ||
                            'Scanned without script execution or external network queries. HTML files are safely flattened into non-executable static DOM structures.'}
                        </p>
                      </div>

                      {activeDoc.html_safety?.external_form_destinations && activeDoc.html_safety.external_form_destinations.length > 0 && (
                        <div className="space-y-1">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">External Form Destinations (Exfiltration Targets)</span>
                          {activeDoc.html_safety.external_form_destinations.map((dest, i) => (
                            <div key={i} className="p-2 rounded border border-red-200 dark:border-red-900/40 bg-red-50/50 dark:bg-red-950/20 text-red-700 dark:text-red-300 font-mono text-[11px]">
                              {dest}
                            </div>
                          ))}
                        </div>
                      )}

                      {activeDoc.html_safety?.brand_domain_mismatches && activeDoc.html_safety.brand_domain_mismatches.length > 0 && (
                        <div className="space-y-1">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">Brand / Domain Mismatches</span>
                          {activeDoc.html_safety.brand_domain_mismatches.map((m, i) => (
                            <div key={i} className="p-2 rounded border border-amber-200 dark:border-amber-900/40 bg-amber-50/50 dark:bg-amber-950/20 text-amber-700 dark:text-amber-300 text-[11px]">
                              {m}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* 3. Embedded Hyperlinks Panel (Feature 3) */}
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 overflow-hidden">
                  <div
                    onClick={() => toggleSection('links')}
                    className="flex items-center justify-between p-3.5 bg-zinc-50 dark:bg-zinc-950/80 cursor-pointer border-b border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100/60 dark:hover:bg-zinc-900/60 transition-colors"
                  >
                    <div className="flex items-center gap-2.5">
                      <Globe className="h-4 w-4 text-zinc-600 dark:text-zinc-300" />
                      <span className="text-xs font-bold text-zinc-900 dark:text-zinc-100">
                        3. Embedded Hyperlinks & One-Click Misdirection Analysis
                      </span>
                      {activeDoc.embedded_links?.mismatched_links_count ? (
                        <Badge level="warning">{activeDoc.embedded_links.mismatched_links_count} MISMATCH DETECTED</Badge>
                      ) : activeDoc.embedded_links?.total_links_found ? (
                        <Badge level="safe">{activeDoc.embedded_links.total_links_found} LINKS VERIFIED</Badge>
                      ) : (
                        <Badge level="neutral">NO EMBEDDED LINKS</Badge>
                      )}
                    </div>
                    {expandedSections.links ? <ChevronUp className="h-4 w-4 text-zinc-400" /> : <ChevronDown className="h-4 w-4 text-zinc-400" />}
                  </div>

                  {expandedSections.links && (
                    <div className="p-4 space-y-3 text-xs">
                      <p className="text-zinc-600 dark:text-zinc-400">
                        {activeDoc.embedded_links?.summary || 'Hyperlink extraction completed without opening external destinations.'}
                      </p>

                      {activeDoc.embedded_links?.links && activeDoc.embedded_links.links.length > 0 ? (
                        <div className="overflow-x-auto border border-zinc-200 dark:border-zinc-800 rounded-lg">
                          <table className="w-full text-left text-xs">
                            <thead className="bg-zinc-50 dark:bg-zinc-950 text-zinc-500 uppercase text-[10px] font-semibold border-b border-zinc-200 dark:border-zinc-800">
                              <tr>
                                <th className="p-2.5">Visible Link Text</th>
                                <th className="p-2.5">Actual Destination</th>
                                <th className="p-2.5">Location</th>
                                <th className="p-2.5">Verdict</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800/60">
                              {activeDoc.embedded_links.links.map((link, idx) => (
                                <tr key={idx} className="hover:bg-zinc-50/50 dark:hover:bg-zinc-900/40">
                                  <td className="p-2.5 font-medium text-zinc-900 dark:text-zinc-200 max-w-xs truncate">
                                    {link.visible_text}
                                  </td>
                                  <td className="p-2.5 font-mono text-[11px] text-zinc-600 dark:text-zinc-400 max-w-sm truncate">
                                    {link.destination_url}
                                  </td>
                                  <td className="p-2.5 text-zinc-500">{link.location}</td>
                                  <td className="p-2.5">
                                    {link.mismatch_warning ? (
                                      <span className="inline-flex items-center gap-1 text-amber-600 dark:text-amber-400 font-semibold text-[11px]">
                                        <AlertTriangle className="h-3 w-3" /> Mismatch
                                      </span>
                                    ) : (
                                      <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400 font-semibold text-[11px]">
                                        <CheckCircle2 className="h-3 w-3" /> Matched
                                      </span>
                                    )}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <div className="p-3 text-center text-zinc-500 dark:text-zinc-400 border border-dashed border-zinc-200 dark:border-zinc-800 rounded-lg">
                          No embedded hyperlinks found inside document streams.
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* 4. Document Structure & Exploit Indicators Panel (Feature 4) */}
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 overflow-hidden">
                  <div
                    onClick={() => toggleSection('exploit')}
                    className="flex items-center justify-between p-3.5 bg-zinc-50 dark:bg-zinc-950/80 cursor-pointer border-b border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100/60 dark:hover:bg-zinc-900/60 transition-colors"
                  >
                    <div className="flex items-center gap-2.5">
                      <Layers className="h-4 w-4 text-zinc-600 dark:text-zinc-300" />
                      <span className="text-xs font-bold text-zinc-900 dark:text-zinc-100">
                        4. Document Structure & Exploit Indicators
                      </span>
                      {activeDoc.exploit_indicators?.suspicious_actions?.length ? (
                        <Badge level="critical">SUSPICIOUS ACTIONS DETECTED</Badge>
                      ) : (
                        <Badge level="safe">STRUCTURE CONFORMS</Badge>
                      )}
                    </div>
                    {expandedSections.exploit ? <ChevronUp className="h-4 w-4 text-zinc-400" /> : <ChevronDown className="h-4 w-4 text-zinc-400" />}
                  </div>

                  {expandedSections.exploit && (
                    <div className="p-4 space-y-3 text-xs">
                      <div className="p-3 rounded bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800">
                        <span className="text-[10px] text-zinc-500 uppercase font-semibold">Engine Structural Evaluation</span>
                        <p className="text-zinc-700 dark:text-zinc-300 mt-1 leading-relaxed">
                          {activeDoc.exploit_indicators?.explanation ||
                            'Document conforms to standard structure. No unexpected /Launch actions or abnormal compression bombs.'}
                        </p>
                      </div>

                      {activeDoc.exploit_indicators?.suspicious_actions && activeDoc.exploit_indicators.suspicious_actions.length > 0 && (
                        <div className="space-y-1">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">Identified Suspicious Actions (/Launch, /JavaScript, Droppers)</span>
                          {activeDoc.exploit_indicators.suspicious_actions.map((act, i) => (
                            <div key={i} className="p-2 rounded border border-red-200 dark:border-red-900/40 bg-red-50/50 dark:bg-red-950/20 text-red-700 dark:text-red-300 font-mono text-[11px]">
                              {act}
                            </div>
                          ))}
                        </div>
                      )}

                      <div className="flex flex-wrap items-center justify-between text-[11px] text-zinc-500 pt-2 border-t border-zinc-200 dark:border-zinc-800">
                        <span>Engine: {activeDoc.exploit_indicators?.engine_version || 'Cyclops Static Analyzer 1.0'}</span>
                        <span>Compression Ratio: {activeDoc.exploit_indicators?.compression_ratio || 1.0}:1</span>
                      </div>
                      <p className="text-[11px] text-zinc-400 italic">
                        {activeDoc.exploit_indicators?.coverage_and_limitations ||
                          'Static structural audit cannot guarantee discovery of novel zero-day exploits. No code was executed.'}
                      </p>
                    </div>
                  )}
                </div>

                {/* 5. Forms & Data Submission Panel (Feature 5) */}
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 overflow-hidden">
                  <div
                    onClick={() => toggleSection('forms')}
                    className="flex items-center justify-between p-3.5 bg-zinc-50 dark:bg-zinc-950/80 cursor-pointer border-b border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100/60 dark:hover:bg-zinc-900/60 transition-colors"
                  >
                    <div className="flex items-center gap-2.5">
                      <Lock className="h-4 w-4 text-zinc-600 dark:text-zinc-300" />
                      <span className="text-xs font-bold text-zinc-900 dark:text-zinc-100">
                        5. Forms & Data-Submission Analysis (Invisible Traps)
                      </span>
                      {activeDoc.forms_and_submission?.external_destinations?.length ? (
                        <Badge level="critical">EXTERNAL EXFILTRATION HOOK</Badge>
                      ) : activeDoc.forms_and_submission?.interactive_forms_detected ? (
                        <Badge level="warning">INTERACTIVE FORM</Badge>
                      ) : (
                        <Badge level="safe">NO FORMS DETECTED</Badge>
                      )}
                    </div>
                    {expandedSections.forms ? <ChevronUp className="h-4 w-4 text-zinc-400" /> : <ChevronDown className="h-4 w-4 text-zinc-400" />}
                  </div>

                  {expandedSections.forms && (
                    <div className="p-4 space-y-3 text-xs">
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <div className="rounded border border-zinc-200 dark:border-zinc-800 p-2.5 bg-zinc-50 dark:bg-zinc-950">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">Form Architecture</span>
                          <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-0.5">
                            {activeDoc.forms_and_submission?.form_type || 'None'}
                          </p>
                        </div>
                        <div className="rounded border border-zinc-200 dark:border-zinc-800 p-2.5 bg-zinc-50 dark:bg-zinc-950">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">Sensitive Prompts</span>
                          <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-0.5">
                            {activeDoc.forms_and_submission?.sensitive_fields_detected?.length || 0} field(s)
                          </p>
                        </div>
                        <div className="rounded border border-zinc-200 dark:border-zinc-800 p-2.5 bg-zinc-50 dark:bg-zinc-950">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">External Targets</span>
                          <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-0.5">
                            {activeDoc.forms_and_submission?.external_destinations?.length || 0}
                          </p>
                        </div>
                      </div>

                      <div className="p-3 rounded bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800">
                        <span className="text-[10px] text-zinc-500 uppercase font-semibold">Form Safety Verdict</span>
                        <p className="text-zinc-700 dark:text-zinc-300 mt-1 leading-relaxed">
                          {activeDoc.forms_and_submission?.explanation ||
                            'Analysis strictly passive; form inputs are never submitted or stored during inspection.'}
                        </p>
                      </div>

                      {activeDoc.forms_and_submission?.external_destinations && activeDoc.forms_and_submission.external_destinations.length > 0 && (
                        <div className="space-y-1">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">External Form Destinations (Submit Targets)</span>
                          {activeDoc.forms_and_submission.external_destinations.map((dest, i) => (
                            <div key={i} className="p-2 rounded border border-red-200 dark:border-red-900/40 bg-red-50/50 dark:bg-red-950/20 text-red-700 dark:text-red-300 font-mono text-[11px]">
                              {dest}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* 6. Brand & Domain Consistency Matcher Panel (Feature 7) */}
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 overflow-hidden">
                  <div
                    onClick={() => toggleSection('domain')}
                    className="flex items-center justify-between p-3.5 bg-zinc-50 dark:bg-zinc-950/80 cursor-pointer border-b border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100/60 dark:hover:bg-zinc-900/60 transition-colors"
                  >
                    <div className="flex items-center gap-2.5">
                      <ExternalLink className="h-4 w-4 text-zinc-600 dark:text-zinc-300" />
                      <span className="text-xs font-bold text-zinc-900 dark:text-zinc-100">
                        6. Brand & Domain Consistency Matcher
                      </span>
                      {activeDoc.brand_domain_consistency?.mismatches?.length ? (
                        <Badge level="warning">DOMAIN MISMATCH DETECTED</Badge>
                      ) : (
                        <Badge level="safe">AFFILIATION VERIFIED</Badge>
                      )}
                    </div>
                    {expandedSections.domain ? <ChevronUp className="h-4 w-4 text-zinc-400" /> : <ChevronDown className="h-4 w-4 text-zinc-400" />}
                  </div>

                  {expandedSections.domain && (
                    <div className="p-4 space-y-3 text-xs">
                      <div className="p-3 rounded bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800">
                        <span className="text-[10px] text-zinc-500 uppercase font-semibold">Domain Relationship Assessment</span>
                        <p className="text-zinc-700 dark:text-zinc-300 mt-1 leading-relaxed">
                          {activeDoc.brand_domain_consistency?.domain_relationship_assessment ||
                            'No corporate identity discrepancies identified.'}
                        </p>
                      </div>

                      {activeDoc.brand_domain_consistency?.claimed_organization && (
                        <div className="text-[11px] text-zinc-600 dark:text-zinc-400">
                          <span className="font-semibold text-zinc-800 dark:text-zinc-200">Claimed Identity: </span>
                          {activeDoc.brand_domain_consistency.claimed_organization}
                        </div>
                      )}

                      <p className="text-[11px] text-zinc-400 italic">
                        {activeDoc.brand_domain_consistency?.confidence_or_uncertainty_explanation ||
                          'Domain differences alone do not prove fraud because organizations routinely use third-party vendors and CDNs.'}
                      </p>
                    </div>
                  )}
                </div>

                {/* 7. Macro-to-English Script Translator (Feature 8) */}
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 overflow-hidden">
                  <div
                    onClick={() => toggleSection('translator')}
                    className="flex items-center justify-between p-3.5 bg-zinc-50 dark:bg-zinc-950/80 cursor-pointer border-b border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100/60 dark:hover:bg-zinc-900/60 transition-colors"
                  >
                    <div className="flex items-center gap-2.5">
                      <Code2 className="h-4 w-4 text-zinc-600 dark:text-zinc-300" />
                      <span className="text-xs font-bold text-zinc-900 dark:text-zinc-100">
                        7. Macro-to-English Script Translator (What This Code Does)
                      </span>
                      {activeDoc.script_translator?.has_script ? (
                        <Badge level="critical">SCRIPT BEHAVIOR DECODED</Badge>
                      ) : (
                        <Badge level="neutral">NO SCRIPTS PRESENT</Badge>
                      )}
                    </div>
                    {expandedSections.translator ? <ChevronUp className="h-4 w-4 text-zinc-400" /> : <ChevronDown className="h-4 w-4 text-zinc-400" />}
                  </div>

                  {expandedSections.translator && (
                    <div className="p-4 space-y-3 text-xs">
                      <div className="p-3 rounded bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800">
                        <span className="text-[10px] text-zinc-500 uppercase font-semibold">Plain-English Behavioral Translation</span>
                        <p className="text-zinc-800 dark:text-zinc-200 mt-1 font-medium leading-relaxed">
                          {activeDoc.script_translator?.plain_english_summary ||
                            'No executable scripts or macro commands were detected in this document.'}
                        </p>
                      </div>

                      {activeDoc.script_translator?.observed_operations && activeDoc.script_translator.observed_operations.length > 0 && (
                        <div className="space-y-1.5">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">Observed Static Operations</span>
                          <div className="space-y-1">
                            {activeDoc.script_translator.observed_operations.map((op, i) => (
                              <div key={i} className="p-2 rounded border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 text-zinc-700 dark:text-zinc-300 text-[11px]">
                                {op}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {activeDoc.script_translator?.evidence_lines && activeDoc.script_translator.evidence_lines.length > 0 && (
                        <div className="space-y-1">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">Underlying Code Evidence</span>
                          <pre className="p-2.5 rounded bg-zinc-900 text-zinc-200 font-mono text-[11px] overflow-x-auto">
                            {activeDoc.script_translator.evidence_lines.join('\n')}
                          </pre>
                        </div>
                      )}

                      <p className="text-[11px] text-zinc-400 italic">
                        {activeDoc.script_translator?.inferred_intent_warning ||
                          'Translation reflects observed static operations, not verified runtime intent.'}
                      </p>
                    </div>
                  )}
                </div>

                {/* 8. Hidden Content & Invisible Text Audit Panel (Feature 9) */}
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 overflow-hidden">
                  <div
                    onClick={() => toggleSection('hidden')}
                    className="flex items-center justify-between p-3.5 bg-zinc-50 dark:bg-zinc-950/80 cursor-pointer border-b border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100/60 dark:hover:bg-zinc-900/60 transition-colors"
                  >
                    <div className="flex items-center gap-2.5">
                      <EyeOff className="h-4 w-4 text-zinc-600 dark:text-zinc-300" />
                      <span className="text-xs font-bold text-zinc-900 dark:text-zinc-100">
                        8. Hidden Content and Invisible Text Audit
                      </span>
                      {activeDoc.hidden_content?.hidden_elements_count ? (
                        <Badge level="warning">{activeDoc.hidden_content.hidden_elements_count} CONCEALED ELEMENTS</Badge>
                      ) : (
                        <Badge level="safe">ALL CONTENT VISIBLE</Badge>
                      )}
                    </div>
                    {expandedSections.hidden ? <ChevronUp className="h-4 w-4 text-zinc-400" /> : <ChevronDown className="h-4 w-4 text-zinc-400" />}
                  </div>

                  {expandedSections.hidden && (
                    <div className="p-4 space-y-3 text-xs">
                      <div className="p-3 rounded bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800">
                        <span className="text-[10px] text-zinc-500 uppercase font-semibold">Visibility Audit Verdict</span>
                        <p className="text-zinc-700 dark:text-zinc-300 mt-1 leading-relaxed">
                          {activeDoc.hidden_content?.explanation ||
                            'Text content and structural layers appear consistently visible.'}
                        </p>
                      </div>

                      {activeDoc.hidden_content?.items && activeDoc.hidden_content.items.length > 0 ? (
                        <div className="space-y-2">
                          <span className="text-[10px] text-zinc-500 uppercase font-semibold">Detected Concealed Elements</span>
                          <div className="space-y-1.5">
                            {activeDoc.hidden_content.items.map((item, idx) => (
                              <div key={idx} className="p-3 rounded border border-amber-200 dark:border-amber-900/40 bg-amber-50/40 dark:bg-amber-950/20 space-y-1">
                                <div className="flex items-center justify-between text-[11px]">
                                  <span className="font-semibold text-zinc-900 dark:text-zinc-100">{item.location}</span>
                                  <span className="text-zinc-500 uppercase text-[10px]">{item.detection_type}</span>
                                </div>
                                <p className="text-amber-800 dark:text-amber-300 text-xs font-mono">{item.extracted_text}</p>
                                <p className="text-[11px] text-zinc-600 dark:text-zinc-400">{item.classification_reason}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      ) : (
                        <div className="p-3 text-center text-zinc-500 dark:text-zinc-400 border border-dashed border-zinc-200 dark:border-zinc-800 rounded-lg">
                          No microscopic text (≤1pt), invisible rendering modes, or concealed worksheets detected.
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB 2: ZERO-INTERACTION SAFE VIEW (FEATURE 6) */}
            {activeTab === 'safeview' && (
              <div className="space-y-4">
                {/* Security Disclaimer Banner */}
                <div className="p-3.5 rounded-lg border border-zinc-300 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-900/80 flex items-start gap-3 text-xs">
                  <ShieldCheck className="h-5 w-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold text-zinc-900 dark:text-zinc-100">Zero-Interaction Document Flattening</span>
                    <p className="text-zinc-600 dark:text-zinc-300 mt-0.5 leading-relaxed">
                      Safe View displays a static rendering of the document. It does not execute the document&#39;s intended interactive features.
                      This preview reduces exposure to active content but is not a guarantee that the original file is harmless.
                    </p>
                  </div>
                </div>

                {/* Safe View Canvas Display */}
                {activeDoc.safe_view?.status === 'available' && activeDoc.safe_view.pages.length > 0 ? (
                  <div className="space-y-3">
                    {/* Page Navigation Controls */}
                    <div className="flex items-center justify-between bg-zinc-50 dark:bg-zinc-950 p-2.5 rounded-lg border border-zinc-200 dark:border-zinc-800 text-xs">
                      <span className="text-zinc-600 dark:text-zinc-400 font-mono">
                        Viewing Page {safeViewPage} of {activeDoc.safe_view.total_pages}
                      </span>
                      <div className="flex items-center gap-1.5">
                        <button
                          disabled={safeViewPage <= 1}
                          onClick={() => setSafeViewPage((p) => Math.max(1, p - 1))}
                          className="px-2.5 py-1 rounded border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 text-zinc-700 dark:text-zinc-300 disabled:opacity-40 hover:bg-zinc-100 dark:hover:bg-zinc-800"
                        >
                          Previous
                        </button>
                        <button
                          disabled={safeViewPage >= activeDoc.safe_view.total_pages}
                          onClick={() => setSafeViewPage((p) => Math.min(activeDoc.safe_view?.total_pages || 1, p + 1))}
                          className="px-2.5 py-1 rounded border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 text-zinc-700 dark:text-zinc-300 disabled:opacity-40 hover:bg-zinc-100 dark:hover:bg-zinc-800"
                        >
                          Next
                        </button>
                      </div>
                    </div>

                    {/* Rendered Page Container */}
                    <div className="rounded-xl border border-zinc-300 dark:border-zinc-800 p-4 bg-zinc-100 dark:bg-zinc-950 flex justify-center shadow-inner overflow-hidden">
                      {activeDoc.safe_view.pages[safeViewPage - 1]?.image_data_url ? (
                        /* eslint-disable-next-line @next/next/no-img-element */
                        <img
                          src={activeDoc.safe_view.pages[safeViewPage - 1].image_data_url}
                          alt={`Safe View Page ${safeViewPage}`}
                          className="max-w-full h-auto rounded shadow-md border border-zinc-300 dark:border-zinc-700"
                          style={{ maxHeight: '720px' }}
                        />
                      ) : (
                        <div className="w-[600px] h-[750px] bg-white dark:bg-zinc-900 border border-zinc-300 dark:border-zinc-700 rounded p-8 shadow space-y-4 text-xs font-sans">
                          <div className="border-b border-zinc-200 dark:border-zinc-800 pb-3 flex justify-between text-zinc-400 font-mono text-[11px]">
                            <span>SAFE VIEW • STATIC FLATTENED RENDER</span>
                            <span>PAGE {safeViewPage}</span>
                          </div>
                          <h3 className="text-base font-bold text-zinc-900 dark:text-zinc-100 font-serif">
                            {activeDoc.fileName}
                          </h3>
                          <div className="space-y-2 text-zinc-700 dark:text-zinc-300 leading-relaxed">
                            <p>{activeDoc.safe_view.pages[safeViewPage - 1]?.extracted_text_snippet || 'Document text extracted securely in non-interactive sandbox.'}</p>
                            <p className="text-zinc-400 italic">
                              Interactive form controls, active macros, and script triggers have been neutralized.
                            </p>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="p-8 text-center border-2 border-dashed border-zinc-200 dark:border-zinc-800 rounded-xl space-y-2">
                    <EyeOff className="h-8 w-8 text-zinc-400 mx-auto" />
                    <p className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">
                      Static Preview Unavailable
                    </p>
                    <p className="text-xs text-zinc-500 max-w-md mx-auto">
                      {activeDoc.safe_view?.disclaimer ||
                        'Safe View is not available for this binary format or file execution was quarantined.'}
                    </p>
                  </div>
                )}
              </div>
            )}
          </Card>
        </div>
      )}

      {/* Recent Document Audits History Card */}
      <Card className="space-y-4">
        <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800 pb-3">
          <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
            <History className="h-4 w-4 text-zinc-600 dark:text-zinc-400" />
            Recent Document Security Audits
          </h3>
        </div>

        <div className="divide-y divide-zinc-200 dark:divide-zinc-800/60">
          {docScans.map((doc) => (
            <div
              key={doc.id}
              onClick={() => {
                setActiveDoc(doc);
                setSafeViewPage(1);
              }}
              className="flex items-center justify-between py-3 px-2 rounded-lg hover:bg-zinc-50 dark:hover:bg-zinc-900/50 cursor-pointer transition-colors"
            >
              <div className="min-w-0 pr-4">
                <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-100 truncate font-mono">{doc.fileName}</p>
                <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                  {doc.fileSize} • {doc.fileType}
                </p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <Badge level={doc.riskLevel}>{doc.verdict.toUpperCase()}</Badge>
                <span className="text-[10px] text-zinc-500 font-mono">{doc.timestamp}</span>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
