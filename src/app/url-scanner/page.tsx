'use client';

import React, { useState, useRef, useMemo } from 'react';
import { useDemoContext } from '../../context/DemoContext';
import { Card } from '../../components/ui/Card';
import { Badge } from '../../components/ui/Badge';
import { UrlScanResult } from '../../types';
import { ScanResultSummary } from '../../components/ui/ScanResultSummary';
import { SecurityFindingsList } from '../../components/ui/SecurityFindingsList';
import { extractUrlFindings } from '../../utils/findingTransformers';
import {
  Globe,
  Search,
  ShieldCheck,
  Loader2,
  AlertTriangle,
  Server,
  Lock,
  ExternalLink,
  History,
  Info,
  CheckCircle2,
  Layers,
  Network,
  CornerDownRight,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  AlertOctagon,
  KeyRound,
  FileDown,
  CheckSquare,
  Building2,
  Calendar,
} from 'lucide-react';

export default function UrlScannerPage() {
  const { urlScans, scanUrl } = useDemoContext();
  const [inputUrl, setInputUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState('');
  const [activeResult, setActiveResult] = useState<UrlScanResult | null>(urlScans[0] || null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  const resultsRef = useRef<HTMLDivElement>(null);
  const findingsRef = useRef<HTMLDivElement>(null);

  const urlFindingsData = useMemo(() => {
    if (!activeResult) return null;
    return extractUrlFindings(activeResult);
  }, [activeResult]);

  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputUrl.trim()) return;

    setIsScanning(true);
    setScanError(null);
    setScanStep('Validating input syntax & normalizing scheme...');

    try {
      const progressTimer = setTimeout(() => {
        setScanStep('Resolving DNS, checking SSL/TLS & enforcing SSRF boundaries...');
      }, 400);

      const progressTimer2 = setTimeout(() => {
        setScanStep('Querying URLhaus threat intelligence & inspecting response headers...');
      }, 900);

      const result = await scanUrl(inputUrl.trim());
      clearTimeout(progressTimer);
      clearTimeout(progressTimer2);

      setActiveResult(result);
      setTimeout(() => {
        resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 100);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Scan failed to complete.';
      setScanError(msg);
    } finally {
      setIsScanning(false);
      setScanStep('');
    }
  };

  const setPresetUrl = (url: string) => {
    setInputUrl(url);
    setScanError(null);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Page Header */}
      <div className="border-b border-[#E5E5E5] dark:border-[#262626] pb-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h1 className="text-xl font-bold text-[#111111] dark:text-[#FFFFFF] flex items-center gap-2">
              <Globe className="h-5 w-5 text-[#737373]" />
              Link Scanner
            </h1>
            <p className="text-xs text-[#737373] mt-1">
              Check web links before you click. We inspect certificates, known scams, credential forms, and download safety.
            </p>
          </div>
          <div className="flex items-center gap-2 text-[11px] text-[#737373] bg-[#FAFAFA] dark:bg-[#262626] border border-[#E5E5E5] dark:border-[#262626] rounded-md px-2.5 py-1 shrink-0">
            <span className="inline-block h-2 w-2 rounded-full bg-emerald-500"></span>
            Safe passive check
          </div>
        </div>
      </div>

      {/* Input Card */}
      <Card className="space-y-4" interactive={false}>
        <form onSubmit={handleScanSubmit} className="space-y-3">
          <label className="block text-xs font-semibold text-[#111111] dark:text-[#FFFFFF]">
            Target URL or Domain Name
          </label>
          <div className="flex flex-col sm:flex-row gap-2">
            <div className="relative flex-1">
              <Globe className="absolute left-3.5 top-3 h-4 w-4 text-[#737373]" />
              <input
                type="text"
                value={inputUrl}
                onChange={(e) => {
                  setInputUrl(e.target.value);
                  if (scanError) setScanError(null);
                }}
                placeholder="e.g. github.com, https://example.com/login, or direct link"
                className="w-full rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111] pl-10 pr-4 py-2.5 text-xs text-[#111111] dark:text-[#FFFFFF] placeholder-[#737373] focus:border-[#111111] dark:focus:border-[#FFFFFF] focus:outline-hidden"
              />
            </div>
            <button
              type="submit"
              disabled={isScanning || !inputUrl.trim()}
              className="flex items-center justify-center gap-2 rounded-lg bg-[#111111] dark:bg-[#FFFFFF] px-5 py-2.5 text-xs font-semibold text-[#FFFFFF] dark:text-[#111111] hover:bg-zinc-800 dark:hover:bg-zinc-200 disabled:opacity-50 transition-colors shrink-0"
            >
              {isScanning ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Analyzing Target...
                </>
              ) : (
                <>
                  <Search className="h-4 w-4" />
                  Scan URL
                </>
              )}
            </button>
          </div>
        </form>

        {/* Scan Error Alert with Safe Retry */}
        {scanError && (
          <div className="rounded-lg border border-red-200 dark:border-red-900/40 bg-red-50 dark:bg-red-950/30 p-3 text-xs text-red-700 dark:text-red-300 flex items-start justify-between gap-3">
            <div className="flex items-start gap-2">
              <AlertOctagon className="h-4 w-4 shrink-0 text-red-600 dark:text-red-400 mt-0.5" />
              <div>
                <span className="font-semibold block">Scan Could Not Be Completed</span>
                <span>{scanError}</span>
              </div>
            </div>
            <button
              onClick={handleScanSubmit}
              className="flex items-center gap-1 text-[11px] font-semibold text-red-700 dark:text-red-300 hover:underline shrink-0"
            >
              <RefreshCw className="h-3 w-3" /> Retry
            </button>
          </div>
        )}

        {/* Safe Presets Notice */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-[#E5E5E5] dark:border-[#262626]">
          <span className="text-[11px] text-[#737373]">Quick Inspection Candidates:</span>
          <button
            type="button"
            onClick={() => setPresetUrl('github.com')}
            className="rounded-md border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111] px-2.5 py-1 text-xs text-[#737373] hover:border-[#111111] dark:hover:border-[#FFFFFF] hover:text-[#111111] dark:hover:text-[#FFFFFF]"
          >
            github.com (Clean Web)
          </button>
          <button
            type="button"
            onClick={() => setPresetUrl('example.com')}
            className="rounded-md border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111] px-2.5 py-1 text-xs text-[#737373] hover:border-[#111111] dark:hover:border-[#FFFFFF] hover:text-[#111111] dark:hover:text-[#FFFFFF]"
          >
            example.com (Standard)
          </button>
          <button
            type="button"
            onClick={() => setPresetUrl('127.0.0.1:8000')}
            className="rounded-md border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111] px-2.5 py-1 text-xs text-[#737373] hover:border-[#111111] dark:hover:border-[#FFFFFF] hover:text-[#111111] dark:hover:text-[#FFFFFF]"
          >
            127.0.0.1 (SSRF Guard Test)
          </button>
        </div>
      </Card>

      {/* Scanning Stage Progress Indicator */}
      {isScanning && (
        <Card className="text-center py-8 space-y-3" interactive={false}>
          <Loader2 className="h-7 w-7 text-[#737373] animate-spin mx-auto" />
          <div>
            <p className="text-xs font-semibold text-[#111111] dark:text-[#FFFFFF]">Executing Multi-Signal Inspection Pipeline...</p>
            <p className="text-[11px] text-[#737373] mt-1 font-mono">{scanStep}</p>
          </div>
          <div className="flex justify-center items-center gap-4 text-[10px] text-[#737373] pt-2">
            <span>• TLS certificate analysis</span>
            <span>• URLhaus reputation check</span>
            <span>• Input form auditing</span>
            <span>• Download safety check</span>
          </div>
        </Card>
      )}

      {/* Active Scan Result Display */}
      {!isScanning && activeResult && urlFindingsData && (
        <div ref={resultsRef} className="space-y-6 scroll-mt-6">
          {/* Prominent Scan Result Summary Panel */}
          <ScanResultSummary
            verdict={urlFindingsData.verdict}
            targetName={activeResult.url}
            targetType="URL"
            timestamp={activeResult.timestamp}
            threatScore={
              activeResult.threat_score !== undefined
                ? activeResult.threat_score
                : activeResult.riskScore / 10
            }
            threatScoreMax={10.0}
            summaryExplanation={
              activeResult.plain_english_explanation ||
              activeResult.summary ||
              'Security assessment completed across passive multi-signal intelligence modules.'
            }
            findingsCounts={urlFindingsData.counts}
            scanStatus={
              activeResult.isLiveScan
                ? 'Full live multi-signal passive scan completed'
                : 'Simulated multi-signal passive scan'
            }
            onScrollToFindings={() =>
              findingsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
            }
            isLiveScan={Boolean(activeResult.isLiveScan)}
          />

          {/* Dedicated Security Findings Section with Category Filter */}
          <div ref={findingsRef}>
            <SecurityFindingsList
              findings={urlFindingsData.findings}
              title="What We Found"
              subtitle="Potential risks and observations detected during the link check."
            />
          </div>

          {/* Assessment Summary & Context Card */}
          <Card className="space-y-6 border-[#E5E5E5] dark:border-[#262626]" interactive={false}>
            {/* Plain English Assessment */}
            <div className="rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FAFAFA] dark:bg-[#111111] p-4 space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#111111] dark:text-[#FFFFFF]">
                  <Info className="h-4 w-4 text-[#737373]" />
                  Security Overview
                </div>
                <Badge level={activeResult.riskLevel}>{activeResult.verdict.toUpperCase()}</Badge>
              </div>
              <p className="text-xs text-[#111111] dark:text-[#FFFFFF] leading-relaxed">
                {activeResult.plain_english_explanation || activeResult.summary || 'URL scan completed.'}
              </p>
              <div className="pt-2 border-t border-[#E5E5E5] dark:border-[#262626] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                <span className="font-semibold text-[#737373]">
                  Recommended Action:{' '}
                  <span className="font-bold text-[#111111] dark:text-[#FFFFFF]">
                    {activeResult.recommendedAction}
                  </span>
                </span>
              </div>
            </div>

            {/* Reassuring vs Risk Evidence Split */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Risk Factors */}
              <div className="rounded-lg border border-[#E5E5E5] dark:border-[#262626] p-3.5 space-y-2 bg-[#FFFFFF] dark:bg-[#111111]">
                <div className="flex items-center gap-2 text-xs font-semibold text-[#111111] dark:text-[#FFFFFF]">
                  <AlertTriangle className="h-4 w-4 text-amber-500" />
                  Elevated Risk Indicators
                </div>
                {activeResult.risk_factors && activeResult.risk_factors.length > 0 ? (
                  <ul className="space-y-1.5 text-xs text-[#737373]">
                    {activeResult.risk_factors.map((rf, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-amber-500 font-bold">•</span>
                        <span>{rf}</span>
                      </li>
                    ))}
                  </ul>
                ) : activeResult.suspiciousSignals.length > 0 ? (
                  <ul className="space-y-1.5 text-xs text-[#737373]">
                    {activeResult.suspiciousSignals.map((sig, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-amber-500 font-bold">•</span>
                        <span>{sig}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-[#737373] italic">No significant risk indicators identified.</p>
                )}
              </div>

              {/* Reassuring Factors */}
              <div className="rounded-lg border border-[#E5E5E5] dark:border-[#262626] p-3.5 space-y-2 bg-[#FFFFFF] dark:bg-[#111111]">
                <div className="flex items-center gap-2 text-xs font-semibold text-[#111111] dark:text-[#FFFFFF]">
                  <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                  Reassuring Evidence
                </div>
                {activeResult.reassuring_factors && activeResult.reassuring_factors.length > 0 ? (
                  <ul className="space-y-1.5 text-xs text-[#737373]">
                    {activeResult.reassuring_factors.map((rf, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-emerald-500 font-bold">✓</span>
                        <span>{rf}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-[#737373] italic">Standard web property evidence without positive reputation badges.</p>
                )}
              </div>
            </div>
          </Card>

          {/* ================================================================= */}
          {/* FEATURE 1: SSL/TLS Certificate Intelligence Card */}
          {/* ================================================================= */}
          <Card className="space-y-4 border-[#E5E5E5] dark:border-[#262626]" interactive={false}>
            <div className="flex items-center justify-between border-b border-[#E5E5E5] dark:border-[#262626] pb-3">
              <h3 className="text-sm font-semibold text-[#111111] dark:text-[#FFFFFF] flex items-center gap-2">
                <Lock className="h-4 w-4 text-[#737373]" />
                Connection &amp; Certificate Details
              </h3>
              {activeResult.ssl_certificate ? (
                <span
                  className={`text-[10px] font-medium px-2 py-0.5 rounded border ${
                    activeResult.ssl_certificate.is_valid
                      ? 'bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800'
                      : activeResult.ssl_certificate.status === 'unencrypted_http'
                      ? 'bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800'
                      : 'bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800'
                  }`}
                >
                  {activeResult.ssl_certificate.connection_status}
                </span>
              ) : (
                <span className="text-[10px] text-[#737373] bg-[#FAFAFA] dark:bg-[#262626] px-2 py-0.5 rounded">
                  {activeResult.domainInfo.sslValid ? 'HTTPS Encrypted' : 'Unencrypted'}
                </span>
              )}
            </div>

            {/* Explanation box */}
            <div className="rounded-lg bg-[#FAFAFA] dark:bg-[#111111] border border-[#E5E5E5] dark:border-[#262626] p-3 text-xs text-[#111111] dark:text-[#FFFFFF] space-y-1">
              <p className="font-medium text-[#737373] text-[11px] uppercase tracking-wider">
                Cryptographic Connection Context
              </p>
              <p className="leading-relaxed">
                {activeResult.ssl_certificate?.plain_language_explanation ||
                  'HTTPS encrypts your connection, but it does not guarantee that this website is legitimate.'}
              </p>
            </div>

            {/* Certificate Details Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111]">
                <span className="text-[10px] text-[#737373] block uppercase tracking-wider">Certificate Issuer</span>
                <span className="font-semibold text-[#111111] dark:text-[#FFFFFF] block mt-1 truncate">
                  {activeResult.ssl_certificate?.issuer || activeResult.domainInfo.sslIssuer}
                </span>
                <span className="text-[10px] text-[#737373] block mt-0.5">
                  {activeResult.ssl_certificate?.is_public_ca ? 'Publicly Trusted CA' : 'Unverified / Private CA'}
                </span>
              </div>

              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111]">
                <span className="text-[10px] text-[#737373] block uppercase tracking-wider">Valid Until</span>
                <span className="font-semibold text-[#111111] dark:text-[#FFFFFF] block mt-1 truncate">
                  {activeResult.ssl_certificate?.valid_until ? activeResult.ssl_certificate.valid_until.split(' ')[0] : 'N/A'}
                </span>
                <span className="text-[10px] text-[#737373] block mt-0.5">
                  {typeof activeResult.ssl_certificate?.days_remaining === 'number'
                    ? `${activeResult.ssl_certificate.days_remaining} days remaining`
                    : 'Expiration window unknown'}
                </span>
              </div>

              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111]">
                <span className="text-[10px] text-[#737373] block uppercase tracking-wider">Hostname Match</span>
                <span className="font-semibold text-[#111111] dark:text-[#FFFFFF] block mt-1">
                  {activeResult.ssl_certificate?.hostname_match ? (
                    <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                      <CheckCircle2 className="h-3.5 w-3.5" /> Matches Target
                    </span>
                  ) : activeResult.ssl_certificate?.status === 'unencrypted_http' ? (
                    <span className="text-[#737373]">N/A (Plaintext HTTP)</span>
                  ) : (
                    <span className="text-red-600 dark:text-red-400 flex items-center gap-1">
                      <AlertOctagon className="h-3.5 w-3.5" /> Mismatch Detected
                    </span>
                  )}
                </span>
                <span className="text-[10px] text-[#737373] block mt-0.5 truncate">
                  SAN: {activeResult.ssl_certificate?.subject_alt_names?.slice(0, 2).join(', ') || 'None'}
                </span>
              </div>

              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111]">
                <span className="text-[10px] text-[#737373] block uppercase tracking-wider">Chain Status</span>
                <span className="font-semibold text-[#111111] dark:text-[#FFFFFF] block mt-1 capitalize">
                  {activeResult.ssl_certificate?.certificate_chain_status?.replace('_', ' ') || 'Unverified'}
                </span>
                <span className="text-[10px] text-[#737373] block mt-0.5">
                  Protocol: {activeResult.ssl_certificate?.tls_version || 'TLS'}
                </span>
              </div>
            </div>

            {/* Warnings if any */}
            {activeResult.ssl_certificate?.warnings && activeResult.ssl_certificate.warnings.length > 0 && (
              <div className="p-3 rounded-lg bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 text-xs text-amber-800 dark:text-amber-200 space-y-1">
                <span className="font-semibold block flex items-center gap-1.5">
                  <AlertTriangle className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
                  Certificate Advisory
                </span>
                {activeResult.ssl_certificate.warnings.map((w, idx) => (
                  <p key={idx}>• {w}</p>
                ))}
              </div>
            )}

            {/* Limitations Notice */}
            <div className="text-[10px] text-[#737373] pt-1">
              Note: Domain Validation (DV) certificates verify control of a domain name, not the legal identity or trustworthiness of the business. Free certificates from automated authorities (e.g. Let&apos;s Encrypt) are standard industry practice and not indicative of malicious intent.
            </div>
          </Card>

          {/* ================================================================= */}
          {/* FEATURE 2: Real-Time Threat Intelligence & Blocklists Panel */}
          {/* ================================================================= */}
          <Card className="space-y-4 border-[#E5E5E5] dark:border-[#262626]" interactive={false}>
            <div className="flex items-center justify-between border-b border-[#E5E5E5] dark:border-[#262626] pb-3">
              <h3 className="text-sm font-semibold text-[#111111] dark:text-[#FFFFFF] flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-[#737373]" />
                Known Scam Checks
              </h3>
              <span className="text-[11px] text-[#737373]">
                {activeResult.reputation_providers?.length || 0} feeds evaluated
              </span>
            </div>

            {/* Active Threat Warning Banner if any provider flagged */}
            {activeResult.reputation_providers?.some((p) => p.is_malicious) && (
              <div className="p-3.5 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-xs text-red-800 dark:text-red-200 flex items-start gap-2.5">
                <AlertOctagon className="h-4 w-4 shrink-0 text-red-600 dark:text-red-400 mt-0.5" />
                <div>
                  <span className="font-bold block">Confirmed Threat Intelligence Detection</span>
                  <span>One or more authoritative threat intelligence providers have flagged this target destination as malicious. Avoid visiting or downloading files.</span>
                </div>
              </div>
            )}

            {/* Provider Rows Table */}
            <div className="rounded-lg border border-[#E5E5E5] dark:border-[#262626] overflow-hidden text-xs">
              <div className="grid grid-cols-12 bg-[#FAFAFA] dark:bg-[#111111] px-3 py-2 font-semibold text-[10px] uppercase text-[#737373] border-b border-[#E5E5E5] dark:border-[#262626]">
                <div className="col-span-4 sm:col-span-3">Provider</div>
                <div className="col-span-4 sm:col-span-3">Verdict / Result</div>
                <div className="col-span-4 sm:col-span-4">Category & Evidence</div>
                <div className="hidden sm:block sm:col-span-2 text-right">Reference</div>
              </div>

              <div className="divide-y divide-[#E5E5E5] dark:divide-[#262626]">
                {activeResult.reputation_providers && activeResult.reputation_providers.length > 0 ? (
                  activeResult.reputation_providers.map((prov, idx) => (
                    <div key={idx} className="grid grid-cols-12 px-3 py-2.5 items-center hover:bg-[#FAFAFA] dark:hover:bg-[#111111]/60 transition-colors">
                      <div className="col-span-4 sm:col-span-3 font-semibold text-[#111111] dark:text-[#FFFFFF] truncate">
                        {prov.provider_name}
                      </div>

                      <div className="col-span-4 sm:col-span-3">
                        {prov.status === 'clean' && (
                          <span className="text-[10px] text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 px-2 py-0.5 rounded font-medium">
                            No detection
                          </span>
                        )}
                        {prov.status === 'malicious_found' && (
                          <span className="text-[10px] text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800 px-2 py-0.5 rounded font-medium">
                            Malicious
                          </span>
                        )}
                        {prov.status === 'not_configured' && (
                          <span className="text-[10px] text-[#737373] bg-[#FAFAFA] dark:bg-[#262626] border border-[#E5E5E5] dark:border-[#262626] px-2 py-0.5 rounded">
                            Not configured
                          </span>
                        )}
                        {prov.status === 'unavailable' && (
                          <span className="text-[10px] text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 px-2 py-0.5 rounded">
                            Check unavailable
                          </span>
                        )}
                        {prov.status === 'rate_limited' && (
                          <span className="text-[10px] text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 px-2 py-0.5 rounded">
                            Rate limited
                          </span>
                        )}
                      </div>

                      <div className="col-span-4 sm:col-span-4 text-[11px] text-[#737373] truncate pr-2">
                        {prov.detection_category && (
                          <span className="font-medium text-[#111111] dark:text-[#FFFFFF] mr-1.5">
                            [{prov.detection_category}]
                          </span>
                        )}
                        <span>{prov.threat_details || prov.error_message || 'No active malicious signatures'}</span>
                      </div>

                      <div className="hidden sm:block sm:col-span-2 text-right">
                        {prov.reference_url ? (
                          <a
                            href={prov.reference_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-[11px] text-[#737373] hover:text-[#111111] dark:hover:text-[#FFFFFF]"
                          >
                            Source <ExternalLink className="h-3 w-3" />
                          </a>
                        ) : (
                          <span className="text-[10px] text-[#737373]">—</span>
                        )}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="p-4 text-center text-xs text-[#737373] italic">
                    No threat feeds populated for this URL.
                  </div>
                )}
              </div>
            </div>

            <div className="text-[10px] text-[#737373] pt-1">
              Disclaimer: An absence of threat intelligence detections does not guarantee that a website is safe. Threat intelligence databases index known malicious infrastructure after detection and reporting.
            </div>
          </Card>

          {/* ================================================================= */}
          {/* FEATURE 3: Password and Sensitive Input Auditing Card */}
          {/* ================================================================= */}
          <Card className="space-y-4 border-[#E5E5E5] dark:border-[#262626]" interactive={false}>
            <div className="flex items-center justify-between border-b border-[#E5E5E5] dark:border-[#262626] pb-3">
              <h3 className="text-sm font-semibold text-[#111111] dark:text-[#FFFFFF] flex items-center gap-2">
                <KeyRound className="h-4 w-4 text-[#737373]" />
                Sensitive Input Audit
              </h3>
              <span
                className={`text-[10px] px-2 py-0.5 rounded font-medium border ${
                  activeResult.sensitive_input_audit?.cross_origin_submission_detected
                    ? 'bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800'
                    : (activeResult.sensitive_input_audit?.password_fields_detected || 0) > 0
                    ? 'bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800'
                    : 'bg-[#FAFAFA] dark:bg-[#262626] text-[#737373] border-[#E5E5E5] dark:border-[#262626]'
                }`}
              >
                {(activeResult.sensitive_input_audit?.password_fields_detected || 0) > 0
                  ? 'Password Fields Detected'
                  : 'No Credentials Requested'}
              </span>
            </div>

            {/* Evidence-based explanation banner */}
            <div className="rounded-lg bg-[#FAFAFA] dark:bg-[#111111] border border-[#E5E5E5] dark:border-[#262626] p-3 text-xs space-y-1">
              <p className="font-medium text-[#737373] text-[11px] uppercase tracking-wider">
                Static Form Audit Verdict
              </p>
              <p className="text-[#111111] dark:text-[#FFFFFF] leading-relaxed">
                {activeResult.sensitive_input_audit?.evidence_based_explanation ||
                  'No sensitive credential or payment collection inputs were detected in static markup.'}
              </p>
            </div>

            {/* Inputs Metric Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111]">
                <span className="text-[10px] text-[#737373] uppercase tracking-wider block">Password Fields</span>
                <span className="text-base font-bold text-[#111111] dark:text-[#FFFFFF] mt-1 block">
                  {activeResult.sensitive_input_audit?.password_fields_detected ?? 0}
                </span>
                <span className="text-[10px] text-[#737373]">Authentication inputs</span>
              </div>

              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111]">
                <span className="text-[10px] text-[#737373] uppercase tracking-wider block">Login / Email Fields</span>
                <span className="text-base font-bold text-[#111111] dark:text-[#FFFFFF] mt-1 block">
                  {activeResult.sensitive_input_audit?.email_login_fields_detected ?? 0}
                </span>
                <span className="text-[10px] text-[#737373]">Account identifier inputs</span>
              </div>

              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111]">
                <span className="text-[10px] text-[#737373] uppercase tracking-wider block">Payment Fields</span>
                <span className="text-base font-bold text-[#111111] dark:text-[#FFFFFF] mt-1 block">
                  {activeResult.sensitive_input_audit?.payment_fields_detected ?? 0}
                </span>
                <span className="text-[10px] text-[#737373]">Credit card / CVV / PAN</span>
              </div>

              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111]">
                <span className="text-[10px] text-[#737373] uppercase tracking-wider block">Cross-Origin Target</span>
                <span className="text-base font-bold mt-1 block">
                  {activeResult.sensitive_input_audit?.cross_origin_submission_detected ? (
                    <span className="text-red-600 dark:text-red-400">Yes (External)</span>
                  ) : (
                    <span className="text-emerald-600 dark:text-emerald-400">Same-Origin</span>
                  )}
                </span>
                <span className="text-[10px] text-[#737373]">Form endpoint origin</span>
              </div>
            </div>

            {/* Form Destinations List */}
            {activeResult.sensitive_input_audit?.form_submission_destinations &&
              activeResult.sensitive_input_audit.form_submission_destinations.length > 0 && (
                <div className="space-y-1.5 text-xs">
                  <span className="text-[11px] font-semibold text-[#737373]">Form Submission Action Destinations:</span>
                  <div className="space-y-1">
                    {activeResult.sensitive_input_audit.form_submission_destinations.map((dest, i) => (
                      <div key={i} className="font-mono text-[11px] p-2 rounded bg-[#FAFAFA] dark:bg-[#111111] border border-[#E5E5E5] dark:border-[#262626] break-all text-[#111111] dark:text-[#FFFFFF]">
                        {dest}
                      </div>
                    ))}
                  </div>
                </div>
              )}

            {/* Warnings */}
            {activeResult.sensitive_input_audit?.warnings && activeResult.sensitive_input_audit.warnings.length > 0 && (
              <div className="p-3 rounded-lg bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 text-xs text-amber-800 dark:text-amber-200 space-y-1">
                <span className="font-semibold block flex items-center gap-1.5">
                  <AlertTriangle className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
                  Form Security Warning
                </span>
                {activeResult.sensitive_input_audit.warnings.map((w, idx) => (
                  <p key={idx}>• {w}</p>
                ))}
              </div>
            )}

            <div className="text-[10px] text-[#737373] pt-1">
              Inspection Rule: The presence of a password field on a recognized bank or service is normal. Concern is raised when credential fields coincide with newly registered domains, external form submission destinations, or unencrypted HTTP transport. Actual credentials are never solicited or recorded.
            </div>
          </Card>

          {/* ================================================================= */}
          {/* FEATURE 4: Dangerous Download & File Extension Detection Card */}
          {/* ================================================================= */}
          <Card className="space-y-4 border-[#E5E5E5] dark:border-[#262626]" interactive={false}>
            <div className="flex items-center justify-between border-b border-[#E5E5E5] dark:border-[#262626] pb-3">
              <h3 className="text-sm font-semibold text-[#111111] dark:text-[#FFFFFF] flex items-center gap-2">
                <FileDown className="h-4 w-4 text-[#737373]" />
                Download Safety &amp; File Extension Detection
              </h3>
              <span
                className={`text-[10px] px-2 py-0.5 rounded font-medium border ${
                  activeResult.download_safety?.mismatch_detected
                    ? 'bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800'
                    : activeResult.download_safety?.is_download
                    ? 'bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800'
                    : 'bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800'
                }`}
              >
                {activeResult.download_safety?.is_download ? 'File Download Detected' : 'Webpage (No Download)'}
              </span>
            </div>

            {/* Explanation box */}
            <div className="rounded-lg bg-[#FAFAFA] dark:bg-[#111111] border border-[#E5E5E5] dark:border-[#262626] p-3 text-xs space-y-1">
              <p className="font-medium text-[#737373] text-[11px] uppercase tracking-wider">
                Payload Inspection Assessment
              </p>
              <p className="text-[#111111] dark:text-[#FFFFFF] leading-relaxed">
                {activeResult.download_safety?.explanation || 'Target returns a standard HTML webpage. No file download was initiated.'}
              </p>
            </div>

            {/* Disguise / Mismatch Warning */}
            {activeResult.download_safety?.warning && (
              <div className="p-3.5 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-xs text-red-800 dark:text-red-200 flex items-start gap-2.5">
                <AlertOctagon className="h-4 w-4 shrink-0 text-red-600 dark:text-red-400 mt-0.5" />
                <div>
                  <span className="font-bold block">Disguised Payload Warning</span>
                  <span>{activeResult.download_safety.warning}</span>
                </div>
              </div>
            )}

            {/* Download Details Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111]">
                <span className="text-[10px] text-[#737373] uppercase tracking-wider block">Reported Filename</span>
                <span className="font-semibold text-[#111111] dark:text-[#FFFFFF] block mt-1 font-mono truncate">
                  {activeResult.download_safety?.server_reported_filename || 'None (Webpage)'}
                </span>
                <span className="text-[10px] text-[#737373] block mt-0.5">Content-Disposition header</span>
              </div>

              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111]">
                <span className="text-[10px] text-[#737373] uppercase tracking-wider block">Effective Extension</span>
                <span className="font-semibold text-[#111111] dark:text-[#FFFFFF] block mt-1 font-mono">
                  {activeResult.download_safety?.effective_extension || (activeResult.download_safety?.is_download ? 'None' : '.html')}
                </span>
                <span className="text-[10px] text-[#737373] block mt-0.5">
                  {activeResult.download_safety?.has_double_extension ? (
                    <span className="text-red-500 font-bold">Double Extension!</span>
                  ) : (
                    'Single extension format'
                  )}
                </span>
              </div>

              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111]">
                <span className="text-[10px] text-[#737373] uppercase tracking-wider block">Server MIME Type</span>
                <span className="font-semibold text-[#111111] dark:text-[#FFFFFF] block mt-1 font-mono truncate">
                  {activeResult.download_safety?.mime_type || activeResult.redirect_analysis?.content_type || 'text/html'}
                </span>
                <span className="text-[10px] text-[#737373] block mt-0.5">Declared Content-Type</span>
              </div>

              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111]">
                <span className="text-[10px] text-[#737373] uppercase tracking-wider block">Magic Byte Signature</span>
                <span className="font-semibold text-[#111111] dark:text-[#FFFFFF] block mt-1 truncate">
                  {activeResult.download_safety?.magic_byte_signature || 'HTML Webpage Content'}
                </span>
                <span className="text-[10px] text-[#737373] block mt-0.5">Prefix byte evaluation</span>
              </div>
            </div>

            <div className="text-[10px] text-[#737373] pt-1">
              Safety Boundary: Scanned files are never executed, decompressed, or downloaded to user devices. Evaluation is strictly confined to response headers and an initial 1 KB buffer.
            </div>
          </Card>

          {/* ================================================================= */}
          {/* FEATURE 5: Hosting Provider and Infrastructure Footprint Card */}
          {/* ================================================================= */}
          <Card className="space-y-4 border-[#E5E5E5] dark:border-[#262626]" interactive={false}>
            <div className="flex items-center justify-between border-b border-[#E5E5E5] dark:border-[#262626] pb-3">
              <h3 className="text-sm font-semibold text-[#111111] dark:text-[#FFFFFF] flex items-center gap-2">
                <Server className="h-4 w-4 text-[#737373]" />
                Website Details
              </h3>
              <span className="text-[10px] bg-[#FAFAFA] dark:bg-[#262626] text-[#737373] border border-[#E5E5E5] dark:border-[#262626] px-2 py-0.5 rounded">
                Network Telemetry
              </span>
            </div>

            {/* Footprint Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111] space-y-1">
                <span className="text-[10px] text-[#737373] uppercase tracking-wider block flex items-center gap-1">
                  <Building2 className="h-3 w-3" /> Hosting Organization &amp; ISP
                </span>
                <p className="font-semibold text-[#111111] dark:text-[#FFFFFF] truncate">
                  {activeResult.hosting_footprint?.organization || activeResult.hosting_intelligence?.organization || 'Cloud Hosting Provider'}
                </p>
                <p className="text-[11px] text-[#737373] truncate">
                  ISP: {activeResult.hosting_footprint?.isp || activeResult.hosting_intelligence?.isp || 'Internet Service Provider'}
                </p>
              </div>

              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111] space-y-1">
                <span className="text-[10px] text-[#737373] uppercase tracking-wider block flex items-center gap-1">
                  <Network className="h-3 w-3" /> ASN &amp; Autonomous System
                </span>
                <p className="font-semibold text-[#111111] dark:text-[#FFFFFF] truncate">
                  {activeResult.hosting_footprint?.asn || activeResult.hosting_intelligence?.asn || 'BGP Autonomous System'}
                </p>
                <p className="text-[11px] text-[#737373]">
                  {activeResult.hosting_footprint?.is_cloud_or_cdn ? (
                    <span className="text-emerald-600 dark:text-emerald-400 font-medium">Edge / CDN Network</span>
                  ) : (
                    'Dedicated / Datacenter IP'
                  )}
                </p>
              </div>

              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111] space-y-1">
                <span className="text-[10px] text-[#737373] uppercase tracking-wider block flex items-center gap-1">
                  <Globe className="h-3 w-3" /> IP Address &amp; Reverse DNS
                </span>
                <p className="font-semibold text-[#111111] dark:text-[#FFFFFF] font-mono truncate">
                  {activeResult.hosting_footprint?.ip_address || activeResult.domainInfo.ipAddress}
                </p>
                <p className="text-[11px] text-[#737373] font-mono truncate">
                  PTR: {activeResult.hosting_footprint?.reverse_dns || 'No reverse PTR record'}
                </p>
              </div>

              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111] space-y-1">
                <span className="text-[10px] text-[#737373] uppercase tracking-wider block">Approximate Geolocation</span>
                <p className="font-semibold text-[#111111] dark:text-[#FFFFFF] truncate">
                  {activeResult.hosting_footprint?.country
                    ? `${activeResult.hosting_footprint.city ? activeResult.hosting_footprint.city + ', ' : ''}${activeResult.hosting_footprint.country}`
                    : activeResult.domainInfo.location}
                </p>
                <p className="text-[10px] text-[#737373]">Network edge routing location</p>
              </div>

              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111] space-y-1">
                <span className="text-[10px] text-[#737373] uppercase tracking-wider block flex items-center gap-1">
                  <Calendar className="h-3 w-3" /> Domain Age (ICANN RDAP)
                </span>
                <p className="font-semibold text-[#111111] dark:text-[#FFFFFF] truncate">
                  {typeof activeResult.domain_registration?.domain_age_days === 'number' && activeResult.domain_registration.domain_age_days >= 0
                    ? `${activeResult.domain_registration.domain_age_days} days old`
                    : activeResult.domainInfo.registeredDaysAgo >= 0
                    ? `${activeResult.domainInfo.registeredDaysAgo} days old`
                    : 'Not available'}
                </p>
                <p className="text-[10px] text-[#737373] truncate">
                  Registrar: {activeResult.domain_registration?.registrar || activeResult.domainInfo.registrar}
                </p>
              </div>

              <div className="p-3 rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FFFFFF] dark:bg-[#111111] space-y-1">
                <span className="text-[10px] text-[#737373] uppercase tracking-wider block">CDN / Proxy Indicator</span>
                <p className="font-semibold text-[#111111] dark:text-[#FFFFFF] truncate">
                  {activeResult.hosting_footprint?.cdn_provider || (activeResult.hosting_footprint?.is_cloud_or_cdn ? 'Cloud Edge Proxy' : 'Direct Origin Host')}
                </p>
                <p className="text-[10px] text-[#737373]">
                  Source: {activeResult.hosting_footprint?.data_provider || 'Network Intelligence'}
                </p>
              </div>
            </div>

            {/* Contextual Note */}
            <div className="rounded-lg bg-[#FAFAFA] dark:bg-[#111111] border border-[#E5E5E5] dark:border-[#262626] p-3 text-xs text-[#737373] space-y-1">
              <span className="font-semibold text-[#111111] dark:text-[#FFFFFF] block">Footprint Analysis Interpretation:</span>
              <p className="leading-relaxed">
                Hosting on AWS, Google Cloud, Microsoft Azure, a budget provider, or a CDN does not independently establish trustworthiness or malicious intent. Geolocation reflects network edge routing points rather than the website owner&apos;s physical street address.
              </p>
            </div>
          </Card>

          {/* ================================================================= */}
          {/* FEATURE 6: Trustworthy Agency and Security Authority Audit Card */}
          {/* ================================================================= */}
          <Card className="space-y-4 border-[#E5E5E5] dark:border-[#262626]" interactive={false}>
            <div className="flex items-center justify-between border-b border-[#E5E5E5] dark:border-[#262626] pb-3">
              <h3 className="text-sm font-semibold text-[#111111] dark:text-[#FFFFFF] flex items-center gap-2">
                <CheckSquare className="h-4 w-4 text-[#737373]" />
                Security Authority Audit Checklist
              </h3>
              <span
                className={`text-[10px] px-2 py-0.5 rounded font-medium border ${
                  (activeResult.security_authority_checklist?.threats_reported_count || 0) > 0
                    ? 'bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800'
                    : 'bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800'
                }`}
              >
                {(activeResult.security_authority_checklist?.threats_reported_count || 0) > 0
                  ? `${activeResult.security_authority_checklist?.threats_reported_count} Threat(s) Reported`
                  : 'Checklist Clean'}
              </span>
            </div>

            {/* Checklist summary banner */}
            <div className="rounded-lg bg-[#FAFAFA] dark:bg-[#111111] border border-[#E5E5E5] dark:border-[#262626] p-3 text-xs text-[#111111] dark:text-[#FFFFFF] space-y-1">
              <p className="font-medium text-[#737373] text-[11px] uppercase tracking-wider">
                Authority Cross-Check Status
              </p>
              <p className="leading-relaxed font-semibold">
                {activeResult.security_authority_checklist?.summary ||
                  'No security authorities reported an active threat against this destination.'}
              </p>
            </div>

            {/* Authority Checklist Table */}
            <div className="rounded-lg border border-[#E5E5E5] dark:border-[#262626] overflow-hidden text-xs">
              <div className="grid grid-cols-12 bg-[#FAFAFA] dark:bg-[#111111] px-3 py-2 font-semibold text-[10px] uppercase text-[#737373] border-b border-[#E5E5E5] dark:border-[#262626]">
                <div className="col-span-4 sm:col-span-3">Authority / Feed</div>
                <div className="col-span-3 sm:col-span-2">Target</div>
                <div className="col-span-5 sm:col-span-3">Check Status</div>
                <div className="hidden sm:block sm:col-span-4">Verified Evidence</div>
              </div>

              <div className="divide-y divide-[#E5E5E5] dark:divide-[#262626]">
                {activeResult.security_authority_checklist?.items &&
                activeResult.security_authority_checklist.items.length > 0 ? (
                  activeResult.security_authority_checklist.items.map((item, idx) => (
                    <div key={idx} className="grid grid-cols-12 px-3 py-2.5 items-center hover:bg-[#FAFAFA] dark:hover:bg-[#111111]/60 transition-colors">
                      <div className="col-span-4 sm:col-span-3 font-semibold text-[#111111] dark:text-[#FFFFFF] truncate">
                        {item.authority_name}
                      </div>

                      <div className="col-span-3 sm:col-span-2 text-[11px] text-[#737373]">
                        {item.target_checked}
                      </div>

                      <div className="col-span-5 sm:col-span-3">
                        {item.status === 'threat_reported' && (
                          <span className="text-[10px] text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800 px-2 py-0.5 rounded font-medium">
                            Threat Reported
                          </span>
                        )}
                        {item.status === 'no_threat_reported' && (
                          <span className="text-[10px] text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 px-2 py-0.5 rounded font-medium">
                            {item.verdict_label || 'No Detection'}
                          </span>
                        )}
                        {item.status === 'not_configured' && (
                          <span className="text-[10px] text-[#737373] bg-[#FAFAFA] dark:bg-[#262626] border border-[#E5E5E5] dark:border-[#262626] px-2 py-0.5 rounded">
                            Not Configured
                          </span>
                        )}
                        {item.status === 'check_unavailable' && (
                          <span className="text-[10px] text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 px-2 py-0.5 rounded">
                            Check Unavailable
                          </span>
                        )}
                        {item.status === 'not_applicable' && (
                          <span className="text-[10px] text-[#737373] bg-[#FAFAFA] dark:bg-[#262626] border border-[#E5E5E5] dark:border-[#262626] px-2 py-0.5 rounded">
                            Not Applicable
                          </span>
                        )}
                      </div>

                      <div className="hidden sm:block sm:col-span-4 text-[11px] text-[#737373] truncate">
                        {item.evidence_summary}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="p-4 text-center text-xs text-[#737373] italic">
                    Authority checklist not generated for this scan.
                  </div>
                )}
              </div>
            </div>

            <div className="text-[10px] text-[#737373] pt-1">
              Ethical Disclosure: Cyclops does not fabricate certifications, endorsements, or law enforcement investigations. A clean check from automated threat databases indicates the target has not yet been indexed as malicious; it is not an official government determination of safety.
            </div>
          </Card>

          {/* Destination & Normalization Details */}
          {activeResult.normalization && (
            <Card className="space-y-3 border-[#E5E5E5] dark:border-[#262626]" interactive={false}>
              <h3 className="text-xs font-semibold text-[#111111] dark:text-[#FFFFFF] flex items-center gap-2">
                <CornerDownRight className="h-4 w-4 text-[#737373]" />
                Destination &amp; Normalization Analysis
              </h3>
              <div className="rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FAFAFA] dark:bg-[#111111] p-3 text-xs space-y-2">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <div>
                    <span className="text-[10px] text-[#737373] block">Submitted Input:</span>
                    <span className="font-mono text-[#111111] dark:text-[#FFFFFF] break-all">{activeResult.normalization.raw_input}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-[#737373] block">Canonical Normalized URL:</span>
                    <span className="font-mono text-[#111111] dark:text-[#FFFFFF] break-all">{activeResult.normalization.normalized_url}</span>
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-[#E5E5E5] dark:border-[#262626] text-[11px]">
                  <div>
                    <span className="text-[#737373] block">Hostname:</span>
                    <span className="font-semibold text-[#111111] dark:text-[#FFFFFF]">{activeResult.normalization.ascii_hostname}</span>
                  </div>
                  <div>
                    <span className="text-[#737373] block">Host Format:</span>
                    <span className="font-semibold text-[#111111] dark:text-[#FFFFFF]">
                      {activeResult.normalization.is_ip ? `Raw IPv${activeResult.normalization.ip_version}` : 'Domain Name'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[#737373] block">Punycode / IDN:</span>
                    <span className="font-semibold text-[#111111] dark:text-[#FFFFFF]">
                      {activeResult.normalization.is_punycode ? 'Yes (Punycode)' : 'Standard ASCII'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[#737373] block">Port:</span>
                    <span className="font-semibold text-[#111111] dark:text-[#FFFFFF]">
                      {activeResult.normalization.port || (activeResult.normalization.scheme === 'https' ? '443 (default)' : '80 (default)')}
                    </span>
                  </div>
                </div>

                {activeResult.normalization.has_homograph_chars && (
                  <div className="p-2 rounded bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/40 text-red-700 dark:text-red-300 text-xs flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold">Homograph Risk Detected: </span>
                      <span>Target contains lookalike Unicode characters mimicking Latin letters.</span>
                    </div>
                  </div>
                )}
              </div>
            </Card>
          )}

          {/* Redirect-Hop Timeline */}
          <Card className="space-y-3 border-[#E5E5E5] dark:border-[#262626]" interactive={false}>
            <h3 className="text-xs font-semibold text-[#111111] dark:text-[#FFFFFF] flex items-center gap-2">
              <Layers className="h-4 w-4 text-[#737373]" />
              Redirect-Hop Timeline
            </h3>
            {activeResult.redirect_analysis && activeResult.redirect_analysis.redirect_chain.length > 0 ? (
              <div className="rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FAFAFA] dark:bg-[#111111] p-3 space-y-3">
                <div className="space-y-2 text-xs">
                  {activeResult.redirect_analysis.redirect_chain.map((hop) => (
                    <div key={hop.hop_number} className="flex items-start gap-3 pl-1">
                      <div className="flex flex-col items-center">
                        <span className="h-5 w-5 rounded-full bg-[#E5E5E5] dark:bg-[#262626] flex items-center justify-center text-[10px] font-bold text-[#111111] dark:text-[#FFFFFF]">
                          {hop.hop_number}
                        </span>
                        <span className="w-0.5 h-6 bg-[#E5E5E5] dark:bg-[#262626] mt-1"></span>
                      </div>
                      <div className="flex-1 pb-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-semibold text-[#111111] dark:text-[#FFFFFF] text-xs">{hop.url}</span>
                          <span className="text-[10px] bg-[#E5E5E5] dark:bg-[#262626] px-1.5 py-0.5 rounded text-[#737373]">
                            HTTP {hop.status_code}
                          </span>
                        </div>
                        <div className="text-[11px] text-[#737373] mt-0.5 flex gap-3">
                          <span>IP: {hop.resolved_ip}</span>
                          {hop.hostname_changed && <span className="text-amber-500 font-medium">Cross-domain change</span>}
                          {hop.scheme_downgraded && <span className="text-red-500 font-medium">HTTPS to HTTP downgrade</span>}
                        </div>
                      </div>
                    </div>
                  ))}
                  {/* Final Destination */}
                  <div className="flex items-start gap-3 pl-1">
                    <div className="flex flex-col items-center">
                      <span className="h-5 w-5 rounded-full bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 flex items-center justify-center text-[10px] font-bold">
                        ✓
                      </span>
                    </div>
                    <div className="flex-1">
                      <span className="text-[10px] text-[#737373] block">Final Destination:</span>
                      <span className="font-mono font-bold text-[#111111] dark:text-[#FFFFFF] text-xs break-all">
                        {activeResult.redirect_analysis.final_url}
                      </span>
                      <div className="text-[11px] text-[#737373] mt-0.5">
                        Status: HTTP {activeResult.redirect_analysis.final_status_code || 200} • IP: {activeResult.redirect_analysis.final_resolved_ip || 'Resolved'}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-lg border border-[#E5E5E5] dark:border-[#262626] bg-[#FAFAFA] dark:bg-[#111111] p-3 text-xs text-[#737373] flex items-center justify-between">
                <span>No HTTP redirect hops observed. Target responded directly without forwarding.</span>
                <span className="text-[11px] font-mono text-[#737373]">1 Hop Direct</span>
              </div>
            )}
          </Card>

          {/* Diagnostic Log */}
          <div className="border-t border-[#E5E5E5] dark:border-[#262626] pt-3">
            <button
              type="button"
              onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
              className="flex items-center gap-1.5 text-xs font-semibold text-[#737373] hover:text-[#111111] dark:hover:text-[#FFFFFF] transition-colors"
            >
              {showTechnicalDetails ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              {showTechnicalDetails ? 'Hide Raw Technical Telemetry' : 'View Raw Technical Telemetry & Diagnostic Data'}
            </button>

            {showTechnicalDetails && (
              <div className="mt-3 rounded-lg bg-[#111111] border border-[#262626] p-4 font-mono text-[11px] text-[#FFFFFF] overflow-x-auto space-y-2">
                <p className="text-[#737373]">{`// Cyclops Technical Diagnostic Log`}</p>
                <div>Scan ID: {activeResult.id}</div>
                <div>Submitted URL: {activeResult.url}</div>
                <div>Verdict: {activeResult.verdict}</div>
                <div>Threat Score: {activeResult.threat_score ?? (activeResult.riskScore / 10)}</div>
                {activeResult.missing_data_notes && activeResult.missing_data_notes.length > 0 && (
                  <div className="pt-2 text-amber-400">
                    [Data Caveats / Unconfigured Integrations]:
                    {activeResult.missing_data_notes.map((m, i) => (
                      <div key={i} className="pl-3 text-zinc-400">
                        - {m}
                      </div>
                    ))}
                  </div>
                )}
                {activeResult.signals && activeResult.signals.length > 0 && (
                  <div className="pt-2">
                    [Signals Fired]:
                    {activeResult.signals.map((sig, i) => (
                      <div key={i} className="pl-3 text-zinc-400">
                        [{sig.severity.toUpperCase()}] {sig.id} (weight {sig.weight}): {sig.title}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Recent URL Scans History Table */}
      <Card className="space-y-4" interactive={false}>
        <div className="flex items-center justify-between border-b border-[#E5E5E5] dark:border-[#262626] pb-3">
          <h3 className="text-sm font-semibold text-[#111111] dark:text-[#FFFFFF] flex items-center gap-2">
            <History className="h-4 w-4 text-[#737373]" />
            Recent Scan History
          </h3>
          <span className="text-xs text-[#737373]">{urlScans.length} scans total</span>
        </div>

        <div className="divide-y divide-[#E5E5E5] dark:divide-[#262626]">
          {urlScans.map((scan) => (
            <div
              key={scan.id}
              onClick={() => setActiveResult(scan)}
              className="flex items-center justify-between py-2.5 px-2 rounded-lg hover:bg-[#FAFAFA] dark:hover:bg-[#262626] cursor-pointer transition-colors"
            >
              <div className="min-w-0 pr-4">
                <p className="text-xs font-semibold text-[#111111] dark:text-[#FFFFFF] truncate font-mono">{scan.url}</p>
                <p className="text-[11px] text-[#737373]">
                  {scan.domainInfo.domain} • {scan.domainInfo.location}
                  {scan.isLiveScan && ' • (Live API)'}
                </p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <Badge level={scan.riskLevel}>{scan.verdict}</Badge>
                <span className="text-[10px] text-[#737373]">{scan.timestamp}</span>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
