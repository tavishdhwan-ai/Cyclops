'use client';

import React, { useState } from 'react';
import { useDemoContext } from '../../context/DemoContext';
import { Card } from '../../components/ui/Card';
import { Badge } from '../../components/ui/Badge';
import { UrlScanResult } from '../../types';
import {
  Globe,
  Search,
  ShieldCheck,
  ShieldAlert,
  Loader2,
  AlertTriangle,
  Server,
  Lock,
  ArrowRight,
  ExternalLink,
  History,
  Info,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Clock,
  Layers,
  FileCode,
  Network,
  CornerDownRight,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  AlertOctagon,
} from 'lucide-react';

export default function UrlScannerPage() {
  const { urlScans, scanUrl } = useDemoContext();
  const [inputUrl, setInputUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState('');
  const [activeResult, setActiveResult] = useState<UrlScanResult | null>(urlScans[0] || null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputUrl.trim()) return;

    setIsScanning(true);
    setScanError(null);
    setScanStep('Validating input syntax & normalizing scheme...');

    try {
      // Show genuine pipeline stages briefly as backend computes
      const progressTimer = setTimeout(() => {
        setScanStep('Resolving DNS & enforcing SSRF boundaries...');
      }, 400);

      const progressTimer2 = setTimeout(() => {
        setScanStep('Inspecting redirect hops & querying hosting intelligence...');
      }, 900);

      const result = await scanUrl(inputUrl.trim());
      clearTimeout(progressTimer);
      clearTimeout(progressTimer2);

      setActiveResult(result);
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
      <div className="border-b border-zinc-200 dark:border-zinc-800 pb-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h1 className="text-xl font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
              <Globe className="h-5 w-5 text-zinc-500 dark:text-zinc-400" />
              Website URL Security Scanner
            </h1>
            <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
              Production-grade passive URL intelligence, SSRF-protected redirect analysis, RDAP domain registration, and hosting telemetry.
            </p>
          </div>
          <div className="flex items-center gap-2 text-[11px] text-zinc-500 bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-md px-2.5 py-1 shrink-0">
            <span className="inline-block h-2 w-2 rounded-full bg-emerald-500"></span>
            Non-executing static inspection mode
          </div>
        </div>
      </div>

      {/* Input Card */}
      <Card className="space-y-4" interactive={false}>
        <form onSubmit={handleScanSubmit} className="space-y-3">
          <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-200">
            Target URL or Domain Name
          </label>
          <div className="flex flex-col sm:flex-row gap-2">
            <div className="relative flex-1">
              <Globe className="absolute left-3.5 top-3 h-4 w-4 text-zinc-400 dark:text-zinc-500" />
              <input
                type="text"
                value={inputUrl}
                onChange={(e) => {
                  setInputUrl(e.target.value);
                  if (scanError) setScanError(null);
                }}
                placeholder="e.g. github.com or https://example.com/login"
                className="w-full rounded-lg border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 pl-10 pr-4 py-2.5 text-xs text-zinc-900 dark:text-zinc-100 placeholder-zinc-500 focus:border-zinc-500 dark:focus:border-zinc-700 focus:outline-hidden"
              />
            </div>
            <button
              type="submit"
              disabled={isScanning || !inputUrl.trim()}
              className="flex items-center justify-center gap-2 rounded-lg bg-zinc-900 dark:bg-zinc-100 px-5 py-2.5 text-xs font-semibold text-white dark:text-zinc-900 hover:bg-zinc-800 dark:hover:bg-white disabled:opacity-50 transition-colors shrink-0"
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
          <div className="rounded-lg border border-red-300 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 p-3 text-xs text-red-700 dark:text-red-300 flex items-start justify-between gap-3">
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
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-zinc-200 dark:border-zinc-800/60">
          <span className="text-[11px] text-zinc-500 dark:text-zinc-400">Quick Test Candidates:</span>
          <button
            type="button"
            onClick={() => setPresetUrl('github.com')}
            className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-2.5 py-1 text-xs text-zinc-600 dark:text-zinc-400 hover:border-zinc-500 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-200"
          >
            github.com (Verified Domain)
          </button>
          <button
            type="button"
            onClick={() => setPresetUrl('example.com')}
            className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-2.5 py-1 text-xs text-zinc-600 dark:text-zinc-400 hover:border-zinc-500 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-200"
          >
            example.com (Standard Web)
          </button>
          <button
            type="button"
            onClick={() => setPresetUrl('127.0.0.1:8000')}
            className="rounded-md border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-2.5 py-1 text-xs text-zinc-600 dark:text-zinc-400 hover:border-zinc-500 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-200"
          >
            127.0.0.1 (SSRF Test)
          </button>
        </div>
      </Card>

      {/* Scanning Stage Progress Indicator */}
      {isScanning && (
        <Card className="text-center py-8 space-y-3" interactive={false}>
          <Loader2 className="h-7 w-7 text-zinc-500 dark:text-zinc-400 animate-spin mx-auto" />
          <div>
            <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-200">Executing Multi-Signal Inspection Pipeline...</p>
            <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-1 font-mono">{scanStep}</p>
          </div>
          <div className="flex justify-center items-center gap-4 text-[10px] text-zinc-400 dark:text-zinc-500 pt-2">
            <span>• Non-executing client</span>
            <span>• Pre-flight DNS validation</span>
            <span>• SSRF enforcement</span>
            <span>• RDAP registry lookup</span>
          </div>
        </Card>
      )}

      {/* Active Scan Result Display */}
      {!isScanning && activeResult && (
        <div className="space-y-6">
          <Card className="space-y-6 border-zinc-200 dark:border-zinc-800" interactive={false}>
            {/* Verdict Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-200 dark:border-zinc-800 pb-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                    Security Verdict
                  </span>
                  <Badge level={activeResult.riskLevel}>{activeResult.verdict.toUpperCase()}</Badge>
                  {activeResult.isLiveScan && (
                    <span className="text-[10px] bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 px-2 py-0.5 rounded font-medium">
                      Live Backend Result
                    </span>
                  )}
                </div>
                <h2 className="text-base font-bold text-zinc-900 dark:text-zinc-100 font-mono break-all">
                  {activeResult.url}
                </h2>
                <p className="text-[11px] text-zinc-500 mt-0.5">Scanned: {activeResult.timestamp}</p>
              </div>

              <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 text-center shrink-0 min-w-36">
                <span className="text-[10px] text-zinc-500 uppercase tracking-wider block">
                  Threat Index
                </span>
                <span
                  className={`text-2xl font-black ${
                    activeResult.riskScore > 50
                      ? 'text-red-500 dark:text-red-400'
                      : activeResult.riskScore > 24
                      ? 'text-amber-500 dark:text-amber-400'
                      : 'text-emerald-500 dark:text-emerald-400'
                  }`}
                >
                  {activeResult.threat_score !== undefined ? activeResult.threat_score.toFixed(1) : (activeResult.riskScore / 10).toFixed(1)} / 10.0
                </span>
                <span className="text-[9px] text-zinc-400 block mt-0.5">Continuous Threat Scale</span>
              </div>
            </div>

            {/* Plain English Assessment */}
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                <Info className="h-4 w-4 text-zinc-500" />
                Assessment Summary
              </div>
              <p className="text-xs text-zinc-700 dark:text-zinc-300 leading-relaxed">
                {activeResult.plain_english_explanation || activeResult.summary || 'URL scan completed.'}
              </p>
              <div className="pt-2 border-t border-zinc-200 dark:border-zinc-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px]">
                <span className="font-semibold text-zinc-600 dark:text-zinc-400">
                  Recommended Action: <span className="font-normal text-zinc-900 dark:text-zinc-200">{activeResult.recommendedAction}</span>
                </span>
              </div>
            </div>

            {/* Reassuring vs Risk Evidence Split */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Risk Factors */}
              <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3.5 space-y-2 bg-white dark:bg-zinc-900/40">
                <div className="flex items-center gap-2 text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                  <AlertTriangle className="h-4 w-4 text-amber-500" />
                  Elevated Risk Indicators
                </div>
                {activeResult.risk_factors && activeResult.risk_factors.length > 0 ? (
                  <ul className="space-y-1.5 text-xs text-zinc-600 dark:text-zinc-400">
                    {activeResult.risk_factors.map((rf, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-amber-500 font-bold">•</span>
                        <span>{rf}</span>
                      </li>
                    ))}
                  </ul>
                ) : activeResult.suspiciousSignals.length > 0 ? (
                  <ul className="space-y-1.5 text-xs text-zinc-600 dark:text-zinc-400">
                    {activeResult.suspiciousSignals.map((sig, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-amber-500 font-bold">•</span>
                        <span>{sig}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-zinc-500 italic">No significant risk indicators identified.</p>
                )}
              </div>

              {/* Reassuring Factors */}
              <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3.5 space-y-2 bg-white dark:bg-zinc-900/40">
                <div className="flex items-center gap-2 text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                  <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                  Reassuring Evidence
                </div>
                {activeResult.reassuring_factors && activeResult.reassuring_factors.length > 0 ? (
                  <ul className="space-y-1.5 text-xs text-zinc-600 dark:text-zinc-400">
                    {activeResult.reassuring_factors.map((rf, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-emerald-500 font-bold">✓</span>
                        <span>{rf}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-zinc-500 italic">Standard web property evidence without positive reputation badges.</p>
                )}
              </div>
            </div>

            {/* Feature: Destination & Normalization Details */}
            {activeResult.normalization && (
              <div className="space-y-2">
                <h3 className="text-xs font-semibold text-zinc-900 dark:text-zinc-300 flex items-center gap-2">
                  <CornerDownRight className="h-4 w-4 text-zinc-400" />
                  Destination & Normalization Analysis
                </h3>
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 text-xs space-y-2">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <div>
                      <span className="text-[10px] text-zinc-500 block">Submitted Input:</span>
                      <span className="font-mono text-zinc-900 dark:text-zinc-200 break-all">{activeResult.normalization.raw_input}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-zinc-500 block">Canonical Normalized URL:</span>
                      <span className="font-mono text-zinc-900 dark:text-zinc-200 break-all">{activeResult.normalization.normalized_url}</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-zinc-200 dark:border-zinc-800/60 text-[11px]">
                    <div>
                      <span className="text-zinc-500 block">Hostname:</span>
                      <span className="font-semibold text-zinc-900 dark:text-zinc-200">{activeResult.normalization.ascii_hostname}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500 block">Host Format:</span>
                      <span className="font-semibold text-zinc-900 dark:text-zinc-200">
                        {activeResult.normalization.is_ip ? `Raw IPv${activeResult.normalization.ip_version}` : 'Domain Name'}
                      </span>
                    </div>
                    <div>
                      <span className="text-zinc-500 block">Punycode / IDN:</span>
                      <span className="font-semibold text-zinc-900 dark:text-zinc-200">
                        {activeResult.normalization.is_punycode ? 'Yes (Punycode)' : 'Standard ASCII'}
                      </span>
                    </div>
                    <div>
                      <span className="text-zinc-500 block">Port:</span>
                      <span className="font-semibold text-zinc-900 dark:text-zinc-200">
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
              </div>
            )}

            {/* Feature: Redirect-Hop Timeline */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-zinc-900 dark:text-zinc-300 flex items-center gap-2">
                <Layers className="h-4 w-4 text-zinc-400" />
                Redirect-Hop Timeline
              </h3>
              {activeResult.redirect_analysis && activeResult.redirect_analysis.redirect_chain.length > 0 ? (
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 space-y-3">
                  <div className="space-y-2 text-xs">
                    {activeResult.redirect_analysis.redirect_chain.map((hop) => (
                      <div key={hop.hop_number} className="flex items-start gap-3 pl-1">
                        <div className="flex flex-col items-center">
                          <span className="h-5 w-5 rounded-full bg-zinc-200 dark:bg-zinc-800 flex items-center justify-center text-[10px] font-bold text-zinc-700 dark:text-zinc-300">
                            {hop.hop_number}
                          </span>
                          <span className="w-0.5 h-6 bg-zinc-200 dark:bg-zinc-800 mt-1"></span>
                        </div>
                        <div className="flex-1 pb-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-semibold text-zinc-900 dark:text-zinc-200 text-xs">{hop.url}</span>
                            <span className="text-[10px] bg-zinc-200 dark:bg-zinc-800 px-1.5 py-0.5 rounded text-zinc-600 dark:text-zinc-400">
                              HTTP {hop.status_code}
                            </span>
                          </div>
                          <div className="text-[11px] text-zinc-500 mt-0.5 flex gap-3">
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
                        <span className="text-[10px] text-zinc-500 block">Final Destination:</span>
                        <span className="font-mono font-bold text-zinc-900 dark:text-zinc-100 text-xs break-all">
                          {activeResult.redirect_analysis.final_url}
                        </span>
                        <div className="text-[11px] text-zinc-500 mt-0.5">
                          Status: HTTP {activeResult.redirect_analysis.final_status_code || 200} • IP: {activeResult.redirect_analysis.final_resolved_ip || 'Resolved'}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 text-xs text-zinc-500 flex items-center justify-between">
                  <span>No HTTP redirect hops observed. Target responded directly without forwarding.</span>
                  <span className="text-[11px] font-mono text-zinc-400">1 Hop Direct</span>
                </div>
              )}
            </div>

            {/* Feature: Domain Age & Infrastructure Telemetry Grid */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-zinc-900 dark:text-zinc-300 flex items-center gap-2">
                <Network className="h-4 w-4 text-zinc-400" />
                Domain Registration & Network Telemetry
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                {/* Domain Registration */}
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3">
                  <p className="text-[10px] text-zinc-500 uppercase tracking-wider">Domain Registration (RDAP)</p>
                  <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-1 truncate">
                    {activeResult.domain_registration?.registrar || activeResult.domainInfo.registrar}
                  </p>
                  <p className="text-[11px] text-zinc-500 mt-0.5">
                    {typeof activeResult.domain_registration?.domain_age_days === 'number' && activeResult.domain_registration.domain_age_days >= 0
                      ? `${activeResult.domain_registration.domain_age_days} days old (${activeResult.domain_registration.created_date || 'N/A'})`
                      : activeResult.domainInfo.registeredDaysAgo >= 0
                      ? `${activeResult.domainInfo.registeredDaysAgo} days old`
                      : 'Not available (IP or private)'}
                  </p>
                </div>

                {/* Hosting & ASN */}
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3">
                  <p className="text-[10px] text-zinc-500 uppercase tracking-wider">Hosting & ASN Provider</p>
                  <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-1 truncate">
                    {activeResult.hosting_intelligence?.organization || 'Cloud / CDN Provider'}
                  </p>
                  <p className="text-[11px] text-zinc-500 mt-0.5 truncate">
                    {activeResult.hosting_intelligence?.asn || 'Autonomous System N/A'}
                  </p>
                </div>

                {/* IP Geolocation */}
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3">
                  <p className="text-[10px] text-zinc-500 uppercase tracking-wider">IP Host Location</p>
                  <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-1 truncate">
                    {activeResult.hosting_intelligence?.country
                      ? `${activeResult.hosting_intelligence.city ? activeResult.hosting_intelligence.city + ', ' : ''}${activeResult.hosting_intelligence.country}`
                      : activeResult.domainInfo.location}
                  </p>
                  <p className="text-[11px] text-zinc-500 mt-0.5 truncate font-mono">
                    {activeResult.hosting_intelligence?.ip_address || activeResult.domainInfo.ipAddress}
                  </p>
                </div>

                {/* TLS & Encryption */}
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3">
                  <p className="text-[10px] text-zinc-500 uppercase tracking-wider">Transport Encryption</p>
                  <p className="font-semibold text-zinc-900 dark:text-zinc-200 mt-1 truncate">
                    {activeResult.domainInfo.sslValid ? 'TLS / HTTPS Verified' : 'Unencrypted HTTP'}
                  </p>
                  <p className="text-[11px] text-zinc-500 mt-0.5 truncate">
                    {activeResult.domainInfo.sslIssuer}
                  </p>
                </div>
              </div>

              {activeResult.hosting_intelligence?.contextual_note && (
                <p className="text-[11px] text-zinc-500 italic px-1">
                  Context: {activeResult.hosting_intelligence.contextual_note}
                </p>
              )}
            </div>

            {/* Feature: Safe Static Page Inspection Findings */}
            {activeResult.page_content && (
              <div className="space-y-2">
                <h3 className="text-xs font-semibold text-zinc-900 dark:text-zinc-300 flex items-center gap-2">
                  <FileCode className="h-4 w-4 text-zinc-400" />
                  Read-Only Page Structure Inspection
                </h3>
                <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3.5 text-xs space-y-2.5">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <span className="font-medium text-zinc-900 dark:text-zinc-200">
                      Page Title: <span className="font-normal italic">{activeResult.page_content.title || 'No HTML title tag detected'}</span>
                    </span>
                    <span className="text-[10px] bg-zinc-200 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 px-2 py-0.5 rounded">
                      {activeResult.page_content.forms_found.length} form(s) parsed
                    </span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-zinc-200 dark:border-zinc-800/60 text-[11px]">
                    <div>
                      <span className="text-zinc-500 block">Password Fields:</span>
                      <span className="font-semibold text-zinc-900 dark:text-zinc-200">
                        {activeResult.page_content.has_password_input ? 'Present (Form input)' : 'None detected'}
                      </span>
                    </div>
                    <div>
                      <span className="text-zinc-500 block">External Form Action:</span>
                      <span className="font-semibold text-zinc-900 dark:text-zinc-200">
                        {activeResult.page_content.has_external_form_action ? 'Warning: External Post' : 'Same-origin or N/A'}
                      </span>
                    </div>
                    <div>
                      <span className="text-zinc-500 block">Script Tags:</span>
                      <span className="font-semibold text-zinc-900 dark:text-zinc-200">
                        {activeResult.page_content.script_count} (Unexecuted)
                      </span>
                    </div>
                    <div>
                      <span className="text-zinc-500 block">Iframe Tags:</span>
                      <span className="font-semibold text-zinc-900 dark:text-zinc-200">
                        {activeResult.page_content.iframe_count}
                      </span>
                    </div>
                  </div>

                  {activeResult.page_content.limitations.length > 0 && (
                    <div className="text-[10px] text-zinc-500 pt-1 flex flex-wrap gap-x-4">
                      {activeResult.page_content.limitations.map((lim, i) => (
                        <span key={i}>• {lim}</span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Feature: Reputation Provider Results (Explicitly Handled States) */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-zinc-900 dark:text-zinc-300 flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-zinc-400" />
                External Threat Intelligence Sources
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                {activeResult.reputation_providers && activeResult.reputation_providers.length > 0 ? (
                  activeResult.reputation_providers.map((prov, idx) => (
                    <div key={idx} className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-zinc-900 dark:text-zinc-200">{prov.provider_name}</span>
                        {prov.status === 'clean' && (
                          <span className="text-[10px] text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 px-1.5 py-0.5 rounded font-medium">
                            Clean
                          </span>
                        )}
                        {prov.status === 'malicious_found' && (
                          <span className="text-[10px] text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950/40 px-1.5 py-0.5 rounded font-medium">
                            Threat Found
                          </span>
                        )}
                        {(prov.status === 'not_configured' || prov.status === 'unavailable') && (
                          <span className="text-[10px] text-zinc-500 bg-zinc-200 dark:bg-zinc-800 px-1.5 py-0.5 rounded">
                            {prov.status === 'not_configured' ? 'Not configured' : 'Unavailable'}
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-zinc-500">
                        {prov.threat_details || prov.error_message || 'Status verified.'}
                      </p>
                    </div>
                  ))
                ) : (
                  <div className="col-span-3 text-xs text-zinc-500 italic p-2 border border-dashed border-zinc-200 dark:border-zinc-800 rounded-lg text-center">
                    No external intelligence providers queried for this sample scan.
                  </div>
                )}
              </div>
            </div>

            {/* Expandable Technical Evidence & Diagnostics */}
            <div className="border-t border-zinc-200 dark:border-zinc-800 pt-3">
              <button
                type="button"
                onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
                className="flex items-center gap-1.5 text-xs font-semibold text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-200 transition-colors"
              >
                {showTechnicalDetails ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                {showTechnicalDetails ? 'Hide Raw Technical Telemetry' : 'View Raw Technical Telemetry & Diagnostic Data'}
              </button>

              {showTechnicalDetails && (
                <div className="mt-3 rounded-lg bg-zinc-950 border border-zinc-800 p-4 font-mono text-[11px] text-zinc-300 overflow-x-auto space-y-2">
                  <p className="text-zinc-500">// Cyclops Technical Diagnostic Log</p>
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
          </Card>
        </div>
      )}

      {/* Recent URL Scans History Table */}
      <Card className="space-y-4" interactive={false}>
        <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800 pb-3">
          <h3 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
            <History className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            Recent Scan History
          </h3>
          <span className="text-xs text-zinc-500">{urlScans.length} scans total</span>
        </div>

        <div className="divide-y divide-zinc-200 dark:divide-zinc-800/60">
          {urlScans.map((scan) => (
            <div
              key={scan.id}
              onClick={() => setActiveResult(scan)}
              className="flex items-center justify-between py-2.5 px-2 rounded-lg hover:bg-zinc-50 dark:hover:bg-zinc-800/40 cursor-pointer transition-colors"
            >
              <div className="min-w-0 pr-4">
                <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-200 truncate font-mono">{scan.url}</p>
                <p className="text-[11px] text-zinc-500">
                  {scan.domainInfo.domain} • {scan.domainInfo.location}
                  {scan.isLiveScan && ' • (Live API)'}
                </p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <Badge level={scan.riskLevel}>{scan.verdict}</Badge>
                <span className="text-[10px] text-zinc-500">{scan.timestamp}</span>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
