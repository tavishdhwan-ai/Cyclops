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
} from 'lucide-react';

export default function UrlScannerPage() {
  const { urlScans, scanUrl } = useDemoContext();
  const [inputUrl, setInputUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState('');
  const [activeResult, setActiveResult] = useState<UrlScanResult | null>(urlScans[0] || null);

  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputUrl.trim()) return;

    setIsScanning(true);
    setScanStep('Resolving DNS records...');
    await new Promise((resolve) => setTimeout(resolve, 600));

    setScanStep('Checking TLS/SSL certificate authority...');
    await new Promise((resolve) => setTimeout(resolve, 600));

    setScanStep('Evaluating AI threat signals & domain age...');
    await new Promise((resolve) => setTimeout(resolve, 600));

    const result = await scanUrl(inputUrl);
    setActiveResult(result);
    setIsScanning(false);
    setScanStep('');
  };

  const setPresetUrl = (url: string) => {
    setInputUrl(url);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Page Header */}
      <div className="border-b border-zinc-800 pb-4">
        <h1 className="text-xl font-bold text-zinc-100 flex items-center gap-2">
          <Globe className="h-5 w-5 text-zinc-400" />
          Real-Time URL & Domain Scanner
        </h1>
        <p className="text-xs text-zinc-400 mt-1">
          Inspect malicious links, typosquatted domains, and credential harvesting landing pages.
        </p>
      </div>

      {/* Input Card */}
      <Card className="space-y-4">
        <form onSubmit={handleScanSubmit} className="space-y-3">
          <label className="block text-xs font-semibold text-zinc-200">Target URL or Domain</label>
          <div className="flex flex-col sm:flex-row gap-2">
            <div className="relative flex-1">
              <Globe className="absolute left-3.5 top-3 h-4 w-4 text-zinc-500" />
              <input
                type="text"
                value={inputUrl}
                onChange={(e) => setInputUrl(e.target.value)}
                placeholder="e.g. login-verify-acme-update.com or https://github.com"
                className="w-full rounded-lg border border-zinc-800 bg-zinc-950 pl-10 pr-4 py-2.5 text-xs text-zinc-100 placeholder-zinc-500 focus:border-zinc-700 focus:outline-hidden"
              />
            </div>
            <button
              type="submit"
              disabled={isScanning || !inputUrl.trim()}
              className="flex items-center justify-center gap-2 rounded-lg bg-zinc-100 px-5 py-2.5 text-xs font-semibold text-zinc-900 hover:bg-white disabled:opacity-50 transition-colors shrink-0"
            >
              {isScanning ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Search className="h-4 w-4" />
                  Scan Link
                </>
              )}
            </button>
          </div>
        </form>

        {/* Quick presets */}
        <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-zinc-800/60">
          <span className="text-[11px] text-zinc-400">Sample URL Presets:</span>
          <button
            onClick={() => setPresetUrl('login-verify-acme-update.com/auth')}
            className="rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-1 text-xs text-zinc-400 hover:border-zinc-700 hover:text-zinc-200"
          >
            Phishing Landing Page
          </button>
          <button
            onClick={() => setPresetUrl('cdn-update-software-fix.ru/patch.bin')}
            className="rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-1 text-xs text-zinc-400 hover:border-zinc-700 hover:text-zinc-200"
          >
            Malware Binary Download
          </button>
          <button
            onClick={() => setPresetUrl('github.com')}
            className="rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-1 text-xs text-zinc-400 hover:border-zinc-700 hover:text-zinc-200"
          >
            Safe Domain (github.com)
          </button>
        </div>
      </Card>

      {/* Scanning loading progress indicator */}
      {isScanning && (
        <Card className="text-center py-8 space-y-3">
          <Loader2 className="h-7 w-7 text-zinc-300 animate-spin mx-auto" />
          <div>
            <p className="text-xs font-semibold text-zinc-200">Analyzing URL Telemetry...</p>
            <p className="text-[11px] text-zinc-400 mt-0.5">{scanStep}</p>
          </div>
        </Card>
      )}

      {/* Active Scan Result Display */}
      {!isScanning && activeResult && (
        <div className="space-y-6">
          <Card className="space-y-6 border-zinc-700/60">
            {/* Verdict Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800 pb-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
                    Scan Verdict
                  </span>
                  <Badge level={activeResult.riskLevel}>{activeResult.verdict.toUpperCase()}</Badge>
                </div>
                <h2 className="text-base font-bold text-zinc-100 font-mono break-all">
                  {activeResult.url}
                </h2>
                <p className="text-[11px] text-zinc-500 mt-0.5">Scanned: {activeResult.timestamp}</p>
              </div>

              <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3 text-center shrink-0 min-w-32">
                <span className="text-[10px] text-zinc-500 uppercase tracking-wider block">
                  Threat Index
                </span>
                <span
                  className={`text-2xl font-black ${
                    activeResult.riskScore > 50 ? 'text-red-400' : 'text-emerald-400'
                  }`}
                >
                  {activeResult.riskScore} / 100
                </span>
              </div>
            </div>

            {/* Domain Telemetry Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3">
                <p className="text-[10px] text-zinc-500">Domain Name</p>
                <p className="font-semibold text-zinc-200 truncate mt-0.5">{activeResult.domainInfo.domain}</p>
              </div>
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3">
                <p className="text-[10px] text-zinc-500">Registrar & Age</p>
                <p className="font-semibold text-zinc-200 mt-0.5">
                  {activeResult.domainInfo.registeredDaysAgo} days old
                </p>
              </div>
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3">
                <p className="text-[10px] text-zinc-500">IP Host Location</p>
                <p className="font-semibold text-zinc-200 truncate mt-0.5">{activeResult.domainInfo.location}</p>
              </div>
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3">
                <p className="text-[10px] text-zinc-500">SSL Certificate</p>
                <p className="font-semibold text-zinc-200 truncate mt-0.5">
                  {activeResult.domainInfo.sslValid ? 'Valid TLS' : 'Unencrypted'}
                </p>
              </div>
            </div>

            {/* Suspicious Signals */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-zinc-300">Detected Risk Signals</h3>
              {activeResult.suspiciousSignals.length > 0 ? (
                <div className="space-y-1.5">
                  {activeResult.suspiciousSignals.map((signal, idx) => (
                    <div
                      key={idx}
                      className="rounded-lg border border-red-900/40 bg-red-950/20 p-2.5 flex items-center gap-2.5 text-xs text-red-300"
                    >
                      <AlertTriangle className="h-4 w-4 shrink-0 text-red-400" />
                      <span>{signal}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="rounded-lg border border-emerald-900/40 bg-emerald-950/20 p-2.5 text-xs text-emerald-300 flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  No suspicious threat signals found. URL appears legitimate.
                </div>
              )}
            </div>

            {/* AI Recommendation */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3.5 space-y-1">
              <span className="text-[11px] font-semibold text-zinc-400">SentinelAI Recommended Action</span>
              <p className="text-xs font-medium text-zinc-200">{activeResult.recommendedAction}</p>
            </div>
          </Card>
        </div>
      )}

      {/* Recent URL Scans History Table */}
      <Card className="space-y-4">
        <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
          <h3 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
            <History className="h-4 w-4 text-zinc-400" />
            Recent Scan History
          </h3>
          <span className="text-xs text-zinc-500">{urlScans.length} scans total</span>
        </div>

        <div className="divide-y divide-zinc-800/60">
          {urlScans.map((scan) => (
            <div
              key={scan.id}
              onClick={() => setActiveResult(scan)}
              className="flex items-center justify-between py-2.5 px-2 rounded-lg hover:bg-zinc-800/40 cursor-pointer transition-colors"
            >
              <div className="min-w-0 pr-4">
                <p className="text-xs font-semibold text-zinc-200 truncate font-mono">{scan.url}</p>
                <p className="text-[11px] text-zinc-500">
                  {scan.domainInfo.domain} • {scan.domainInfo.location}
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
