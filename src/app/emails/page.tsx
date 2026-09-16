'use client';

import React, { useState, useEffect } from 'react';
import { useDemoContext } from '../../context/DemoContext';
import { EmailViewer } from '../../components/email-security/EmailViewer';
import { SentinelAnalysisPanel } from '../../components/email-security/SentinelAnalysisPanel';
import { DetailedReportModal } from '../../components/email-security/DetailedReportModal';
import {
  Mail,
  RotateCw,
  Info,
} from 'lucide-react';

export default function EmailSecurityPage() {
  const { rescanKey, triggerRescan, emailReviewStatus, setEmailReviewStatus, showToast } =
    useDemoContext();

  const [isScanning, setIsScanning] = useState(true);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStep, setScanStep] = useState('Initializing SentinelAI scanner...');
  const [isReportOpen, setIsReportOpen] = useState(false);

  // Handle scanning simulation (1.5 - 2s duration)
  useEffect(() => {
    setIsScanning(true);
    setScanProgress(10);
    setScanStep('Checking sender domain & authentication signatures...');

    const step1 = setTimeout(() => {
      setScanProgress(40);
      setScanStep('Scanning email text & urgency indicators...');
    }, 500);

    const step2 = setTimeout(() => {
      setScanProgress(75);
      setScanStep('Scanning 5 email attachments separately...');
    }, 1000);

    const step3 = setTimeout(() => {
      setScanProgress(100);
      setScanStep('Analysis complete. Phishing indicators mapped.');
    }, 1500);

    const step4 = setTimeout(() => {
      setIsScanning(false);
    }, 1800);

    return () => {
      clearTimeout(step1);
      clearTimeout(step2);
      clearTimeout(step3);
      clearTimeout(step4);
    };
  }, [rescanKey]);

  const handleMarkReviewed = () => {
    const newStatus = emailReviewStatus === 'reviewed' ? 'pending' : 'reviewed';
    setEmailReviewStatus(newStatus);
    showToast(
      newStatus === 'reviewed' ? 'Marked as Reviewed' : 'Status Reset',
      newStatus === 'reviewed'
        ? 'Email security audit marked as reviewed.'
        : 'Email returned to pending review status.',
      newStatus === 'reviewed' ? 'success' : 'info'
    );
  };

  const handleRescan = () => {
    triggerRescan();
    showToast('Rescanning Email', 'Initiating full threat scan on email and attachments...', 'info');
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-200 dark:border-zinc-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2 tracking-tight">
              <Mail className="h-5 w-5 text-zinc-600 dark:text-zinc-400" />
              Inbound Email Security Inspection
            </h1>
            <span className="rounded-full border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/40 px-2.5 py-0.5 text-[10px] font-semibold text-red-700 dark:text-red-400">
              High Risk Flagged
            </span>
          </div>
          <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-1">
            SentinelAI automatically scans sender authentication, domain age, embedded links, and individual attachments.
          </p>
        </div>

        {/* Demo Mode & Disclaimers */}
        <div className="flex items-center gap-2 shrink-0">
          <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-900 px-3 py-1 text-[11px] text-zinc-600 dark:text-zinc-400 font-medium">
            Simulated demo analysis
          </div>
          <button
            onClick={handleRescan}
            disabled={isScanning}
            className="flex items-center gap-1.5 rounded-md border border-zinc-300 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800 px-3 py-1 text-xs font-semibold text-zinc-900 dark:text-zinc-100 hover:bg-zinc-200 dark:hover:bg-zinc-700 disabled:opacity-50 transition-colors cursor-pointer"
          >
            <RotateCw className={`h-3.5 w-3.5 text-amber-500 dark:text-amber-400 ${isScanning ? 'animate-spin' : ''}`} />
            <span>Rescan Email</span>
          </button>
        </div>
      </div>

      {/* Safety Notice Strip */}
      <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/40 px-4 py-2.5 flex flex-wrap items-center justify-between text-xs gap-2">
        <div className="flex items-center gap-2 text-zinc-800 dark:text-zinc-300">
          <Info className="h-4 w-4 text-zinc-500 dark:text-zinc-400 shrink-0" />
          <span>
            <strong>Demo Mode:</strong> Demo data — no real email or attachment was scanned.
          </span>
        </div>
        <span className="text-[11px] text-zinc-500 font-mono">
          Inspection ID: em-2026-msft-phish
        </span>
      </div>

      {/* MAIN PAGE LAYOUT: Desktop Split / Mobile Stacked */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Email Viewer (7 cols) */}
        <div className="lg:col-span-7">
          <EmailViewer isScanning={isScanning} />
        </div>

        {/* Right Column: SentinelAI Analysis Panel (5 cols) */}
        <div className="lg:col-span-5">
          <SentinelAnalysisPanel
            isScanning={isScanning}
            scanProgress={scanProgress}
            scanStep={scanStep}
            onRescan={handleRescan}
            onOpenReport={() => setIsReportOpen(true)}
            reviewStatus={emailReviewStatus}
            onMarkReviewed={handleMarkReviewed}
          />
        </div>
      </div>

      {/* Detailed Report Modal */}
      <DetailedReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
        reviewStatus={emailReviewStatus}
      />
    </div>
  );
}
