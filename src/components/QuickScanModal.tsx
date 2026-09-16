'use client';

import React, { useState } from 'react';
import { Modal } from './ui/Modal';
import { useDemoContext } from '../context/DemoContext';
import { Link2, FileText, Loader2, ArrowRight } from 'lucide-react';
import { useRouter } from 'next/navigation';

export const QuickScanModal: React.FC = () => {
  const { isQuickScanOpen, setIsQuickScanOpen, scanUrl, scanDocument, showToast } = useDemoContext();
  const [scanType, setScanType] = useState<'url' | 'document'>('url');
  const [inputValue, setInputValue] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const router = useRouter();

  const handleRunScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue.trim()) return;

    setIsScanning(true);
    if (scanType === 'url') {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      await scanUrl(inputValue);
      showToast('URL Scan Complete', 'Redirecting to URL scanner overview...', 'success');
      setIsScanning(false);
      setIsQuickScanOpen(false);
      setInputValue('');
      router.push('/url-scanner');
    } else {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      await scanDocument(inputValue);
      showToast('Document Scan Complete', 'Redirecting to document scanner overview...', 'success');
      setIsScanning(false);
      setIsQuickScanOpen(false);
      setInputValue('');
      router.push('/document-scanner');
    }
  };

  return (
    <Modal
      isOpen={isQuickScanOpen}
      onClose={() => setIsQuickScanOpen(false)}
      title="Quick Security Analysis"
      subtitle="Analyze URLs, domains, or document filenames instantly in frontend demo mode."
    >
      <div className="space-y-4">
        {/* Toggle Scan Type */}
        <div className="grid grid-cols-2 gap-2 rounded-lg bg-zinc-100 dark:bg-zinc-950 p-1 border border-zinc-200 dark:border-zinc-800">
          <button
            type="button"
            onClick={() => {
              setScanType('url');
              setInputValue('');
            }}
            className={`flex items-center justify-center gap-2 rounded-md py-1.5 text-xs font-medium transition-colors ${
              scanType === 'url'
                ? 'bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 shadow-xs'
                : 'text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200'
            }`}
          >
            <Link2 className="h-3.5 w-3.5" />
            URL / Domain Scan
          </button>
          <button
            type="button"
            onClick={() => {
              setScanType('document');
              setInputValue('');
            }}
            className={`flex items-center justify-center gap-2 rounded-md py-1.5 text-xs font-medium transition-colors ${
              scanType === 'document'
                ? 'bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 shadow-xs'
                : 'text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200'
            }`}
          >
            <FileText className="h-3.5 w-3.5" />
            Document File
          </button>
        </div>

        {/* Input Form */}
        <form onSubmit={handleRunScan} className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1.5">
              {scanType === 'url' ? 'Target URL or Domain Name' : 'File Name or Attachment Name'}
            </label>
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder={
                scanType === 'url'
                  ? 'e.g. login-verify-acme-update.com'
                  : 'e.g. Vendor_Invoice_Q3.pdf.exe'
              }
              className="w-full rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 px-3.5 py-2 text-xs text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:border-zinc-400 dark:focus:border-zinc-700 focus:outline-hidden"
              required
            />
          </div>

          {/* Quick presets */}
          <div className="flex flex-wrap gap-1.5">
            <span className="text-[11px] text-zinc-500 self-center mr-1">Presets:</span>
            {scanType === 'url' ? (
              <>
                <button
                  type="button"
                  onClick={() => setInputValue('login-verify-acme-update.com')}
                  className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 px-2 py-0.5 text-[11px] text-zinc-600 dark:text-zinc-400 hover:border-zinc-300 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-200"
                >
                  Phishing Link
                </button>
                <button
                  type="button"
                  onClick={() => setInputValue('cdn-update-software-fix.ru/patch.bin')}
                  className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 px-2 py-0.5 text-[11px] text-zinc-600 dark:text-zinc-400 hover:border-zinc-300 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-200"
                >
                  Malware Download
                </button>
                <button
                  type="button"
                  onClick={() => setInputValue('github.com')}
                  className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 px-2 py-0.5 text-[11px] text-zinc-600 dark:text-zinc-400 hover:border-zinc-300 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-200"
                >
                  Safe Domain
                </button>
              </>
            ) : (
              <>
                <button
                  type="button"
                  onClick={() => setInputValue('Invoice_Update.pdf.exe')}
                  className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 px-2 py-0.5 text-[11px] text-zinc-600 dark:text-zinc-400 hover:border-zinc-300 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-200"
                >
                  Executable Trojan
                </button>
                <button
                  type="button"
                  onClick={() => setInputValue('Report_2026.xlsm')}
                  className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 px-2 py-0.5 text-[11px] text-zinc-600 dark:text-zinc-400 hover:border-zinc-300 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-200"
                >
                  Macro Excel
                </button>
                <button
                  type="button"
                  onClick={() => setInputValue('Employee_Handbook.pdf')}
                  className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 px-2 py-0.5 text-[11px] text-zinc-600 dark:text-zinc-400 hover:border-zinc-300 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-200"
                >
                  Clean PDF
                </button>
              </>
            )}
          </div>

          <div className="pt-3 flex justify-end gap-2 border-t border-zinc-200 dark:border-zinc-800">
            <button
              type="button"
              onClick={() => setIsQuickScanOpen(false)}
              className="rounded-lg border border-zinc-200 dark:border-zinc-800 px-3 py-1.5 text-xs text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isScanning || !inputValue.trim()}
              className="flex items-center gap-2 rounded-lg bg-zinc-900 dark:bg-zinc-100 text-zinc-100 dark:text-zinc-900 px-4 py-1.5 text-xs font-semibold hover:bg-zinc-800 dark:hover:bg-white disabled:opacity-50 transition-colors"
            >
              {isScanning ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  Run Analysis
                  <ArrowRight className="h-3.5 w-3.5" />
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </Modal>
  );
};
