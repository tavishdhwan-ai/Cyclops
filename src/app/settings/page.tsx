'use client';

import React, { useState } from 'react';
import { useDemoContext } from '../../context/DemoContext';
import { useTheme } from '../../context/ThemeContext';
import { Card } from '../../components/ui/Card';
import {
  Settings,
  User,
  Shield,
  Lock,
  Eye,
  Save,
  Trash2,
  Sun,
  Moon,
  Info,
} from 'lucide-react';

export default function SettingsPage() {
  const { settings, updateSettings, showToast } = useDemoContext();
  const { theme, setTheme } = useTheme();

  const [displayName, setDisplayName] = useState(
    settings.companyName === 'Acme Corporation' ? 'Alex Vance' : settings.companyName || 'Alex Vance'
  );
  const [email, setEmail] = useState(
    settings.adminEmail === 'alex.vance@acmecorp.com' ? 'alex.vance@example.com' : settings.adminEmail || 'alex.vance@example.com'
  );

  const [scanExternalUrls, setScanExternalUrls] = useState(settings.scanExternalUrls ?? true);
  const [blockExecutables, setBlockExecutables] = useState(settings.blockExecutableAttachments ?? true);
  const [highlightUrgency, setHighlightUrgency] = useState(settings.autoQuarantinePhishing ?? true);
  const [showTechnicalDetailsDefault, setShowTechnicalDetailsDefault] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    await new Promise((res) => setTimeout(res, 400));

    updateSettings({
      companyName: displayName,
      adminEmail: email,
      scanExternalUrls,
      blockExecutableAttachments: blockExecutables,
      autoQuarantinePhishing: highlightUrgency,
    });

    setIsSaving(false);
    showToast('Settings Updated', 'Your personal security preferences have been saved.', 'success');
  };

  const handleClearLocalData = () => {
    showToast('Session Data Cleared', 'Local scan cache has been reset for this session.', 'info');
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto pb-12">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#E5E5E5] dark:border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-[#111111] dark:text-[#FFFFFF] flex items-center gap-2 tracking-tight">
            <Settings className="h-5 w-5 text-[#737373]" />
            Settings &amp; Privacy
          </h1>
          <p className="text-xs text-[#737373] mt-1">
            Manage your personal security preferences, privacy controls, and data transparency.
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* 1. Personal Profile */}
        <Card className="space-y-4" interactive={false}>
          <div className="flex items-center gap-2 border-b border-[#E5E5E5] dark:border-zinc-800 pb-3">
            <User className="h-4 w-4 text-[#737373]" />
            <h2 className="text-sm font-bold text-[#111111] dark:text-[#FFFFFF]">Personal Profile</h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-[#111111] dark:text-[#FFFFFF] mb-1">
                Display Name
              </label>
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="e.g. Alex Vance"
                className="w-full rounded-lg border border-[#E5E5E5] dark:border-zinc-800 bg-[#FFFFFF] dark:bg-zinc-950 px-3 py-2 text-xs text-[#111111] dark:text-[#FFFFFF] focus:border-[#111111] dark:focus:border-[#FFFFFF] focus:outline-hidden"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-[#111111] dark:text-[#FFFFFF] mb-1">
                Contact Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="e.g. alex@example.com"
                className="w-full rounded-lg border border-[#E5E5E5] dark:border-zinc-800 bg-[#FFFFFF] dark:bg-zinc-950 px-3 py-2 text-xs text-[#111111] dark:text-[#FFFFFF] focus:border-[#111111] dark:focus:border-[#FFFFFF] focus:outline-hidden"
              />
            </div>
          </div>
        </Card>

        {/* 2. Protection Preferences */}
        <Card className="space-y-4" interactive={false}>
          <div className="flex items-center gap-2 border-b border-[#E5E5E5] dark:border-zinc-800 pb-3">
            <Shield className="h-4 w-4 text-[#737373]" />
            <h2 className="text-sm font-bold text-[#111111] dark:text-[#FFFFFF]">Personal Safety Preferences</h2>
          </div>

          <div className="space-y-3 divide-y divide-[#E5E5E5] dark:divide-zinc-800/80">
            {/* Preference 1 */}
            <div className="flex items-center justify-between pt-2">
              <div className="pr-4">
                <p className="text-xs font-semibold text-[#111111] dark:text-[#FFFFFF]">
                  Automatic Known Scam &amp; Threat Checks
                </p>
                <p className="text-[11px] text-[#737373]">
                  Verify submitted links against public threat feeds (e.g. URLhaus) and certificate authorities.
                </p>
              </div>
              <input
                type="checkbox"
                checked={scanExternalUrls}
                onChange={(e) => setScanExternalUrls(e.target.checked)}
                className="h-4 w-4 rounded border-[#E5E5E5] dark:border-zinc-700 accent-[#111111] dark:accent-white"
              />
            </div>

            {/* Preference 2 */}
            <div className="flex items-center justify-between pt-3">
              <div className="pr-4">
                <p className="text-xs font-semibold text-[#111111] dark:text-[#FFFFFF]">
                  Flag Disguised &amp; Executable Attachments
                </p>
                <p className="text-[11px] text-[#737373]">
                  Detect executable binaries masquerading as documents (e.g. .pdf.exe or script files).
                </p>
              </div>
              <input
                type="checkbox"
                checked={blockExecutables}
                onChange={(e) => setBlockExecutables(e.target.checked)}
                className="h-4 w-4 rounded border-[#E5E5E5] dark:border-zinc-700 accent-[#111111] dark:accent-white"
              />
            </div>

            {/* Preference 3 */}
            <div className="flex items-center justify-between pt-3">
              <div className="pr-4">
                <p className="text-xs font-semibold text-[#111111] dark:text-[#FFFFFF]">
                  Phishing Urgency &amp; Credential Trap Detection
                </p>
                <p className="text-[11px] text-[#737373]">
                  Highlight artificial urgency phrasing and suspicious login prompts in scanned emails.
                </p>
              </div>
              <input
                type="checkbox"
                checked={highlightUrgency}
                onChange={(e) => setHighlightUrgency(e.target.checked)}
                className="h-4 w-4 rounded border-[#E5E5E5] dark:border-zinc-700 accent-[#111111] dark:accent-white"
              />
            </div>

            {/* Preference 4 */}
            <div className="flex items-center justify-between pt-3">
              <div className="pr-4">
                <p className="text-xs font-semibold text-[#111111] dark:text-[#FFFFFF]">
                  Show Detailed Technical Telemetry by Default
                </p>
                <p className="text-[11px] text-[#737373]">
                  Automatically expand cryptographic certificates, DNS records, and raw headers in scan results.
                </p>
              </div>
              <input
                type="checkbox"
                checked={showTechnicalDetailsDefault}
                onChange={(e) => setShowTechnicalDetailsDefault(e.target.checked)}
                className="h-4 w-4 rounded border-[#E5E5E5] dark:border-zinc-700 accent-[#111111] dark:accent-white"
              />
            </div>
          </div>
        </Card>

        {/* 3. Personal Privacy & Transparent Data Handling */}
        <Card className="space-y-4" interactive={false}>
          <div className="flex items-center gap-2 border-b border-[#E5E5E5] dark:border-zinc-800 pb-3">
            <Lock className="h-4 w-4 text-[#737373]" />
            <h2 className="text-sm font-bold text-[#111111] dark:text-[#FFFFFF]">Privacy &amp; Data Handling</h2>
          </div>

          <div className="rounded-lg bg-[#FAFAFA] dark:bg-zinc-950 p-4 border border-[#E5E5E5] dark:border-zinc-800 text-xs text-[#737373] space-y-3">
            <div className="flex items-start gap-2">
              <Info className="h-4 w-4 text-[#737373] shrink-0 mt-0.5" />
              <div className="space-y-2">
                <p className="font-semibold text-[#111111] dark:text-[#FFFFFF]">
                  What happens when you scan links, files, and emails:
                </p>
                <ul className="list-disc pl-4 space-y-1.5 leading-relaxed">
                  <li>
                    <strong className="text-[#111111] dark:text-zinc-200">Submitted Links:</strong> URLs are checked against public security intelligence lists (such as URLhaus) and DNS servers to identify known scams. Your personal browsing history is never tracked, indexed, or shared.
                  </li>
                  <li>
                    <strong className="text-[#111111] dark:text-zinc-200">Uploaded Documents:</strong> Uploaded files are inspected in an isolated static sandbox to detect embedded macros, concealed text, and malicious script hooks. Files are analyzed strictly for threats and are never executed on your machine.
                  </li>
                  <li>
                    <strong className="text-[#111111] dark:text-zinc-200">Inspected Emails:</strong> Email headers and contents are processed locally within your active session to verify sender authenticity and detect typosquatted domains.
                  </li>
                </ul>
              </div>
            </div>

            <div className="pt-2 border-t border-[#E5E5E5] dark:border-zinc-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <p className="font-semibold text-[#111111] dark:text-[#FFFFFF]">Session Scan Data</p>
                <p className="text-[11px]">Clear stored scan results from your current browser session.</p>
              </div>
              <button
                type="button"
                onClick={handleClearLocalData}
                className="flex items-center gap-1.5 rounded-lg border border-[#E5E5E5] dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-xs font-semibold text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 transition-colors shrink-0"
              >
                <Trash2 className="h-3.5 w-3.5" />
                <span>Reset Scan Cache</span>
              </button>
            </div>
          </div>
        </Card>

        {/* 4. Appearance Preferences */}
        <Card className="space-y-4" interactive={false}>
          <div className="flex items-center gap-2 border-b border-[#E5E5E5] dark:border-zinc-800 pb-3">
            <Eye className="h-4 w-4 text-[#737373]" />
            <h2 className="text-sm font-bold text-[#111111] dark:text-[#FFFFFF]">Appearance</h2>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-semibold text-[#111111] dark:text-[#FFFFFF]">Interface Theme</p>
              <p className="text-[11px] text-[#737373]">Choose between dark mode and clean light mode.</p>
            </div>
            <div className="flex items-center gap-1 rounded-lg border border-[#E5E5E5] dark:border-zinc-800 bg-[#FAFAFA] dark:bg-zinc-950 p-1">
              <button
                type="button"
                onClick={() => setTheme('light')}
                className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                  theme === 'light'
                    ? 'bg-white text-[#111111] shadow-xs font-semibold'
                    : 'text-[#737373] hover:text-[#111111]'
                }`}
              >
                <Sun className="h-3.5 w-3.5" />
                <span>Light</span>
              </button>
              <button
                type="button"
                onClick={() => setTheme('dark')}
                className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                  theme === 'dark'
                    ? 'bg-zinc-800 text-white shadow-xs font-semibold'
                    : 'text-[#737373] hover:text-white'
                }`}
              >
                <Moon className="h-3.5 w-3.5" />
                <span>Dark</span>
              </button>
            </div>
          </div>
        </Card>

        {/* Save Bar */}
        <div className="flex items-center justify-between pt-2">
          <span className="text-xs text-[#737373]">Changes apply immediately to your personal session</span>
          <button
            type="submit"
            disabled={isSaving}
            className="flex items-center gap-2 rounded-lg bg-[#111111] text-[#FFFFFF] dark:bg-[#FFFFFF] dark:text-[#111111] px-5 py-2 text-xs font-semibold hover:bg-zinc-800 dark:hover:bg-zinc-200 transition-colors cursor-pointer"
          >
            <Save className="h-4 w-4" />
            {isSaving ? 'Saving...' : 'Save Preferences'}
          </button>
        </div>
      </form>
    </div>
  );
}
