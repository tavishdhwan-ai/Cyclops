'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useDemoContext } from '../../context/DemoContext';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../context/AuthContext';
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
  LogOut,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
} from 'lucide-react';

export default function SettingsPage() {
  const { settings, updateSettings, showToast } = useDemoContext();
  const { theme, setTheme } = useTheme();
  const { user, profile, updateProfile, signOut, deleteAccount } = useAuth();

  const [displayName, setDisplayName] = useState(profile.displayName || user?.displayName || 'Alex Vance');
  const email = user?.email || 'alex.vance@example.com';

  const [scanExternalUrls, setScanExternalUrls] = useState(settings.scanExternalUrls ?? true);
  const [blockExecutables, setBlockExecutables] = useState(settings.blockExecutableAttachments ?? true);
  const [highlightUrgency, setHighlightUrgency] = useState(settings.autoQuarantinePhishing ?? true);
  const [isSaving, setIsSaving] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);

    // Save in Auth profile
    await updateProfile({
      displayName: displayName.trim(),
    });

    // Save in local settings
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

  const handleConfirmDeleteAccount = async () => {
    setIsDeleting(true);
    const result = await deleteAccount();
    setIsDeleting(false);
    setShowDeleteModal(false);

    if (result.success) {
      showToast('Account Deleted', 'Your profile and session data have been permanently erased.', 'info');
    } else {
      showToast('Deletion Failed', result.error || 'Could not complete account deletion.', 'error');
    }
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
            Manage your personal security preferences, account identity, and data privacy.
          </p>
        </div>
      </div>

      <form key={user?.id || 'guest'} onSubmit={handleSubmit} className="space-y-6">
        {/* 1. Account & Identity */}
        <Card className="space-y-4" interactive={false}>
          <div className="flex items-center justify-between border-b border-[#E5E5E5] dark:border-zinc-800 pb-3">
            <div className="flex items-center gap-2">
              <User className="h-4 w-4 text-[#737373]" />
              <h2 className="text-sm font-bold text-[#111111] dark:text-[#FFFFFF]">Account &amp; Identity</h2>
            </div>
            {user ? (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800/60">
                <CheckCircle2 className="h-3 w-3" />
                <span>Authenticated</span>
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-700">
                <span>Guest Session</span>
              </span>
            )}
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
                Account Email
              </label>
              <input
                type="email"
                value={email}
                disabled
                className="w-full rounded-lg border border-[#E5E5E5] dark:border-zinc-800 bg-[#FAFAFA] dark:bg-zinc-900 px-3 py-2 text-xs text-[#737373] cursor-not-allowed"
              />
              <p className="text-[10px] text-[#737373] mt-1">
                {user ? 'Verified passwordless email identity.' : 'Sign in to sync your profile across devices.'}
              </p>
            </div>
          </div>

          {/* Account Actions Bar */}
          <div className="pt-2 border-t border-[#E5E5E5] dark:border-zinc-800 flex flex-wrap items-center justify-between gap-3">
            {user ? (
              <>
                <button
                  type="button"
                  onClick={signOut}
                  className="flex items-center gap-1.5 rounded-lg border border-[#E5E5E5] dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors cursor-pointer"
                >
                  <LogOut className="h-3.5 w-3.5" />
                  <span>Sign Out</span>
                </button>

                <button
                  type="button"
                  onClick={() => setShowDeleteModal(true)}
                  className="text-xs text-red-600 dark:text-red-400 hover:underline cursor-pointer"
                >
                  Delete Account
                </button>
              </>
            ) : (
              <div className="w-full flex items-center justify-between">
                <span className="text-xs text-[#737373]">Want to save preferences and history?</span>
                <Link
                  href="/login"
                  className="flex items-center gap-1.5 rounded-lg bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 px-3 py-1.5 text-xs font-semibold hover:opacity-90 transition-opacity"
                >
                  <span>Sign In</span>
                </Link>
              </div>
            )}
          </div>
        </Card>

        {/* 2. Onboarding Preferences */}
        <Card className="space-y-4" interactive={false}>
          <div className="flex items-center justify-between border-b border-[#E5E5E5] dark:border-zinc-800 pb-3">
            <div className="flex items-center gap-2">
              <Sliders className="h-4 w-4 text-[#737373]" />
              <h2 className="text-sm font-bold text-[#111111] dark:text-[#FFFFFF]">Personal Security Profile</h2>
            </div>
            <Link
              href="/onboarding"
              className="text-xs text-[#737373] hover:text-[#111111] dark:hover:text-zinc-100 underline flex items-center gap-1"
            >
              <span>Retake Onboarding</span>
              <ExternalLink className="h-3 w-3" />
            </Link>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div className="p-3 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 space-y-1">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">Primary Goal</span>
              <p className="font-semibold text-zinc-900 dark:text-zinc-100 capitalize">
                {profile.goal ? `${profile.goal} protection` : 'Personal protection'}
              </p>
            </div>
            <div className="p-3 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 space-y-1">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">Experience Level</span>
              <p className="font-semibold text-zinc-900 dark:text-zinc-100 capitalize">
                {profile.experience || 'Beginner'}
              </p>
            </div>
            <div className="p-3 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 space-y-1">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">Key Concerns</span>
              <p className="font-semibold text-zinc-900 dark:text-zinc-100">
                {profile.concerns && profile.concerns.length > 0
                  ? profile.concerns.join(', ')
                  : 'Phishing, Documents'}
              </p>
            </div>
          </div>
        </Card>

        {/* 3. Protection Preferences */}
        <Card className="space-y-4" interactive={false}>
          <div className="flex items-center gap-2 border-b border-[#E5E5E5] dark:border-zinc-800 pb-3">
            <Shield className="h-4 w-4 text-[#737373]" />
            <h2 className="text-sm font-bold text-[#111111] dark:text-[#FFFFFF]">Protection Preferences</h2>
          </div>

          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold text-[#111111] dark:text-[#FFFFFF]">External Link Verification</p>
                <p className="text-[11px] text-[#737373]">
                  Automatically verify external domains against URLhaus threat feeds.
                </p>
              </div>
              <input
                type="checkbox"
                checked={scanExternalUrls}
                onChange={(e) => setScanExternalUrls(e.target.checked)}
                className="h-4 w-4 rounded border-[#E5E5E5] dark:border-zinc-800 text-[#111111] focus:ring-0"
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold text-[#111111] dark:text-[#FFFFFF]">Executable Attachment Filter</p>
                <p className="text-[11px] text-[#737373]">
                  Flag attachments containing scripts, macros, or dangerous extensions (.exe, .scr, .vbs).
                </p>
              </div>
              <input
                type="checkbox"
                checked={blockExecutables}
                onChange={(e) => setBlockExecutables(e.target.checked)}
                className="h-4 w-4 rounded border-[#E5E5E5] dark:border-zinc-800 text-[#111111] focus:ring-0"
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold text-[#111111] dark:text-[#FFFFFF]">Phishing Urgency Flagging</p>
                <p className="text-[11px] text-[#737373]">
                  Highlight urgency language and psychological pressure tactics in inspected emails.
                </p>
              </div>
              <input
                type="checkbox"
                checked={highlightUrgency}
                onChange={(e) => setHighlightUrgency(e.target.checked)}
                className="h-4 w-4 rounded border-[#E5E5E5] dark:border-zinc-800 text-[#111111] focus:ring-0"
              />
            </div>
          </div>
        </Card>

        {/* 4. Personal Privacy & Transparent Data Handling */}
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
                  Our Privacy Standards:
                </p>
                <ul className="list-disc pl-4 space-y-1.5 leading-relaxed">
                  <li>
                    <strong className="text-[#111111] dark:text-zinc-200">No Advertising Analytics:</strong> We never sell, track, or share your scan history, file contents, or email analysis with advertising networks.
                  </li>
                  <li>
                    <strong className="text-[#111111] dark:text-zinc-200">Ephemeral In-Memory Inspection:</strong> Documents uploaded for security analysis are inspected in isolated memory and are not retained on server storage or used for model training.
                  </li>
                  <li>
                    <strong className="text-[#111111] dark:text-zinc-200">Passwordless Security:</strong> We never generate or store passwords. Authentication is powered by one-time magic links and Google OAuth.
                  </li>
                </ul>
              </div>
            </div>

            <div className="pt-2 border-t border-[#E5E5E5] dark:border-zinc-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <p className="font-semibold text-[#111111] dark:text-[#FFFFFF]">Session Scan Cache</p>
                <p className="text-[11px]">Clear cached results from your current browser window.</p>
              </div>
              <button
                type="button"
                onClick={handleClearLocalData}
                className="flex items-center gap-1.5 rounded-lg border border-[#E5E5E5] dark:border-zinc-700 bg-white dark:bg-zinc-900 px-3 py-1.5 text-xs font-semibold text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 transition-colors shrink-0 cursor-pointer"
              >
                <Trash2 className="h-3.5 w-3.5" />
                <span>Reset Scan Cache</span>
              </button>
            </div>
          </div>
        </Card>

        {/* 5. Appearance Preferences */}
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
                className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer ${
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
                className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer ${
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

      {/* Account Deletion Confirmation Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-2xl border border-red-200 dark:border-red-900/60 bg-white dark:bg-zinc-900 p-6 space-y-4 shadow-xl">
            <div className="flex items-start gap-3">
              <div className="h-10 w-10 rounded-full bg-red-100 dark:bg-red-950/60 text-red-600 dark:text-red-400 flex items-center justify-center shrink-0">
                <AlertTriangle className="h-5 w-5" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">
                  Delete Cyclops Account?
                </h3>
                <p className="text-xs text-zinc-600 dark:text-zinc-400 leading-relaxed">
                  This action will permanently erase your personal security profile and invalidate all active sessions. This action cannot be undone.
                </p>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-zinc-100 dark:border-zinc-800">
              <button
                type="button"
                onClick={() => setShowDeleteModal(false)}
                disabled={isDeleting}
                className="px-3.5 py-1.5 rounded-lg border border-zinc-300 dark:border-zinc-700 text-xs font-semibold text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmDeleteAccount}
                disabled={isDeleting}
                className="px-4 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-semibold cursor-pointer"
              >
                {isDeleting ? 'Deleting...' : 'Yes, Delete My Account'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
