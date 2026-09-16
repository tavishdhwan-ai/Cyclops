'use client';

import React, { useState } from 'react';
import { useDemoContext } from '../../context/DemoContext';
import { Card } from '../../components/ui/Card';
import { Badge } from '../../components/ui/Badge';
import {
  Settings,
  Building2,
  Bell,
  ShieldCheck,
  Lock,
  Save,
  CheckCircle2,
  MessageSquare,
  Globe,
} from 'lucide-react';

export default function SettingsPage() {
  const { settings, updateSettings } = useDemoContext();
  const [formState, setFormState] = useState(settings);
  const [isSaving, setIsSaving] = useState(false);

  const handleChange = (key: keyof typeof settings, value: any) => {
    setFormState((prev) => ({ ...prev, [key]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    await new Promise((res) => setTimeout(res, 500));
    updateSettings(formState);
    setIsSaving(false);
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800 pb-4">
        <div>
          <h1 className="text-xl font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
            <Settings className="h-5 w-5 text-zinc-500 dark:text-zinc-400" />
            Workspace & Security Policy Settings
          </h1>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
            Configure automated threat policies, notification channels, and workspace parameters.
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Workspace Info */}
        <Card className="space-y-4">
          <div className="flex items-center gap-2 border-b border-zinc-200 dark:border-zinc-800 pb-3">
            <Building2 className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Workspace Identity</h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">Company Name</label>
              <input
                type="text"
                value={formState.companyName}
                onChange={(e) => handleChange('companyName', e.target.value)}
                className="w-full rounded-lg border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-3 py-2 text-xs text-zinc-900 dark:text-zinc-100 focus:border-zinc-500 dark:focus:border-zinc-700 focus:outline-hidden"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">Primary Admin Email</label>
              <input
                type="email"
                value={formState.adminEmail}
                onChange={(e) => handleChange('adminEmail', e.target.value)}
                className="w-full rounded-lg border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-3 py-2 text-xs text-zinc-900 dark:text-zinc-100 focus:border-zinc-500 dark:focus:border-zinc-700 focus:outline-hidden"
              />
            </div>
          </div>
        </Card>

        {/* Security Policy Toggles */}
        <Card className="space-y-4">
          <div className="flex items-center gap-2 border-b border-zinc-200 dark:border-zinc-800 pb-3">
            <ShieldCheck className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Automated Security Policies</h2>
          </div>

          <div className="space-y-3 divide-y divide-zinc-200 dark:divide-zinc-800/60">
            {/* Policy 1 */}
            <div className="flex items-center justify-between pt-2">
              <div>
                <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-200">Auto-Quarantine Phishing Emails</p>
                <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                  Automatically isolate inbound mail failing SPF or DKIM validation.
                </p>
              </div>
              <input
                type="checkbox"
                checked={formState.autoQuarantinePhishing}
                onChange={(e) => handleChange('autoQuarantinePhishing', e.target.checked)}
                className="h-4 w-4 rounded border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 accent-zinc-900 dark:accent-zinc-100"
              />
            </div>

            {/* Policy 2 */}
            <div className="flex items-center justify-between pt-3">
              <div>
                <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-200">Enforce Real-Time URL Scanning</p>
                <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                  Check external web links clicked by employees in real time.
                </p>
              </div>
              <input
                type="checkbox"
                checked={formState.scanExternalUrls}
                onChange={(e) => handleChange('scanExternalUrls', e.target.checked)}
                className="h-4 w-4 rounded border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 accent-zinc-900 dark:accent-zinc-100"
              />
            </div>

            {/* Policy 3 */}
            <div className="flex items-center justify-between pt-3">
              <div>
                <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-200">Block Executable Attachments</p>
                <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                  Strip .exe, .bat, .bin, and double-extension payload files.
                </p>
              </div>
              <input
                type="checkbox"
                checked={formState.blockExecutableAttachments}
                onChange={(e) => handleChange('blockExecutableAttachments', e.target.checked)}
                className="h-4 w-4 rounded border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 accent-zinc-900 dark:accent-zinc-100"
              />
            </div>

            {/* Policy 4 */}
            <div className="flex items-center justify-between pt-3">
              <div>
                <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-200">Require 2FA Authentication</p>
                <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                  Enforce hardware security keys or authenticator apps for all workspace users.
                </p>
              </div>
              <input
                type="checkbox"
                checked={formState.requireTwoFactor}
                onChange={(e) => handleChange('requireTwoFactor', e.target.checked)}
                className="h-4 w-4 rounded border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 accent-zinc-900 dark:accent-zinc-100"
              />
            </div>
          </div>
        </Card>

        {/* Notifications & Slack Integrations */}
        <Card className="space-y-4">
          <div className="flex items-center gap-2 border-b border-zinc-200 dark:border-zinc-800 pb-3">
            <Bell className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Alerts & Integrations</h2>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-200">Weekly Security Audit Digest</p>
                <p className="text-[11px] text-zinc-500 dark:text-zinc-400">Receive summary reports every Monday morning.</p>
              </div>
              <input
                type="checkbox"
                checked={formState.weeklySummaryReports}
                onChange={(e) => handleChange('weeklySummaryReports', e.target.checked)}
                className="h-4 w-4 rounded border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 accent-zinc-900 dark:accent-zinc-100"
              />
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-zinc-200 dark:border-zinc-800/60">
              <div>
                <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-200">Slack Security Notifications</p>
                <p className="text-[11px] text-zinc-500 dark:text-zinc-400">Post critical risk alerts to #security-alerts channel.</p>
              </div>
              <input
                type="checkbox"
                checked={formState.slackWebhookEnabled}
                onChange={(e) => handleChange('slackWebhookEnabled', e.target.checked)}
                className="h-4 w-4 rounded border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 accent-zinc-900 dark:accent-zinc-100"
              />
            </div>

            {formState.slackWebhookEnabled && (
              <div className="pt-2">
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">Slack Webhook URL</label>
                <input
                  type="text"
                  value={formState.slackWebhookUrl}
                  onChange={(e) => handleChange('slackWebhookUrl', e.target.value)}
                  className="w-full rounded-lg border border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-3 py-2 text-xs font-mono text-zinc-900 dark:text-zinc-100 focus:border-zinc-500 dark:focus:border-zinc-700 focus:outline-hidden"
                />
              </div>
            )}
          </div>
        </Card>

        {/* Save Bar */}
        <div className="flex items-center justify-between pt-2">
          <span className="text-xs text-zinc-500">Changes save to local frontend demo state</span>
          <button
            type="submit"
            disabled={isSaving}
            className="flex items-center gap-2 rounded-lg bg-zinc-900 dark:bg-zinc-100 px-5 py-2 text-xs font-semibold text-white dark:text-zinc-900 hover:bg-zinc-800 dark:hover:bg-white transition-colors"
          >
            <Save className="h-4 w-4" />
            {isSaving ? 'Saving Changes...' : 'Save Workspace Policies'}
          </button>
        </div>
      </form>
    </div>
  );
}
