'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  RefreshCw,
  Unlink,
  ExternalLink,
  Loader2,
  Lock,
  Info,
  Clock,
  XCircle,
  MailCheck,
} from 'lucide-react';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { useAuth } from '../../context/AuthContext';
import { useDemoContext } from '../../context/DemoContext';

export interface GmailConnectionStatus {
  configured: boolean;
  configIssue: string | null;
  connected: boolean;
  status: 'not_connected' | 'connected' | 'reauth_required' | 'revoked' | 'error';
  gmailAddress: string | null;
  grantedScopes: string[];
  connectedAt: number | null;
  lastVerifiedAt: number | null;
  reauthRequired: boolean;
  reauthReason: string | null;
  accessTokenExpiresAt: number | null;
  refreshTokenIssuedAt: number | null;
  refreshTokenExpiresEstimateAt: number | null;
  testingModeNotice?: string;
}

interface DisconnectNotice {
  remoteRevoked: boolean;
  manualRevocationUrl: string;
  message: string;
}

interface ConnectedAccountsSectionProps {
  callbackStatus?: string | null;
  onClearCallbackParams?: () => void;
}

const GmailLogoIcon: React.FC<{ className?: string }> = ({ className = 'h-6 w-6' }) => (
  <svg viewBox="0 0 24 24" className={className} aria-hidden="true">
    <path
      fill="#4285F4"
      d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
    />
    <path
      fill="#34A853"
      d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
    />
    <path
      fill="#FBBC05"
      d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
    />
    <path
      fill="#EA4335"
      d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
    />
  </svg>
);

const CALLBACK_BANNERS: Record<
  string,
  { tone: 'success' | 'warning' | 'error' | 'info'; title: string; message: string }
> = {
  connected: {
    tone: 'success',
    title: 'Gmail Connected & Verified',
    message: 'Your Gmail account was authorised with read-only access and verified against the Gmail profile API.',
  },
  denied: {
    tone: 'info',
    title: 'Consent Declined',
    message: 'You declined Gmail access on Google’s consent screen. No credentials were stored.',
  },
  expired: {
    tone: 'warning',
    title: 'Authorization Timed Out',
    message: 'Your OAuth request expired before completion. Please try connecting Gmail again.',
  },
  state_replayed: {
    tone: 'warning',
    title: 'Callback Already Processed',
    message: 'This Gmail authorisation callback was already consumed.',
  },
  ownership_mismatch: {
    tone: 'error',
    title: 'Session Mismatch Blocked',
    message: 'The OAuth callback did not match your current Cyclops session and was rejected for security.',
  },
  missing_permissions: {
    tone: 'warning',
    title: 'Read-Only Permission Missing',
    message: 'Google did not grant the required gmail.readonly permission.',
  },
  excessive_permissions: {
    tone: 'error',
    title: 'Scope Validation Failed',
    message: 'Returned permissions exceeded Cyclops’s strict read-only boundary and were rejected.',
  },
  missing_refresh_token: {
    tone: 'warning',
    title: 'Offline Authorisation Incomplete',
    message:
      'Google did not issue a refresh token. Please revoke Cyclops under your Google Account permissions and connect again.',
  },
  account_mismatch: {
    tone: 'warning',
    title: 'Different Gmail Account Detected',
    message:
      'Another Gmail address is already linked to this Cyclops account. Disconnect the existing account first before linking a different address.',
  },
  already_connected: {
    tone: 'info',
    title: 'Gmail Already Connected',
    message: 'A Gmail connection is already active for this profile.',
  },
  configuration_error: {
    tone: 'error',
    title: 'Gmail Integration Unconfigured',
    message: 'Server-side Gmail OAuth or credential encryption settings are missing or invalid.',
  },
  temporary_unavailable: {
    tone: 'warning',
    title: 'Service Temporarily Unavailable',
    message: 'Could not complete verification with Google right now. Please try again in a moment.',
  },
};

export const ConnectedAccountsSection: React.FC<ConnectedAccountsSectionProps> = ({
  callbackStatus,
  onClearCallbackParams,
}) => {
  const { user, sessionToken } = useAuth();
  const { showToast } = useDemoContext();

  const [gmailStatus, setGmailStatus] = useState<GmailConnectionStatus | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isConnecting, setIsConnecting] = useState<boolean>(false);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [isDisconnecting, setIsDisconnecting] = useState<boolean>(false);
  const [showDisconnectModal, setShowDisconnectModal] = useState<boolean>(false);
  const [consentChecked, setConsentChecked] = useState<boolean>(false);
  const [inlineError, setInlineError] = useState<{ code: string; message: string } | null>(null);
  const [disconnectNotice, setDisconnectNotice] = useState<DisconnectNotice | null>(null);

  const buildHeaders = useCallback(
    (includeJson: boolean = false): Record<string, string> => {
      const headers: Record<string, string> = {
        'X-Cyclops-CSRF': '1',
        'X-Requested-With': 'XMLHttpRequest',
      };
      if (includeJson) {
        headers['Content-Type'] = 'application/json';
      }
      const token =
        sessionToken ||
        (typeof window !== 'undefined' ? localStorage.getItem('sentinel_session_token') : null);
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      return headers;
    },
    [sessionToken]
  );

  const fetchStatus = useCallback(async () => {
    if (!user) {
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    try {
      const res = await fetch('/api/integrations/gmail/status', {
        method: 'GET',
        headers: buildHeaders(false),
        cache: 'no-store',
      });

      if (res.status === 401) {
        setGmailStatus(null);
        setInlineError({
          code: 'session_required',
          message: 'Please complete two-channel biometric sign-in to manage Gmail connections.',
        });
        return;
      }

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setInlineError({
          code: err.code || 'temporary_unavailable',
          message: err.message || err.detail || 'Could not load Gmail connection status.',
        });
        return;
      }

      const data = (await res.json()) as GmailConnectionStatus;
      setGmailStatus(data);
      setInlineError(null);
    } catch {
      setInlineError({
        code: 'temporary_unavailable',
        message: 'Network error loading Gmail integration status.',
      });
    } finally {
      setIsLoading(false);
    }
  }, [user, buildHeaders]);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  useEffect(() => {
    if (callbackStatus && CALLBACK_BANNERS[callbackStatus]) {
      const info = CALLBACK_BANNERS[callbackStatus];
      showToast(info.title, info.message, info.tone);
    }
  }, [callbackStatus, showToast]);

  const handleStartOAuth = async (action: 'connect' | 'reconnect') => {
    if (isConnecting || isVerifying || isDisconnecting) return;
    if (!consentChecked) {
      setInlineError({
        code: 'consent_required',
        message: 'Please confirm the read-only privacy disclosure above before connecting Gmail.',
      });
      return;
    }

    setIsConnecting(true);
    setInlineError(null);
    setDisconnectNotice(null);

    try {
      const endpoint =
        action === 'reconnect' ? '/api/integrations/gmail/reconnect' : '/api/integrations/gmail/start';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: buildHeaders(true),
        body: JSON.stringify({
          action,
          privacyConsentAccepted: true,
        }),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.authorizationUrl) {
        setInlineError({
          code: data.code || data.error || 'temporary_unavailable',
          message: data.message || data.detail || 'Could not start Google OAuth flow.',
        });
        setIsConnecting(false);
        return;
      }

      window.location.assign(data.authorizationUrl);
    } catch {
      setInlineError({
        code: 'temporary_unavailable',
        message: 'Unable to reach Cyclops backend to initiate Gmail connection.',
      });
      setIsConnecting(false);
    }
  };

  const handleVerifyConnection = async () => {
    if (isVerifying || isConnecting || isDisconnecting) return;
    setIsVerifying(true);
    setInlineError(null);

    try {
      const res = await fetch('/api/integrations/gmail/verify', {
        method: 'POST',
        headers: buildHeaders(true),
        body: JSON.stringify({}),
      });
      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        if (data.reauthRequired || data.code === 'reauth_required' || res.status === 401) {
          await fetchStatus();
        }
        setInlineError({
          code: data.code || 'verification_failed',
          message: data.message || data.detail || 'Gmail connection verification failed.',
        });
        showToast('Verification Failed', data.message || 'Please check your Gmail connection.', 'warning');
        return;
      }

      setGmailStatus(data as GmailConnectionStatus);
      showToast('Connection Verified', 'Gmail API profile access confirmed.', 'success');
    } catch {
      setInlineError({
        code: 'temporary_unavailable',
        message: 'Temporary error verifying Gmail connection. Please try again.',
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleConfirmDisconnect = async () => {
    if (isDisconnecting) return;
    setIsDisconnecting(true);
    setInlineError(null);

    try {
      const res = await fetch('/api/integrations/gmail/disconnect', {
        method: 'POST',
        headers: buildHeaders(true),
        body: JSON.stringify({}),
      });
      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        setInlineError({
          code: data.code || 'disconnect_failed',
          message: data.message || data.detail || 'Failed to disconnect Gmail.',
        });
        return;
      }

      setDisconnectNotice({
        remoteRevoked: Boolean(data.remoteRevoked),
        manualRevocationUrl: data.manualRevocationUrl || 'https://myaccount.google.com/permissions',
        message: data.message || 'Gmail connection removed.',
      });
      setConsentChecked(false);
      if (onClearCallbackParams) onClearCallbackParams();
      await fetchStatus();
      showToast(
        'Gmail Disconnected',
        data.remoteRevoked ? 'Credentials deleted and Google grant revoked.' : 'Local credentials deleted.',
        data.remoteRevoked ? 'info' : 'warning'
      );
    } catch {
      setInlineError({
        code: 'temporary_unavailable',
        message: 'Network error while disconnecting Gmail.',
      });
    } finally {
      setIsDisconnecting(false);
      setShowDisconnectModal(false);
    }
  };

  const formatTimestamp = (ts?: number | null) => {
    if (!ts) return 'Not yet verified';
    return new Date(ts * 1000).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const activeCallbackBanner = callbackStatus ? CALLBACK_BANNERS[callbackStatus] : null;
  const isConfigured = gmailStatus?.configured !== false;
  const isConnected = Boolean(gmailStatus?.connected && gmailStatus?.status === 'connected' && !gmailStatus?.reauthRequired);
  const needsReauth = Boolean(gmailStatus && (gmailStatus.reauthRequired || gmailStatus.status === 'reauth_required'));

  return (
    <div className="space-y-6">
      {/* Callback Result Banner */}
      {activeCallbackBanner && (
        <div
          className={`rounded-xl border p-4 flex items-start justify-between gap-3 ${
            activeCallbackBanner.tone === 'success'
              ? 'border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/70 dark:bg-emerald-950/30 text-emerald-900 dark:text-emerald-200'
              : activeCallbackBanner.tone === 'error'
              ? 'border-red-200 dark:border-red-900/60 bg-red-50/70 dark:bg-red-950/30 text-red-900 dark:text-red-200'
              : activeCallbackBanner.tone === 'warning'
              ? 'border-amber-200 dark:border-amber-900/60 bg-amber-50/70 dark:bg-amber-950/30 text-amber-900 dark:text-amber-200'
              : 'border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/50 text-zinc-900 dark:text-zinc-200'
          }`}
        >
          <div className="flex items-start gap-3">
            {activeCallbackBanner.tone === 'success' ? (
              <CheckCircle2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
            ) : activeCallbackBanner.tone === 'error' ? (
              <XCircle className="h-5 w-5 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
            ) : activeCallbackBanner.tone === 'warning' ? (
              <AlertTriangle className="h-5 w-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
            ) : (
              <Info className="h-5 w-5 text-zinc-600 dark:text-zinc-400 shrink-0 mt-0.5" />
            )}
            <div className="space-y-0.5 text-xs">
              <p className="font-bold">{activeCallbackBanner.title}</p>
              <p className="opacity-90">{activeCallbackBanner.message}</p>
            </div>
          </div>
          {onClearCallbackParams && (
            <button
              type="button"
              onClick={onClearCallbackParams}
              className="text-xs font-medium opacity-70 hover:opacity-100 cursor-pointer shrink-0"
            >
              Dismiss
            </button>
          )}
        </div>
      )}

      {/* Honest Remote Revocation Notice after Disconnecting */}
      {disconnectNotice && (
        <div
          className={`rounded-xl border p-4 flex items-start gap-3 text-xs ${
            disconnectNotice.remoteRevoked
              ? 'border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/60 text-zinc-800 dark:text-zinc-200'
              : 'border-amber-200 dark:border-amber-900/60 bg-amber-50/70 dark:bg-amber-950/30 text-amber-900 dark:text-amber-200'
          }`}
        >
          {disconnectNotice.remoteRevoked ? (
            <CheckCircle2 className="h-4 w-4 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
          ) : (
            <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
          )}
          <div className="space-y-1.5">
            <p className="font-semibold">
              {disconnectNotice.remoteRevoked ? 'Gmail Disconnected & Revoked' : 'Local Credentials Removed (Manual Revocation Advised)'}
            </p>
            <p className="opacity-90">{disconnectNotice.message}</p>
            {!disconnectNotice.remoteRevoked && (
              <a
                href={disconnectNotice.manualRevocationUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 font-semibold underline hover:opacity-80"
              >
                <span>Open Google Account Third-Party Permissions</span>
                <ExternalLink className="h-3 w-3" />
              </a>
            )}
          </div>
        </div>
      )}

      {/* Main Gmail Integration Card */}
      <Card className="space-y-5" interactive={false}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-200 dark:border-zinc-800 pb-4">
          <div className="flex items-start gap-3.5">
            <div className="h-11 w-11 rounded-xl border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-950 flex items-center justify-center shrink-0 shadow-2xs">
              <GmailLogoIcon className="h-6 w-6" />
            </div>
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">Gmail</h2>
                <Badge level="neutral">Read-Only Access</Badge>
                {isLoading ? (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-zinc-100 dark:bg-zinc-800 text-zinc-500">
                    <Loader2 className="h-3 w-3 animate-spin" />
                    <span>Checking status</span>
                  </span>
                ) : !isConfigured ? (
                  <Badge level="warning">Configuration Required</Badge>
                ) : isConnected ? (
                  <Badge level="safe">Connected</Badge>
                ) : needsReauth ? (
                  <Badge level="warning">Reauthorisation Required</Badge>
                ) : (
                  <Badge level="neutral">Not connected</Badge>
                )}
              </div>
              <p className="text-xs text-zinc-500 dark:text-zinc-400">
                Connect your Google Gmail account with strictly read-only permission to lay the foundation for your Personal Trust Graph.
              </p>
            </div>
          </div>
        </div>

        {/* Inline Error Notice */}
        {inlineError && (
          <div className="rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50/70 dark:bg-red-950/30 p-3 flex items-start gap-2.5 text-xs text-red-800 dark:text-red-300">
            <AlertTriangle className="h-4 w-4 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold">Action Could Not Be Completed</p>
              <p className="mt-0.5 opacity-90">{inlineError.message}</p>
            </div>
          </div>
        )}

        {/* Unauthenticated Gate Notice */}
        {!user ? (
          <div className="rounded-xl border border-dashed border-zinc-200 dark:border-zinc-800 p-6 text-center space-y-3">
            <Lock className="h-7 w-7 text-zinc-400 mx-auto" />
            <div className="space-y-1">
              <p className="text-xs font-bold text-zinc-900 dark:text-zinc-100">Two-Channel Authentication Required</p>
              <p className="text-xs text-zinc-500 max-w-md mx-auto">
                Sign in with your Cyclops account and mobile passkey before linking an external Gmail account.
              </p>
            </div>
            <Link
              href="/login?next=/settings?tab=integrations"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 text-xs font-semibold hover:opacity-90"
            >
              <span>Sign In to Connect Gmail</span>
            </Link>
          </div>
        ) : isLoading ? (
          <div className="py-8 flex items-center justify-center gap-2 text-xs text-zinc-500">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span>Loading Gmail connection details...</span>
          </div>
        ) : !isConfigured ? (
          <div className="rounded-xl border border-amber-200 dark:border-amber-900/60 bg-amber-50/50 dark:bg-amber-950/20 p-4 space-y-2 text-xs">
            <div className="flex items-center gap-2 font-bold text-amber-800 dark:text-amber-300">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>Gmail Integration Unavailable on This Server</span>
            </div>
            <p className="text-amber-700 dark:text-amber-400">
              Server-side Gmail OAuth or encryption configuration (`GMAIL_TOKEN_ENCRYPTION_KEY` / Google client variables) is currently incomplete. Core Cyclops security features remain unaffected.
            </p>
          </div>
        ) : isConnected && gmailStatus ? (
          /* CONNECTED STATE */
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50/70 dark:bg-zinc-950/60 p-3 space-y-1">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">
                  Connected Gmail Address
                </span>
                <p className="text-xs font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-1.5 break-all">
                  <MailCheck className="h-3.5 w-3.5 text-emerald-500 shrink-0" />
                  <span>{gmailStatus.gmailAddress}</span>
                </p>
              </div>

              <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50/70 dark:bg-zinc-950/60 p-3 space-y-1">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">
                  Connection Date
                </span>
                <p className="text-xs font-medium text-zinc-800 dark:text-zinc-200 flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5 text-zinc-400 shrink-0" />
                  <span>{formatTimestamp(gmailStatus.connectedAt)}</span>
                </p>
              </div>

              <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50/70 dark:bg-zinc-950/60 p-3 space-y-1">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">
                  Last Verified Date
                </span>
                <p className="text-xs font-medium text-zinc-800 dark:text-zinc-200 flex items-center gap-1.5">
                  <ShieldCheck className="h-3.5 w-3.5 text-emerald-500 shrink-0" />
                  <span>{formatTimestamp(gmailStatus.lastVerifiedAt)}</span>
                </p>
              </div>
            </div>

            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50/40 dark:bg-zinc-950/40 p-3.5 text-xs space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-zinc-800 dark:text-zinc-200">Granted Scope</span>
                <code className="text-[11px] px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">
                  gmail.readonly
                </code>
              </div>
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                Stage 1 verification only: Cyclops checks mailbox profile availability without downloading message bodies, attachments, or sender histories.
              </p>
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                {gmailStatus.testingModeNotice ||
                  'Google OAuth is currently in Testing mode; authorisations may expire after 7 days and prompt you to reconnect.'}
              </p>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
              <button
                type="button"
                onClick={handleVerifyConnection}
                disabled={isVerifying || isDisconnecting}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-950 text-xs font-semibold text-zinc-800 dark:text-zinc-200 hover:bg-zinc-50 dark:hover:bg-zinc-800 disabled:opacity-50 cursor-pointer"
              >
                {isVerifying ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <RefreshCw className="h-3.5 w-3.5" />
                )}
                <span>{isVerifying ? 'Verifying...' : 'Verify Connection'}</span>
              </button>

              <button
                type="button"
                onClick={() => setShowDisconnectModal(true)}
                disabled={isDisconnecting || isVerifying}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50/60 dark:bg-red-950/20 text-xs font-semibold text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/40 disabled:opacity-50 cursor-pointer"
              >
                <Unlink className="h-3.5 w-3.5" />
                <span>Disconnect Gmail</span>
              </button>
            </div>
          </div>
        ) : (
          /* NOT CONNECTED OR REAUTH REQUIRED STATE */
          <div className="space-y-4">
            {needsReauth && gmailStatus && (
              <div className="rounded-xl border border-amber-200 dark:border-amber-900/60 bg-amber-50/70 dark:bg-amber-950/30 p-4 space-y-2 text-xs">
                <div className="flex items-center gap-2 font-bold text-amber-900 dark:text-amber-200">
                  <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0" />
                  <span>Gmail Reauthorisation Required</span>
                </div>
                <p className="text-amber-800 dark:text-amber-300">
                  Access for <strong>{gmailStatus.gmailAddress}</strong> has expired or been revoked (Google Testing mode tokens expire after 7 days). Reconnect your Gmail account to restore verification, or disconnect it cleanly.
                </p>
              </div>
            )}

            {/* Privacy & User Consent Disclosure BEFORE Initiating OAuth */}
            <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50/60 dark:bg-zinc-950/50 p-4 space-y-3">
              <div className="flex items-center gap-2 text-xs font-bold text-zinc-900 dark:text-zinc-100">
                <ShieldCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                <span>Privacy &amp; Read-Only Access Disclosure</span>
              </div>

              <ul className="space-y-1.5 text-xs text-zinc-600 dark:text-zinc-400 list-disc pl-5">
                <li>
                  Cyclops requests strictly <strong>read-only Gmail access</strong> (
                  <code className="text-[11px]">https://www.googleapis.com/auth/gmail.readonly</code>).
                </li>
                <li>
                  Cyclops <strong>cannot send, delete, or modify</strong> any emails or account settings.
                </li>
                <li>
                  This stage verifies your Gmail connection using only your mailbox address without downloading email contents, attachments, or message lists.
                </li>
                <li>
                  Future Trust Graph or mailbox analysis features will require clear user disclosure before any email metadata processing begins.
                </li>
                <li>
                  Cyclops never trains AI models on Gmail data, never shares Gmail data with third-party AI or analytics providers, and lets you disconnect Gmail at any time.
                </li>
              </ul>

              <label className="flex items-start gap-2.5 pt-2 border-t border-zinc-200 dark:border-zinc-800 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={consentChecked}
                  onChange={(e) => setConsentChecked(e.target.checked)}
                  className="mt-0.5 h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-zinc-900 focus:ring-0 cursor-pointer"
                />
                <span className="text-xs font-medium text-zinc-800 dark:text-zinc-200">
                  I understand Cyclops will request read-only Gmail verification access and I authorise connecting my Gmail account.
                </span>
              </label>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
              <button
                type="button"
                onClick={() => handleStartOAuth(needsReauth ? 'reconnect' : 'connect')}
                disabled={isConnecting || !consentChecked}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 text-xs font-semibold hover:opacity-90 disabled:opacity-50 cursor-pointer transition-opacity"
              >
                {isConnecting ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    <span>Redirecting to Google...</span>
                  </>
                ) : (
                  <>
                    <GmailLogoIcon className="h-4 w-4" />
                    <span>{needsReauth ? 'Reconnect Gmail' : 'Connect Gmail'}</span>
                  </>
                )}
              </button>

              {needsReauth && (
                <button
                  type="button"
                  onClick={() => setShowDisconnectModal(true)}
                  disabled={isDisconnecting || isConnecting}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-red-200 dark:border-red-900/60 text-xs font-semibold text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 disabled:opacity-50 cursor-pointer"
                >
                  <Unlink className="h-3.5 w-3.5" />
                  <span>Disconnect Gmail</span>
                </button>
              )}
            </div>
          </div>
        )}
      </Card>

      {/* Disconnect Confirmation Modal */}
      {showDisconnectModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 space-y-4 shadow-xl">
            <div className="flex items-start gap-3">
              <div className="h-10 w-10 rounded-full bg-red-100 dark:bg-red-950/60 text-red-600 dark:text-red-400 flex items-center justify-center shrink-0">
                <Unlink className="h-5 w-5" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">
                  Disconnect Gmail Account?
                </h3>
                <p className="text-xs text-zinc-500 dark:text-zinc-400 leading-relaxed">
                  Cyclops will revoke Google OAuth access where reachable, purge encrypted Gmail credentials immediately, and return your Gmail status to Not connected. Your Cyclops account and registered passkeys will not be affected.
                </p>
              </div>
            </div>
            <div className="flex items-center justify-end gap-2 pt-3 border-t border-zinc-100 dark:border-zinc-800">
              <button
                type="button"
                onClick={() => setShowDisconnectModal(false)}
                disabled={isDisconnecting}
                className="px-3.5 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 text-xs font-medium text-zinc-700 dark:text-zinc-300 cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmDisconnect}
                disabled={isDisconnecting}
                className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-semibold disabled:opacity-50 cursor-pointer"
              >
                {isDisconnecting ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    <span>Disconnecting...</span>
                  </>
                ) : (
                  <span>Yes, Disconnect Gmail</span>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
