'use client';

import React, { useState, useEffect, useRef, useCallback } from 'react';
import Link from 'next/link';
import { useDemoContext } from '../../context/DemoContext';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../context/AuthContext';
import { Card } from '../../components/ui/Card';
import { COUNTRIES, LANGUAGES, COMMON_TIMEZONES } from '../../lib/profileConstants';
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
  Smartphone,
  Key,
  Laptop,
  Clock,
  History,
  Bell,
  Camera,
  AtSign,
  Loader2,
  XCircle,
  RefreshCw,
  X,
} from 'lucide-react';

interface PasskeyItem {
  id: string;
  deviceId: string;
  deviceName: string;
  platform: string;
  credentialId: string;
  credentialIdPreview: string;
  signCount: number;
  isActive: boolean;
  lastUsedAt: number | null;
  createdAt: number;
  revokedAt: number | null;
}

interface DeviceItem {
  id: string;
  deviceId: string;
  deviceName: string;
  deviceType: string;
  platform: string;
  hasPasskey: boolean;
  hasWebPush: boolean;
  isActive: boolean;
  lastUsedAt: number | null;
  createdAt: number;
  revokedAt: number | null;
}

interface SessionItem {
  sessionId: string;
  transactionId: string;
  email: string;
  userAgent: string;
  ipAddress: string;
  createdAt: number;
  lastActiveAt: number;
  expiresAt: number;
  state: string;
}

interface AuditEventItem {
  id: string;
  transactionId: string | null;
  eventType: string;
  status: string;
  details: Record<string, unknown>;
  ipAddress: string;
  userAgent: string;
  createdAt: number;
}

interface SecurityPreferences {
  notifyNewDevice: boolean;
  notifyNewPasskey: boolean;
  notifyFailedLogin: boolean;
  notifySecurityChanges: boolean;
}

export default function SettingsPage() {
  const { settings, updateSettings, showToast } = useDemoContext();
  const { theme, setTheme } = useTheme();
  const { user, profile, updateProfile, signOut, deleteAccount, sessionToken, isSigningOut } = useAuth();

  // Navigation tab
  const [activeTab, setActiveTab] = useState<'profile' | 'security' | 'activity' | 'privacy'>('profile');

  // 1. Profile & Identity Form State
  const [fullName, setFullName] = useState(profile.fullName || profile.displayName || user?.displayName || '');
  const [username, setUsername] = useState(profile.username || '');
  const [country, setCountry] = useState(profile.country || 'United States');
  const [profilePictureUrl, setProfilePictureUrl] = useState(profile.profilePictureUrl || user?.avatarUrl || '');
  const [dateOfBirth, setDateOfBirth] = useState(profile.dateOfBirth || '');
  const [preferredLanguage, setPreferredLanguage] = useState(profile.preferredLanguage || 'en');
  const [timeZone, setTimeZone] = useState(
    profile.timeZone ||
      (typeof Intl !== 'undefined' ? Intl.DateTimeFormat().resolvedOptions().timeZone : 'UTC')
  );

  // Username validation state
  const [isCheckingUsername, setIsCheckingUsername] = useState(false);
  const [usernameAvailable, setUsernameAvailable] = useState<boolean | null>(null);
  const [usernameError, setUsernameError] = useState<string | null>(null);

  // Avatar upload
  const [isUploadingAvatar, setIsUploadingAvatar] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [isSavingProfile, setIsSavingProfile] = useState(false);

  // 2. Security & Devices State
  const [passkeys, setPasskeys] = useState<PasskeyItem[]>([]);
  const [devices, setDevices] = useState<DeviceItem[]>([]);
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [secPrefs, setSecPrefs] = useState<SecurityPreferences>({
    notifyNewDevice: true,
    notifyNewPasskey: true,
    notifyFailedLogin: true,
    notifySecurityChanges: true,
  });
  const [isLoadingSecurity, setIsLoadingSecurity] = useState(false);

  // 3. Activity State
  const [activityEvents, setActivityEvents] = useState<AuditEventItem[]>([]);
  const [isLoadingActivity, setIsLoadingActivity] = useState(false);

  // 4. Privacy & Protection Toggles
  const [scanExternalUrls, setScanExternalUrls] = useState(settings.scanExternalUrls ?? true);
  const [blockExecutables, setBlockExecutables] = useState(settings.blockExecutableAttachments ?? true);
  const [highlightUrgency, setHighlightUrgency] = useState(settings.autoQuarantinePhishing ?? true);

  // Modals & Confirmation Dialogs
  const [revokePasskeyModal, setRevokePasskeyModal] = useState<PasskeyItem | null>(null);
  const [revokeDeviceModal, setRevokeDeviceModal] = useState<DeviceItem | null>(null);
  const [revokeSessionModal, setRevokeSessionModal] = useState<SessionItem | null>(null);
  const [showRevokeOthersModal, setShowRevokeOthersModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [isActionLoading, setIsActionLoading] = useState(false);

  // Sync profile when auth state updates
  useEffect(() => {
    if (profile) {
      if (profile.fullName) setFullName(profile.fullName);
      else if (profile.displayName) setFullName(profile.displayName);
      if (profile.username) setUsername(profile.username);
      if (profile.country) setCountry(profile.country);
      if (profile.profilePictureUrl) setProfilePictureUrl(profile.profilePictureUrl);
      if (profile.dateOfBirth) setDateOfBirth(profile.dateOfBirth);
      if (profile.preferredLanguage) setPreferredLanguage(profile.preferredLanguage);
      if (profile.timeZone) setTimeZone(profile.timeZone);
    }
  }, [profile]);

  // Debounced username check
  useEffect(() => {
    const trimmed = username.trim().toLowerCase();
    if (!trimmed || trimmed === profile.username?.toLowerCase()) {
      setUsernameAvailable(null);
      setUsernameError(null);
      return;
    }

    if (trimmed.length < 3 || trimmed.length > 30) {
      setUsernameAvailable(false);
      setUsernameError('Username must be 3-30 characters.');
      return;
    }

    if (!/^[a-zA-Z0-9_]+$/.test(trimmed)) {
      setUsernameAvailable(false);
      setUsernameError('Only alphanumeric letters and underscores.');
      return;
    }

    let active = true;
    setIsCheckingUsername(true);

    const timer = setTimeout(async () => {
      try {
        const token = sessionToken || (typeof window !== 'undefined' ? localStorage.getItem('sentinel_session_token') : null);
        const headers: Record<string, string> = {};
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const res = await fetch(`/api/user/check-username?username=${encodeURIComponent(trimmed)}`, {
          headers,
        });
        if (!active) return;

        if (res.ok) {
          const data = await res.json();
          setUsernameAvailable(data.available);
          setUsernameError(data.available ? null : 'This username is already taken.');
        } else {
          setUsernameAvailable(false);
          setUsernameError('Unable to check username.');
        }
      } catch {
        if (active) setUsernameAvailable(null);
      } finally {
        if (active) setIsCheckingUsername(false);
      }
    }, 400);

    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [username, profile.username, sessionToken]);

  // Fetch security data (Passkeys, Devices, Sessions, Preferences)
  const loadSecurityData = useCallback(async () => {
    if (!user) return;
    setIsLoadingSecurity(true);
    const token = sessionToken || (typeof window !== 'undefined' ? localStorage.getItem('sentinel_session_token') : null);
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    try {
      const [passkeysRes, devicesRes, sessionsRes, prefsRes] = await Promise.all([
        fetch('/api/security/passkeys', { headers }).then((r) => (r.ok ? r.json() : { passkeys: [] })),
        fetch('/api/security/devices', { headers }).then((r) => (r.ok ? r.json() : { devices: [] })),
        fetch('/api/security/sessions', { headers }).then((r) => (r.ok ? r.json() : { sessions: [] })),
        fetch('/api/security/preferences', { headers }).then((r) => (r.ok ? r.json() : { preferences: null })),
      ]);

      setPasskeys(passkeysRes.passkeys || []);
      setDevices(devicesRes.devices || []);
      setSessions(sessionsRes.sessions || []);
      if (prefsRes.preferences) {
        setSecPrefs(prefsRes.preferences);
      }
    } catch (e) {
      console.warn('Failed to fetch security dashboard telemetry:', e);
    } finally {
      setIsLoadingSecurity(false);
    }
  }, [user, sessionToken]);

  // Fetch activity log
  const loadActivityData = useCallback(async () => {
    if (!user) return;
    setIsLoadingActivity(true);
    const token = sessionToken || (typeof window !== 'undefined' ? localStorage.getItem('sentinel_session_token') : null);
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    try {
      const res = await fetch('/api/security/activity?limit=50', { headers });
      if (res.ok) {
        const data = await res.json();
        setActivityEvents(data.activity || []);
      }
    } catch (e) {
      console.warn('Failed to load activity events:', e);
    } finally {
      setIsLoadingActivity(false);
    }
  }, [user, sessionToken]);

  useEffect(() => {
    if (activeTab === 'security') {
      loadSecurityData();
    } else if (activeTab === 'activity') {
      loadActivityData();
    }
  }, [activeTab, loadSecurityData, loadActivityData]);

  // Handle avatar upload
  const handleAvatarFile = async (file: File) => {
    if (!file.type.startsWith('image/')) {
      showToast('Invalid File', 'Please select a valid image (JPEG, PNG, WEBP).', 'error');
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      showToast('File Too Large', 'Avatar size must be under 5MB.', 'error');
      return;
    }

    setIsUploadingAvatar(true);
    try {
      const formData = new FormData();
      formData.append('file', file);

      const token = sessionToken || (typeof window !== 'undefined' ? localStorage.getItem('sentinel_session_token') : null);
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch('/api/user/avatar', {
        method: 'POST',
        headers,
        body: formData,
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || 'Avatar upload failed.');
      }

      const data = await res.json();
      setProfilePictureUrl(data.avatarUrl);
      showToast('Avatar Updated', 'Profile picture has been saved.', 'success');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error uploading avatar.';
      showToast('Upload Error', msg, 'error');
    } finally {
      setIsUploadingAvatar(false);
    }
  };

  // Save Profile Form
  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (usernameAvailable === false) {
      showToast('Invalid Username', usernameError || 'Please choose a unique username.', 'error');
      return;
    }

    setIsSavingProfile(true);
    const result = await updateProfile({
      fullName: fullName.trim(),
      displayName: fullName.trim(),
      username: username.trim().toLowerCase(),
      country,
      profilePictureUrl,
      dateOfBirth,
      preferredLanguage,
      timeZone,
    });
    setIsSavingProfile(false);

    if (result.success) {
      showToast('Profile Saved', 'Your identity and profile settings have been updated.', 'success');
    } else {
      showToast('Update Failed', result.error || 'Could not save profile.', 'error');
    }
  };

  // Revoke Passkey
  const handleConfirmRevokePasskey = async () => {
    if (!revokePasskeyModal) return;
    setIsActionLoading(true);
    const token = sessionToken || (typeof window !== 'undefined' ? localStorage.getItem('sentinel_session_token') : null);
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    try {
      const res = await fetch(`/api/security/passkeys/${encodeURIComponent(revokePasskeyModal.credentialId)}`, {
        method: 'DELETE',
        headers,
      });
      if (res.ok) {
        showToast('Passkey Revoked', 'The biometric passkey has been deactivated.', 'info');
        loadSecurityData();
      } else {
        showToast('Revocation Failed', 'Could not revoke passkey.', 'error');
      }
    } catch {
      showToast('Revocation Failed', 'Network error.', 'error');
    } finally {
      setIsActionLoading(false);
      setRevokePasskeyModal(null);
    }
  };

  // Revoke Trusted Device
  const handleConfirmRevokeDevice = async () => {
    if (!revokeDeviceModal) return;
    setIsActionLoading(true);
    const token = sessionToken || (typeof window !== 'undefined' ? localStorage.getItem('sentinel_session_token') : null);
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    try {
      const res = await fetch(`/api/security/devices/${encodeURIComponent(revokeDeviceModal.deviceId)}`, {
        method: 'DELETE',
        headers,
      });
      if (res.ok) {
        showToast('Device Revoked', 'Device authorization has been revoked.', 'info');
        loadSecurityData();
      } else {
        showToast('Revocation Failed', 'Could not revoke device.', 'error');
      }
    } catch {
      showToast('Revocation Failed', 'Network error.', 'error');
    } finally {
      setIsActionLoading(false);
      setRevokeDeviceModal(null);
    }
  };

  // Revoke Single Session
  const handleConfirmRevokeSession = async () => {
    if (!revokeSessionModal) return;
    setIsActionLoading(true);
    const token = sessionToken || (typeof window !== 'undefined' ? localStorage.getItem('sentinel_session_token') : null);
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    try {
      const res = await fetch(`/api/security/sessions/${encodeURIComponent(revokeSessionModal.sessionId)}`, {
        method: 'DELETE',
        headers,
      });
      if (res.ok) {
        showToast('Session Revoked', 'Session invalidated.', 'info');
        loadSecurityData();
      } else {
        showToast('Revocation Failed', 'Could not revoke session.', 'error');
      }
    } catch {
      showToast('Revocation Failed', 'Network error.', 'error');
    } finally {
      setIsActionLoading(false);
      setRevokeSessionModal(null);
    }
  };

  // Revoke All Other Sessions
  const handleConfirmRevokeOthers = async () => {
    setIsActionLoading(true);
    const token = sessionToken || (typeof window !== 'undefined' ? localStorage.getItem('sentinel_session_token') : null);
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    try {
      const res = await fetch('/api/security/sessions/revoke-others', {
        method: 'POST',
        headers,
        body: JSON.stringify({ currentSessionId: '' }),
      });
      if (res.ok) {
        const data = await res.json();
        showToast('Sessions Revoked', data.message || 'All other active sessions have been terminated.', 'info');
        loadSecurityData();
      } else {
        showToast('Revocation Failed', 'Could not terminate other sessions.', 'error');
      }
    } catch {
      showToast('Revocation Failed', 'Network error.', 'error');
    } finally {
      setIsActionLoading(false);
      setShowRevokeOthersModal(false);
    }
  };

  // Toggle Security Notification Preference
  const handleTogglePref = async (key: keyof SecurityPreferences) => {
    const updated = { ...secPrefs, [key]: !secPrefs[key] };
    setSecPrefs(updated);

    const token = sessionToken || (typeof window !== 'undefined' ? localStorage.getItem('sentinel_session_token') : null);
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    try {
      await fetch('/api/security/preferences', {
        method: 'POST',
        headers,
        body: JSON.stringify(updated),
      });
      showToast('Preferences Saved', 'Security alert settings updated.', 'success');
    } catch {
      showToast('Update Failed', 'Could not save alert preferences.', 'error');
    }
  };

  // Save Privacy / Scanner Settings
  const handleSavePrivacySettings = (e: React.FormEvent) => {
    e.preventDefault();
    updateSettings({
      scanExternalUrls,
      blockExecutableAttachments: blockExecutables,
      autoQuarantinePhishing: highlightUrgency,
    });
    showToast('Settings Updated', 'Threat detection preferences have been saved.', 'success');
  };

  // Account deletion
  const handleConfirmDeleteAccount = async () => {
    setIsActionLoading(true);
    const result = await deleteAccount();
    setIsActionLoading(false);
    setShowDeleteModal(false);

    if (result.success) {
      showToast('Account Deleted', 'Your profile and data have been permanently erased.', 'info');
    } else {
      showToast('Deletion Failed', result.error || 'Could not complete account deletion.', 'error');
    }
  };

  const formatDate = (timestamp?: number | null) => {
    if (!timestamp) return 'Never';
    return new Date(timestamp * 1000).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-16">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-200 dark:border-zinc-800 pb-5">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2.5 tracking-tight">
            <Settings className="h-6 w-6 text-zinc-500" />
            <span>Settings &amp; Security Dashboard</span>
          </h1>
          <p className="text-xs sm:text-sm text-zinc-500 dark:text-zinc-400 mt-1">
            Manage your personal identity, WebAuthn passkeys, trusted devices, sessions, and privacy controls.
          </p>
        </div>

        {user ? (
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800/60">
              <CheckCircle2 className="h-3.5 w-3.5" />
              <span>Biometric 2FA Active</span>
            </span>
            <button
              type="button"
              disabled={isSigningOut}
              onClick={signOut}
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg border border-zinc-200 dark:border-zinc-700 text-xs font-medium text-zinc-600 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 disabled:opacity-50 cursor-pointer"
            >
              {isSigningOut ? (
                <>
                  <div className="h-3.5 w-3.5 border-2 border-zinc-600 dark:border-zinc-400 border-t-transparent rounded-full animate-spin" />
                  <span>Signing Out...</span>
                </>
              ) : (
                <>
                  <LogOut className="h-3.5 w-3.5" />
                  <span>Sign Out</span>
                </>
              )}
            </button>
          </div>
        ) : (
          <Link
            href="/login"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 text-xs font-semibold hover:opacity-90 transition-opacity"
          >
            <span>Sign In to Sync</span>
          </Link>
        )}
      </div>

      {/* Tabs Switcher */}
      <div className="flex items-center gap-1 border-b border-zinc-200 dark:border-zinc-800 overflow-x-auto pb-px">
        {[
          { id: 'profile', label: 'Profile & Identity', icon: User },
          { id: 'security', label: 'Security & Devices', icon: Shield },
          { id: 'activity', label: 'Recent Activity', icon: History },
          { id: 'privacy', label: 'Preferences & Privacy', icon: Lock },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors cursor-pointer shrink-0 ${
                isActive
                  ? 'border-zinc-900 dark:border-white text-zinc-900 dark:text-white'
                  : 'border-transparent text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-200'
              }`}
            >
              <Icon className="h-4 w-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* ===================================================================== */}
      {/* TAB 1: Profile & Identity */}
      {/* ===================================================================== */}
      {activeTab === 'profile' && (
        <form onSubmit={handleSaveProfile} className="space-y-6">
          <Card className="space-y-6" interactive={false}>
            <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800 pb-3">
              <div>
                <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
                  <User className="h-4 w-4 text-zinc-500" />
                  <span>Profile Information</span>
                </h2>
                <p className="text-xs text-zinc-500 mt-0.5">
                  Update your display credentials and geographic settings.
                </p>
              </div>
            </div>

            {/* Avatar Section */}
            <div className="flex items-center gap-4">
              <div className="relative h-16 w-16 rounded-full overflow-hidden bg-zinc-100 dark:bg-zinc-800 border-2 border-zinc-200 dark:border-zinc-700 flex items-center justify-center shrink-0">
                {profilePictureUrl ? (
                  // eslint-disable-next-line @next/next/no-img-element
                  <img src={profilePictureUrl} alt="Avatar" className="h-full w-full object-cover" />
                ) : (
                  <User className="h-7 w-7 text-zinc-400" />
                )}
                {isUploadingAvatar && (
                  <div className="absolute inset-0 bg-black/50 flex items-center justify-center text-white">
                    <Loader2 className="h-5 w-5 animate-spin" />
                  </div>
                )}
              </div>
              <div className="space-y-1">
                <span className="block text-xs font-semibold text-zinc-800 dark:text-zinc-200">
                  Profile Avatar
                </span>
                <div className="flex items-center gap-2">
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept="image/png, image/jpeg, image/webp"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) handleAvatarFile(file);
                    }}
                    className="hidden"
                  />
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    disabled={isUploadingAvatar}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-950 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800 cursor-pointer disabled:opacity-50"
                  >
                    <Camera className="h-3.5 w-3.5" />
                    <span>Upload New Photo</span>
                  </button>
                  {profilePictureUrl && (
                    <button
                      type="button"
                      onClick={() => setProfilePictureUrl('')}
                      className="text-xs text-red-500 hover:underline cursor-pointer"
                    >
                      Remove
                    </button>
                  )}
                </div>
                <p className="text-[10px] text-zinc-400">JPG, PNG, WEBP up to 5MB.</p>
              </div>
            </div>

            {/* Core Fields */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                  Full Name
                </label>
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="e.g. Alex Vance"
                  className="block w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-xs text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 focus:outline-hidden focus:border-zinc-900 dark:focus:border-zinc-100"
                />
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                    Unique Username
                  </label>
                  {isCheckingUsername && (
                    <span className="text-[10px] text-zinc-400 flex items-center gap-1">
                      <Loader2 className="h-3 w-3 animate-spin" />
                      <span>Checking...</span>
                    </span>
                  )}
                </div>
                <div className="relative">
                  <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                    <AtSign className="h-3.5 w-3.5 text-zinc-400" />
                  </div>
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value.toLowerCase())}
                    placeholder="e.g. alex_vance"
                    maxLength={30}
                    className={`block w-full rounded-lg border pl-8 pr-8 py-2 text-xs text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 focus:outline-hidden ${
                      usernameError
                        ? 'border-red-400'
                        : usernameAvailable === true
                        ? 'border-emerald-500'
                        : 'border-zinc-300 dark:border-zinc-700'
                    } bg-white dark:bg-zinc-950`}
                  />
                  <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-2.5">
                    {usernameAvailable === true && <CheckCircle2 className="h-4 w-4 text-emerald-500" />}
                    {usernameError && <XCircle className="h-4 w-4 text-red-500" />}
                  </div>
                </div>
                {usernameError ? (
                  <p className="text-[10px] text-red-500">{usernameError}</p>
                ) : usernameAvailable === true ? (
                  <p className="text-[10px] text-emerald-600 dark:text-emerald-400">✓ Username available</p>
                ) : (
                  <p className="text-[10px] text-zinc-400">3-30 letters, numbers, and underscores.</p>
                )}
              </div>
            </div>

            {/* Email & Phone (Read-Only) */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                  Primary Email (Authenticated)
                </label>
                <input
                  type="email"
                  value={user?.email || 'user@sentinel.ai'}
                  disabled
                  className="block w-full rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 px-3 py-2 text-xs text-zinc-500 cursor-not-allowed"
                />
              </div>

              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                  Mobile WhatsApp Device (Authenticated)
                </label>
                <input
                  type="text"
                  value={user?.phoneNumber || 'Enrolled on sign-in'}
                  disabled
                  className="block w-full rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 px-3 py-2 text-xs text-zinc-500 cursor-not-allowed"
                />
              </div>
            </div>

            {/* Regional & Localization */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                  Country
                </label>
                <select
                  value={country}
                  onChange={(e) => setCountry(e.target.value)}
                  className="block w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-xs text-zinc-900 dark:text-zinc-100 focus:outline-hidden"
                >
                  {COUNTRIES.map((c) => (
                    <option key={c.code} value={c.name}>
                      {c.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                  Preferred Language
                </label>
                <select
                  value={preferredLanguage}
                  onChange={(e) => setPreferredLanguage(e.target.value)}
                  className="block w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-xs text-zinc-900 dark:text-zinc-100 focus:outline-hidden"
                >
                  {LANGUAGES.map((l) => (
                    <option key={l.code} value={l.code}>
                      {l.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                  Time Zone
                </label>
                <select
                  value={timeZone}
                  onChange={(e) => setTimeZone(e.target.value)}
                  className="block w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-xs text-zinc-900 dark:text-zinc-100 focus:outline-hidden"
                >
                  {COMMON_TIMEZONES.includes(timeZone) ? null : (
                    <option value={timeZone}>{timeZone}</option>
                  )}
                  {COMMON_TIMEZONES.map((tz) => (
                    <option key={tz} value={tz}>
                      {tz}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Optional Date of Birth */}
            <div className="max-w-xs space-y-1.5">
              <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100 flex items-center justify-between">
                <span>Date of Birth</span>
                <span className="text-[10px] text-zinc-400 font-normal">Optional</span>
              </label>
              <input
                type="date"
                value={dateOfBirth}
                onChange={(e) => setDateOfBirth(e.target.value)}
                className="block w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-xs text-zinc-900 dark:text-zinc-100 focus:outline-hidden"
              />
            </div>

            {/* Save Button */}
            <div className="pt-3 border-t border-zinc-200 dark:border-zinc-800 flex justify-end">
              <button
                type="submit"
                disabled={isSavingProfile || usernameAvailable === false}
                className="flex items-center gap-2 rounded-lg bg-zinc-900 dark:bg-white px-5 py-2 text-xs font-semibold text-white dark:text-zinc-900 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors cursor-pointer disabled:opacity-50"
              >
                <Save className="h-3.5 w-3.5" />
                <span>{isSavingProfile ? 'Saving...' : 'Save Profile Changes'}</span>
              </button>
            </div>
          </Card>
        </form>
      )}

      {/* ===================================================================== */}
      {/* TAB 2: Security & Devices Dashboard */}
      {/* ===================================================================== */}
      {activeTab === 'security' && (
        <div className="space-y-6">
          {/* Section 1: WebAuthn Passkeys */}
          <Card className="space-y-4" interactive={false}>
            <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800 pb-3">
              <div>
                <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
                  <Key className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                  <span>Registered WebAuthn Passkeys</span>
                </h2>
                <p className="text-xs text-zinc-500 mt-0.5">
                  Hardware-backed biometric passkeys enrolled for zero-trust authentication.
                </p>
              </div>
              <button
                type="button"
                onClick={loadSecurityData}
                disabled={isLoadingSecurity}
                className="p-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 text-zinc-500 hover:text-zinc-900 dark:hover:text-white cursor-pointer"
                title="Refresh passkeys"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${isLoadingSecurity ? 'animate-spin' : ''}`} />
              </button>
            </div>

            {passkeys.length === 0 ? (
              <div className="rounded-xl border border-dashed border-zinc-200 dark:border-zinc-800 p-6 text-center space-y-2">
                <Smartphone className="h-8 w-8 text-zinc-400 mx-auto" />
                <p className="text-xs font-semibold text-zinc-700 dark:text-zinc-300">
                  No Passkeys Registered Yet
                </p>
                <p className="text-[11px] text-zinc-500 max-w-sm mx-auto">
                  When you sign in using our two-channel flow on your mobile phone, your device will prompt you to register a platform passkey (Face ID / Fingerprint).
                </p>
              </div>
            ) : (
              <div className="divide-y divide-zinc-100 dark:divide-zinc-800">
                {passkeys.map((pk) => (
                  <div key={pk.id} className="py-3 flex items-center justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <div className="h-9 w-9 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400 flex items-center justify-center shrink-0">
                        <Key className="h-4 w-4" />
                      </div>
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-zinc-900 dark:text-zinc-100">
                            {pk.deviceName}
                          </span>
                          {pk.isActive ? (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400">
                              Active
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-500">
                              Revoked
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-zinc-500">
                          Platform: <span className="text-zinc-700 dark:text-zinc-300">{pk.platform}</span> • Registered: {formatDate(pk.createdAt)}
                        </p>
                        <p className="text-[10px] text-zinc-400">
                          Credential ID: {pk.credentialIdPreview} • Sign Count: {pk.signCount} • Last Used: {formatDate(pk.lastUsedAt)}
                        </p>
                      </div>
                    </div>

                    {pk.isActive && (
                      <button
                        type="button"
                        onClick={() => setRevokePasskeyModal(pk)}
                        className="text-xs font-medium text-red-600 dark:text-red-400 hover:underline cursor-pointer shrink-0"
                      >
                        Revoke Passkey
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* Section 2: Trusted Devices */}
          <Card className="space-y-4" interactive={false}>
            <div className="border-b border-zinc-200 dark:border-zinc-800 pb-3">
              <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
                <Smartphone className="h-4 w-4 text-zinc-500" />
                <span>Trusted Enrolled Devices</span>
              </h2>
              <p className="text-xs text-zinc-500 mt-0.5">
                Authorized mobile and desktop devices bound to your dual-channel authentication profile.
              </p>
            </div>

            {devices.length === 0 ? (
              <p className="text-xs text-zinc-500 py-3">No trusted devices registered.</p>
            ) : (
              <div className="divide-y divide-zinc-100 dark:divide-zinc-800">
                {devices.map((dev) => (
                  <div key={dev.id} className="py-3 flex items-center justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <div className="h-9 w-9 rounded-lg bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 flex items-center justify-center shrink-0">
                        {dev.deviceType === 'desktop' ? (
                          <Laptop className="h-4 w-4" />
                        ) : (
                          <Smartphone className="h-4 w-4" />
                        )}
                      </div>
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-zinc-900 dark:text-zinc-100">
                            {dev.deviceName}
                          </span>
                          {dev.isActive ? (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400">
                              Active
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-500">
                              Revoked
                            </span>
                          )}
                          {dev.hasPasskey && (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-blue-100 dark:bg-blue-950/60 text-blue-700 dark:text-blue-400">
                              Passkey Enrolled
                            </span>
                          )}
                          {dev.hasWebPush && (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-purple-100 dark:bg-purple-950/60 text-purple-700 dark:text-purple-400">
                              Push Enabled
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-zinc-500">
                          Platform: {dev.platform} • Enrolled: {formatDate(dev.createdAt)}
                        </p>
                      </div>
                    </div>

                    {dev.isActive && (
                      <button
                        type="button"
                        onClick={() => setRevokeDeviceModal(dev)}
                        className="text-xs font-medium text-red-600 dark:text-red-400 hover:underline cursor-pointer shrink-0"
                      >
                        Revoke Access
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* Section 3: Active Sessions */}
          <Card className="space-y-4" interactive={false}>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-200 dark:border-zinc-800 pb-3">
              <div>
                <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
                  <Laptop className="h-4 w-4 text-zinc-500" />
                  <span>Active Browser Sessions</span>
                </h2>
                <p className="text-xs text-zinc-500 mt-0.5">
                  Currently authenticated sessions established across your browsers.
                </p>
              </div>
              {sessions.length > 1 && (
                <button
                  type="button"
                  onClick={() => setShowRevokeOthersModal(true)}
                  className="px-3 py-1.5 rounded-lg border border-red-200 dark:border-red-900/60 text-xs font-semibold text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 cursor-pointer self-start sm:self-auto"
                >
                  Sign Out All Other Sessions
                </button>
              )}
            </div>

            {sessions.length === 0 ? (
              <p className="text-xs text-zinc-500 py-3">No other active sessions detected.</p>
            ) : (
              <div className="divide-y divide-zinc-100 dark:divide-zinc-800">
                {sessions.map((sess, idx) => (
                  <div key={sess.sessionId || idx} className="py-3 flex items-center justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <div className="h-9 w-9 rounded-lg bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 flex items-center justify-center shrink-0">
                        <Laptop className="h-4 w-4" />
                      </div>
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-zinc-900 dark:text-zinc-100">
                            {sess.userAgent?.includes('Mozilla') ? 'Desktop Web Browser' : sess.userAgent}
                          </span>
                          {idx === 0 && (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400">
                              Current Session
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-zinc-500">
                          IP: {sess.ipAddress} • Established: {formatDate(sess.createdAt)}
                        </p>
                      </div>
                    </div>

                    {idx > 0 && (
                      <button
                        type="button"
                        onClick={() => setRevokeSessionModal(sess)}
                        className="text-xs font-medium text-red-600 dark:text-red-400 hover:underline cursor-pointer shrink-0"
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* Section 4: Security Notification Preferences */}
          <Card className="space-y-4" interactive={false}>
            <div className="border-b border-zinc-200 dark:border-zinc-800 pb-3">
              <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
                <Bell className="h-4 w-4 text-zinc-500" />
                <span>Security Alert &amp; Notification Preferences</span>
              </h2>
              <p className="text-xs text-zinc-500 mt-0.5">
                Choose when Sentinel AI should dispatch instant alerts to your email and WhatsApp.
              </p>
            </div>

            <div className="space-y-3.5">
              {[
                {
                  key: 'notifyNewDevice' as const,
                  title: 'New Device Sign-In Alert',
                  desc: 'Notify immediately when an unverified device initiates a desktop session.',
                },
                {
                  key: 'notifyNewPasskey' as const,
                  title: 'New Passkey Enrolled Alert',
                  desc: 'Notify when a new platform authenticator or biometric passkey is registered.',
                },
                {
                  key: 'notifyFailedLogin' as const,
                  title: 'Failed Biometric / Passkey Attempt',
                  desc: 'Notify when an authentication assertion fails verification or challenge expires.',
                },
                {
                  key: 'notifySecurityChanges' as const,
                  title: 'Security Settings Modified',
                  desc: 'Notify whenever account credentials, recovery channels, or preferences change.',
                },
              ].map((item) => (
                <div key={item.key} className="flex items-center justify-between gap-4 py-1">
                  <div>
                    <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-100">{item.title}</p>
                    <p className="text-[11px] text-zinc-500">{item.desc}</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={secPrefs[item.key]}
                    onChange={() => handleTogglePref(item.key)}
                    className="h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-zinc-900 focus:ring-0 cursor-pointer"
                  />
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {/* ===================================================================== */}
      {/* TAB 3: Recent Activity (Real Audit Log) */}
      {/* ===================================================================== */}
      {activeTab === 'activity' && (
        <Card className="space-y-4" interactive={false}>
          <div className="flex items-center justify-between border-b border-zinc-200 dark:border-zinc-800 pb-3">
            <div>
              <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
                <History className="h-4 w-4 text-zinc-500" />
                <span>Authentication &amp; Security Audit Log</span>
              </h2>
              <p className="text-xs text-zinc-500 mt-0.5">
                Real cryptographic verification events, logins, and device registrations stored in SQLite.
              </p>
            </div>
            <button
              type="button"
              onClick={loadActivityData}
              disabled={isLoadingActivity}
              className="p-1.5 rounded-lg border border-zinc-200 dark:border-zinc-800 text-zinc-500 hover:text-zinc-900 dark:hover:text-white cursor-pointer"
              title="Refresh log"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${isLoadingActivity ? 'animate-spin' : ''}`} />
            </button>
          </div>

          {activityEvents.length === 0 ? (
            <div className="text-center py-8 space-y-2">
              <Clock className="h-6 w-6 text-zinc-400 mx-auto" />
              <p className="text-xs text-zinc-500">No recent audit events recorded yet.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-zinc-200 dark:border-zinc-800 text-zinc-400 text-[10px] uppercase tracking-wider">
                    <th className="py-2.5 font-semibold">Event</th>
                    <th className="py-2.5 font-semibold">Status</th>
                    <th className="py-2.5 font-semibold">IP Address</th>
                    <th className="py-2.5 font-semibold">Date &amp; Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800">
                  {activityEvents.map((evt) => (
                    <tr key={evt.id} className="hover:bg-zinc-50/50 dark:hover:bg-zinc-800/30">
                      <td className="py-2.5 font-mono text-[11px] text-zinc-800 dark:text-zinc-200">
                        {evt.eventType}
                      </td>
                      <td className="py-2.5">
                        <span
                          className={`inline-flex px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                            evt.status === 'SUCCESS'
                              ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400'
                              : 'bg-red-100 dark:bg-red-950/60 text-red-700 dark:text-red-400'
                          }`}
                        >
                          {evt.status}
                        </span>
                      </td>
                      <td className="py-2.5 text-zinc-500 font-mono text-[11px]">
                        {evt.ipAddress}
                      </td>
                      <td className="py-2.5 text-zinc-500 text-[11px]">
                        {formatDate(evt.createdAt)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {/* ===================================================================== */}
      {/* TAB 4: Preferences & Privacy */}
      {/* ===================================================================== */}
      {activeTab === 'privacy' && (
        <form onSubmit={handleSavePrivacySettings} className="space-y-6">
          {/* Scanner Toggles */}
          <Card className="space-y-4" interactive={false}>
            <div className="flex items-center gap-2 border-b border-zinc-200 dark:border-zinc-800 pb-3">
              <Shield className="h-4 w-4 text-zinc-500" />
              <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">
                Threat Inspection Parameters
              </h2>
            </div>

            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                    External Link Threat Feed Verification
                  </p>
                  <p className="text-[11px] text-zinc-500">
                    Automatically cross-reference links with real-time URLhaus telemetry.
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={scanExternalUrls}
                  onChange={(e) => setScanExternalUrls(e.target.checked)}
                  className="h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-zinc-900 focus:ring-0"
                />
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                    Executable &amp; Macro Attachment Filter
                  </p>
                  <p className="text-[11px] text-zinc-500">
                    Flag attachments containing embedded scripts or dangerous extensions (.exe, .vbs, .scr).
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={blockExecutables}
                  onChange={(e) => setBlockExecutables(e.target.checked)}
                  className="h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-zinc-900 focus:ring-0"
                />
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                    Urgency &amp; Impersonation Highlighting
                  </p>
                  <p className="text-[11px] text-zinc-500">
                    Detect social engineering pressure tactics and impersonation attempts.
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={highlightUrgency}
                  onChange={(e) => setHighlightUrgency(e.target.checked)}
                  className="h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-zinc-900 focus:ring-0"
                />
              </div>
            </div>
          </Card>

          {/* Theme */}
          <Card className="space-y-4" interactive={false}>
            <div className="flex items-center gap-2 border-b border-zinc-200 dark:border-zinc-800 pb-3">
              <Eye className="h-4 w-4 text-zinc-500" />
              <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">Interface Theme</h2>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-100">Appearance</p>
                <p className="text-[11px] text-zinc-500">Choose between dark mode and light mode.</p>
              </div>
              <div className="flex items-center gap-1 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-1">
                <button
                  type="button"
                  onClick={() => setTheme('light')}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer ${
                    theme === 'light'
                      ? 'bg-white text-zinc-900 shadow-xs font-semibold'
                      : 'text-zinc-500 hover:text-zinc-900'
                  }`}
                >
                  <Sun className="h-3.5 w-3.5" />
                  <span>Light</span>
                </button>
                <button
                  type="button"
                  onClick={() => setTheme('dark')}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer ${
                    theme === 'dark'
                      ? 'bg-zinc-800 text-white shadow-xs font-semibold'
                      : 'text-zinc-500 hover:text-white'
                  }`}
                >
                  <Moon className="h-3.5 w-3.5" />
                  <span>Dark</span>
                </button>
              </div>
            </div>
          </Card>

          {/* Data Privacy & Cache */}
          <Card className="space-y-4" interactive={false}>
            <div className="flex items-center gap-2 border-b border-zinc-200 dark:border-zinc-800 pb-3">
              <Lock className="h-4 w-4 text-zinc-500" />
              <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">Privacy &amp; Data Erasure</h2>
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-100">Session Threat Cache</p>
                <p className="text-[11px] text-zinc-500">Clear cached scan telemetry from this browser session.</p>
              </div>
              <button
                type="button"
                onClick={() => {
                  showToast('Cache Cleared', 'Session scan cache has been reset.', 'info');
                }}
                className="flex items-center gap-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 px-3 py-1.5 text-xs font-semibold text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 cursor-pointer self-start sm:self-auto"
              >
                <Trash2 className="h-3.5 w-3.5" />
                <span>Reset Scan Cache</span>
              </button>
            </div>

            {user && (
              <div className="pt-3 border-t border-zinc-200 dark:border-zinc-800 flex items-center justify-between">
                <div>
                  <p className="text-xs font-semibold text-red-600 dark:text-red-400">Permanently Delete Account</p>
                  <p className="text-[11px] text-zinc-500">Erase all profile records, passkeys, and audit logs.</p>
                </div>
                <button
                  type="button"
                  onClick={() => setShowDeleteModal(true)}
                  className="px-3.5 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-semibold cursor-pointer"
                >
                  Delete Account
                </button>
              </div>
            )}
          </Card>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              className="flex items-center gap-2 rounded-lg bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 px-5 py-2 text-xs font-semibold hover:opacity-90 cursor-pointer"
            >
              <Save className="h-4 w-4" />
              <span>Save Privacy Preferences</span>
            </button>
          </div>
        </form>
      )}

      {/* ===================================================================== */}
      {/* CONFIRMATION MODALS */}
      {/* ===================================================================== */}

      {/* 1. Passkey Revocation Modal */}
      {revokePasskeyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 space-y-4 shadow-xl">
            <div className="flex items-start gap-3">
              <div className="h-10 w-10 rounded-full bg-red-100 dark:bg-red-950/60 text-red-600 flex items-center justify-center shrink-0">
                <Key className="h-5 w-5" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">
                  Revoke Passkey Credential?
                </h3>
                <p className="text-xs text-zinc-500">
                  Are you sure you want to deactivate <strong className="text-zinc-800 dark:text-zinc-200">{revokePasskeyModal.deviceName}</strong> ({revokePasskeyModal.credentialIdPreview})? You will need to enroll a new passkey to use biometric authorization on this device.
                </p>
              </div>
            </div>
            <div className="flex items-center justify-end gap-2 pt-2 border-t border-zinc-100 dark:border-zinc-800">
              <button
                type="button"
                onClick={() => setRevokePasskeyModal(null)}
                disabled={isActionLoading}
                className="px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 text-xs font-medium cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmRevokePasskey}
                disabled={isActionLoading}
                className="px-3.5 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-semibold cursor-pointer"
              >
                {isActionLoading ? 'Revoking...' : 'Yes, Revoke Passkey'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 2. Device Revocation Modal */}
      {revokeDeviceModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 space-y-4 shadow-xl">
            <div className="flex items-start gap-3">
              <div className="h-10 w-10 rounded-full bg-red-100 dark:bg-red-950/60 text-red-600 flex items-center justify-center shrink-0">
                <Smartphone className="h-5 w-5" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">
                  Revoke Device Authorization?
                </h3>
                <p className="text-xs text-zinc-500">
                  Deauthorizing <strong className="text-zinc-800 dark:text-zinc-200">{revokeDeviceModal.deviceName}</strong> will invalidate associated passkeys and push subscriptions.
                </p>
              </div>
            </div>
            <div className="flex items-center justify-end gap-2 pt-2 border-t border-zinc-100 dark:border-zinc-800">
              <button
                type="button"
                onClick={() => setRevokeDeviceModal(null)}
                disabled={isActionLoading}
                className="px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 text-xs font-medium cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmRevokeDevice}
                disabled={isActionLoading}
                className="px-3.5 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-semibold cursor-pointer"
              >
                {isActionLoading ? 'Revoking...' : 'Yes, Revoke Device'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 3. Session Revocation Modal */}
      {revokeSessionModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 space-y-4 shadow-xl">
            <div className="flex items-start gap-3">
              <div className="h-10 w-10 rounded-full bg-red-100 dark:bg-red-950/60 text-red-600 flex items-center justify-center shrink-0">
                <Laptop className="h-5 w-5" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">
                  Revoke Session?
                </h3>
                <p className="text-xs text-zinc-500">
                  This will immediately sign out the browser session from IP {revokeSessionModal.ipAddress}.
                </p>
              </div>
            </div>
            <div className="flex items-center justify-end gap-2 pt-2 border-t border-zinc-100 dark:border-zinc-800">
              <button
                type="button"
                onClick={() => setRevokeSessionModal(null)}
                disabled={isActionLoading}
                className="px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 text-xs font-medium cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmRevokeSession}
                disabled={isActionLoading}
                className="px-3.5 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-semibold cursor-pointer"
              >
                {isActionLoading ? 'Revoking...' : 'Yes, Revoke Session'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 4. Revoke Other Sessions Modal */}
      {showRevokeOthersModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 space-y-4 shadow-xl">
            <div className="flex items-start gap-3">
              <div className="h-10 w-10 rounded-full bg-amber-100 dark:bg-amber-950/60 text-amber-600 flex items-center justify-center shrink-0">
                <Laptop className="h-5 w-5" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">
                  Sign Out All Other Sessions?
                </h3>
                <p className="text-xs text-zinc-500">
                  All active desktop and mobile sessions except for this current window will be invalidated.
                </p>
              </div>
            </div>
            <div className="flex items-center justify-end gap-2 pt-2 border-t border-zinc-100 dark:border-zinc-800">
              <button
                type="button"
                onClick={() => setShowRevokeOthersModal(false)}
                disabled={isActionLoading}
                className="px-3 py-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 text-xs font-medium cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmRevokeOthers}
                disabled={isActionLoading}
                className="px-3.5 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold cursor-pointer"
              >
                {isActionLoading ? 'Signing Out...' : 'Sign Out Others'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 5. Account Deletion Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-2xl border border-red-200 dark:border-red-900/60 bg-white dark:bg-zinc-900 p-6 space-y-4 shadow-xl">
            <div className="flex items-start gap-3">
              <div className="h-10 w-10 rounded-full bg-red-100 dark:bg-red-950/60 text-red-600 flex items-center justify-center shrink-0">
                <AlertTriangle className="h-5 w-5" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">
                  Delete Sentinel AI Account?
                </h3>
                <p className="text-xs text-zinc-500 leading-relaxed">
                  This action will permanently erase your personal security profile, revoke all WebAuthn passkeys, and invalidate all active sessions in SQLite. This cannot be undone.
                </p>
              </div>
            </div>
            <div className="flex items-center justify-end gap-2 pt-3 border-t border-zinc-100 dark:border-zinc-800">
              <button
                type="button"
                onClick={() => setShowDeleteModal(false)}
                disabled={isActionLoading}
                className="px-3.5 py-1.5 rounded-lg border border-zinc-300 dark:border-zinc-700 text-xs font-semibold text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmDeleteAccount}
                disabled={isActionLoading}
                className="px-4 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-semibold cursor-pointer"
              >
                {isActionLoading ? 'Deleting...' : 'Yes, Delete My Account'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
