'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '../../context/AuthContext';
import { COUNTRIES, LANGUAGES, COMMON_TIMEZONES } from '../../lib/profileConstants';
import {
  Shield,
  User,
  AtSign,
  Globe,
  Camera,
  Calendar,
  Languages,
  Clock,
  Target,
  AlertTriangle,
  Sliders,
  ArrowRight,
  ArrowLeft,
  Check,
  CheckCircle2,
  XCircle,
  Loader2,
  Upload,
  Lock,
} from 'lucide-react';

export default function OnboardingPage() {
  const router = useRouter();
  const { user, profile, updateProfile, sessionToken } = useAuth();

  // Step control: 1 = Profile Identity, 2 = Security Persona
  const [currentStep, setCurrentStep] = useState<1 | 2>(1);

  // Form Fields - Identity
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

  // Form Fields - Security Persona
  const [goal, setGoal] = useState<'personal' | 'family' | 'learning' | ''>(profile.goal || 'personal');
  const [concerns, setConcerns] = useState<string[]>(
    profile.concerns && profile.concerns.length > 0 ? profile.concerns : ['phishing', 'documents']
  );
  const [experience, setExperience] = useState<'beginner' | 'intermediate' | 'advanced' | ''>(
    profile.experience || 'intermediate'
  );

  // Username validation state
  const [isCheckingUsername, setIsCheckingUsername] = useState(false);
  const [usernameAvailable, setUsernameAvailable] = useState<boolean | null>(null);
  const [usernameError, setUsernameError] = useState<string | null>(null);

  // Avatar upload state
  const [isUploadingAvatar, setIsUploadingAvatar] = useState(false);
  const [avatarError, setAvatarError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // General submission state
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submissionError, setSubmissionError] = useState<string | null>(null);

  // Debounced username availability check
  useEffect(() => {
    const trimmed = username.trim().toLowerCase();
    if (!trimmed) {
      setUsernameAvailable(null);
      setUsernameError(null);
      return;
    }

    if (trimmed.length < 3 || trimmed.length > 30) {
      setUsernameAvailable(false);
      setUsernameError('Username must be 3 to 30 characters.');
      return;
    }

    if (!/^[a-zA-Z0-9_]+$/.test(trimmed)) {
      setUsernameAvailable(false);
      setUsernameError('Only alphanumeric letters and underscores are allowed.');
      return;
    }

    let active = true;
    setIsCheckingUsername(true);
    setUsernameError(null);

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
          if (!data.available) {
            setUsernameError('This username is already taken. Please choose another.');
          } else {
            setUsernameError(null);
          }
        } else {
          setUsernameAvailable(false);
          setUsernameError('Unable to check username availability.');
        }
      } catch {
        if (active) {
          setUsernameAvailable(null);
        }
      } finally {
        if (active) setIsCheckingUsername(false);
      }
    }, 400);

    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [username, sessionToken]);

  // Handle Avatar file selection & upload
  const handleAvatarFile = async (file: File) => {
    setAvatarError(null);
    if (!file.type.startsWith('image/')) {
      setAvatarError('Please select a valid image file (JPEG, PNG, WEBP).');
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      setAvatarError('Profile picture must be under 5MB.');
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
        throw new Error(errJson.detail || 'Failed to upload profile picture.');
      }

      const data = await res.json();
      setProfilePictureUrl(data.avatarUrl);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error uploading profile image.';
      setAvatarError(msg);
    } finally {
      setIsUploadingAvatar(false);
    }
  };

  const toggleConcern = (key: string) => {
    if (concerns.includes(key)) {
      setConcerns(concerns.filter((c) => c !== key));
    } else {
      setConcerns([...concerns, key]);
    }
  };

  const handleStep1Next = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmissionError(null);

    if (!fullName.trim()) {
      setSubmissionError('Please enter your full name.');
      return;
    }

    if (!username.trim() || usernameAvailable === false) {
      setSubmissionError(usernameError || 'Please provide a valid, unique username.');
      return;
    }

    if (!country.trim()) {
      setSubmissionError('Please select your country.');
      return;
    }

    setCurrentStep(2);
  };

  const handleFinalSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setSubmissionError(null);

    const updatePayload = {
      fullName: fullName.trim(),
      displayName: fullName.trim(),
      username: username.trim().toLowerCase(),
      country,
      profilePictureUrl,
      dateOfBirth,
      preferredLanguage,
      timeZone,
      goal,
      concerns,
      experience,
      onboardingCompleted: true,
    };

    const res = await updateProfile(updatePayload);
    setIsSubmitting(false);

    if (res.success) {
      router.push('/dashboard');
    } else {
      setSubmissionError(res.error || 'Failed to save profile. Please review your details.');
    }
  };

  return (
    <div className="min-h-[calc(100vh-3.5rem)] flex items-center justify-center p-4 sm:p-6 lg:p-8">
      <div className="w-full max-w-2xl space-y-6">
        {/* Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 shadow-sm mb-1">
            <Shield className="h-6 w-6" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-100">
            Welcome to Sentinel AI
          </h1>
          <p className="text-xs sm:text-sm text-zinc-600 dark:text-zinc-400">
            {user?.email ? `Signed in as ${user.email}. ` : ''}
            Complete your profile to customize your defense telemetry and biometric alerts.
          </p>

          {/* Stepper indicator */}
          <div className="flex items-center justify-center gap-3 pt-2">
            <div
              className={`flex items-center gap-1.5 text-xs font-semibold px-3 py-1 rounded-full ${
                currentStep === 1
                  ? 'bg-zinc-900 text-white dark:bg-white dark:text-zinc-900'
                  : 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400'
              }`}
            >
              <span className="h-4 w-4 rounded-full bg-zinc-700 dark:bg-zinc-300 text-white dark:text-zinc-900 flex items-center justify-center text-[10px]">
                1
              </span>
              <span>Profile &amp; Identity</span>
            </div>
            <div className="h-0.5 w-6 bg-zinc-200 dark:bg-zinc-700" />
            <div
              className={`flex items-center gap-1.5 text-xs font-semibold px-3 py-1 rounded-full ${
                currentStep === 2
                  ? 'bg-zinc-900 text-white dark:bg-white dark:text-zinc-900'
                  : 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400'
              }`}
            >
              <span className="h-4 w-4 rounded-full bg-zinc-700 dark:bg-zinc-300 text-white dark:text-zinc-900 flex items-center justify-center text-[10px]">
                2
              </span>
              <span>Protection Goals</span>
            </div>
          </div>
        </div>

        {/* Global Error Banner */}
        {submissionError && (
          <div
            role="alert"
            className="flex items-start gap-2.5 rounded-xl border border-red-200 dark:border-red-900/50 bg-red-50 dark:bg-red-950/30 p-3.5 text-xs text-red-800 dark:text-red-300"
          >
            <AlertTriangle className="h-4 w-4 shrink-0 text-red-600 dark:text-red-400 mt-0.5" />
            <p className="leading-relaxed">{submissionError}</p>
          </div>
        )}

        {/* Wizard Form */}
        <div className="rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 sm:p-8 shadow-sm">
          {currentStep === 1 ? (
            <form onSubmit={handleStep1Next} className="space-y-6">
              <div className="border-b border-zinc-100 dark:border-zinc-800 pb-3">
                <h2 className="text-base font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
                  <User className="h-4 w-4 text-zinc-600 dark:text-zinc-400" />
                  <span>Personal Identity &amp; Region</span>
                </h2>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  Provide your profile credentials and regional settings.
                </p>
              </div>

              {/* Avatar Uploader */}
              <div className="flex items-center gap-4">
                <div className="relative h-16 w-16 rounded-full overflow-hidden bg-zinc-100 dark:bg-zinc-800 border-2 border-zinc-200 dark:border-zinc-700 flex items-center justify-center shrink-0">
                  {profilePictureUrl ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img
                      src={profilePictureUrl}
                      alt="Avatar preview"
                      className="h-full w-full object-cover"
                    />
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
                    Profile Picture <span className="text-zinc-400 font-normal">(Optional)</span>
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
                      <span>{profilePictureUrl ? 'Change Photo' : 'Upload Photo'}</span>
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
                  <p className="text-[10px] text-zinc-400">JPG, PNG or WebP up to 5MB.</p>
                  {avatarError && <p className="text-[11px] text-red-500">{avatarError}</p>}
                </div>
              </div>

              {/* Required: Full Name & Username */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label
                    htmlFor="full-name-input"
                    className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100"
                  >
                    Full Name <span className="text-red-500">*</span>
                  </label>
                  <div className="relative">
                    <input
                      id="full-name-input"
                      type="text"
                      required
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      placeholder="e.g. Alex Vance"
                      className="block w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-xs text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 focus:border-zinc-900 dark:focus:border-zinc-100 focus:outline-hidden"
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <label
                      htmlFor="username-input"
                      className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100"
                    >
                      Unique Username <span className="text-red-500">*</span>
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
                      id="username-input"
                      type="text"
                      required
                      value={username}
                      onChange={(e) => setUsername(e.target.value.toLowerCase())}
                      placeholder="e.g. alex_vance"
                      maxLength={30}
                      className={`block w-full rounded-lg border pl-8 pr-8 py-2 text-xs text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 focus:outline-hidden ${
                        usernameError
                          ? 'border-red-400 focus:border-red-500'
                          : usernameAvailable === true
                          ? 'border-emerald-500 focus:border-emerald-600'
                          : 'border-zinc-300 dark:border-zinc-700 focus:border-zinc-900 dark:focus:border-zinc-100'
                      } bg-white dark:bg-zinc-950`}
                    />
                    <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-2.5">
                      {usernameAvailable === true && (
                        <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                      )}
                      {usernameError && <XCircle className="h-4 w-4 text-red-500" />}
                    </div>
                  </div>
                  {usernameError ? (
                    <p className="text-[10px] text-red-500">{usernameError}</p>
                  ) : usernameAvailable === true ? (
                    <p className="text-[10px] text-emerald-600 dark:text-emerald-400">
                      ✓ Username is available
                    </p>
                  ) : (
                    <p className="text-[10px] text-zinc-400">3-30 letters, numbers, and underscores.</p>
                  )}
                </div>
              </div>

              {/* Required Country & Optional DOB */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label
                    htmlFor="country-select"
                    className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100"
                  >
                    Country of Residence <span className="text-red-500">*</span>
                  </label>
                  <div className="relative">
                    <select
                      id="country-select"
                      required
                      value={country}
                      onChange={(e) => setCountry(e.target.value)}
                      className="block w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-xs text-zinc-900 dark:text-zinc-100 focus:border-zinc-900 dark:focus:border-zinc-100 focus:outline-hidden"
                    >
                      {COUNTRIES.map((c) => (
                        <option key={c.code} value={c.name}>
                          {c.name}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor="dob-input"
                    className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100 flex items-center justify-between"
                  >
                    <span>Date of Birth</span>
                    <span className="text-[10px] font-normal text-zinc-400">Optional</span>
                  </label>
                  <input
                    id="dob-input"
                    type="date"
                    value={dateOfBirth}
                    onChange={(e) => setDateOfBirth(e.target.value)}
                    className="block w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-xs text-zinc-900 dark:text-zinc-100 focus:border-zinc-900 dark:focus:border-zinc-100 focus:outline-hidden"
                  />
                </div>
              </div>

              {/* Optional: Language & Timezone */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label
                    htmlFor="lang-select"
                    className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100"
                  >
                    Preferred Language
                  </label>
                  <select
                    id="lang-select"
                    value={preferredLanguage}
                    onChange={(e) => setPreferredLanguage(e.target.value)}
                    className="block w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-xs text-zinc-900 dark:text-zinc-100 focus:border-zinc-900 dark:focus:border-zinc-100 focus:outline-hidden"
                  >
                    {LANGUAGES.map((l) => (
                      <option key={l.code} value={l.code}>
                        {l.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor="timezone-select"
                    className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100"
                  >
                    Time Zone <span className="text-[10px] text-zinc-400">(Auto-detected)</span>
                  </label>
                  <select
                    id="timezone-select"
                    value={timeZone}
                    onChange={(e) => setTimeZone(e.target.value)}
                    className="block w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-xs text-zinc-900 dark:text-zinc-100 focus:border-zinc-900 dark:focus:border-zinc-100 focus:outline-hidden"
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

              {/* Step 1 Actions */}
              <div className="pt-4 border-t border-zinc-100 dark:border-zinc-800 flex justify-end">
                <button
                  type="submit"
                  disabled={!fullName.trim() || !username.trim() || usernameAvailable === false}
                  className="flex items-center gap-2 rounded-lg bg-zinc-900 dark:bg-white px-5 py-2.5 text-xs font-semibold text-white dark:text-zinc-900 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors cursor-pointer disabled:opacity-50"
                >
                  <span>Next: Protection Goals</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </form>
          ) : (
            <form onSubmit={handleFinalSubmit} className="space-y-6">
              <div className="border-b border-zinc-100 dark:border-zinc-800 pb-3">
                <h2 className="text-base font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
                  <Target className="h-4 w-4 text-zinc-600 dark:text-zinc-400" />
                  <span>Protection Goals &amp; Security Persona</span>
                </h2>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  Configure how threats and risk scores are presented across your dashboard.
                </p>
              </div>

              {/* Primary Goal */}
              <div className="space-y-2">
                <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                  Primary Protection Objective
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                  {[
                    { id: 'personal', title: 'Personal Protection', desc: 'Secure my emails, attachments, and links.' },
                    { id: 'family', title: 'Family Safety', desc: 'Guard non-technical relatives from fraud.' },
                    { id: 'learning', title: 'Security Learning', desc: 'Deep dive into attack vectors & IOC analysis.' },
                  ].map((item) => {
                    const selected = goal === item.id;
                    return (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => setGoal(item.id as 'personal' | 'family' | 'learning')}
                        className={`text-left p-3 rounded-xl border text-xs transition-colors cursor-pointer ${
                          selected
                            ? 'border-zinc-900 dark:border-white bg-zinc-900/5 dark:bg-white/10 ring-1 ring-zinc-900 dark:ring-white'
                            : 'border-zinc-200 dark:border-zinc-800 hover:border-zinc-300 dark:hover:border-zinc-700'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-semibold text-zinc-900 dark:text-zinc-100">{item.title}</span>
                          {selected && <Check className="h-3.5 w-3.5 text-zinc-900 dark:text-white" />}
                        </div>
                        <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-tight">{item.desc}</p>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Primary Security Concerns */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                    Priority Threat Concerns
                  </label>
                  <span className="text-[10px] text-zinc-400">Select all that apply</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {[
                    { id: 'phishing', label: 'Phishing & Impersonation Emails' },
                    { id: 'documents', label: 'Hidden Macros in PDFs & Office Docs' },
                    { id: 'downloads', label: 'Suspicious Software & Executables' },
                    { id: 'privacy', label: 'Tracking Pixels & Data Breaches' },
                  ].map((item) => {
                    const checked = concerns.includes(item.id);
                    return (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => toggleConcern(item.id)}
                        className={`flex items-center gap-2.5 p-2.5 rounded-lg border text-xs text-left transition-colors cursor-pointer ${
                          checked
                            ? 'border-zinc-900 dark:border-white bg-zinc-900/5 dark:bg-white/10'
                            : 'border-zinc-200 dark:border-zinc-800 hover:border-zinc-300 dark:hover:border-zinc-700'
                        }`}
                      >
                        <div
                          className={`h-4 w-4 rounded flex items-center justify-center border transition-colors ${
                            checked
                              ? 'border-zinc-900 bg-zinc-900 dark:border-white dark:bg-white text-white dark:text-zinc-900'
                              : 'border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950'
                          }`}
                        >
                          {checked && <Check className="h-3 w-3" />}
                        </div>
                        <span className="text-zinc-800 dark:text-zinc-200 text-[11px] font-medium">{item.label}</span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Experience Level */}
              <div className="space-y-2">
                <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                  Security Experience Level
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                  {[
                    { id: 'beginner', title: 'Beginner', desc: 'Clear plain-English warnings and recommendations.' },
                    { id: 'intermediate', title: 'Intermediate', desc: 'Domain signals, SPF/DKIM details, and TLS checks.' },
                    { id: 'advanced', title: 'Advanced', desc: 'Full raw header telemetry, hashes, and IOC graphs.' },
                  ].map((item) => {
                    const selected = experience === item.id;
                    return (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => setExperience(item.id as 'beginner' | 'intermediate' | 'advanced')}
                        className={`text-left p-3 rounded-xl border text-xs transition-colors cursor-pointer ${
                          selected
                            ? 'border-zinc-900 dark:border-white bg-zinc-900/5 dark:bg-white/10 ring-1 ring-zinc-900 dark:ring-white'
                            : 'border-zinc-200 dark:border-zinc-800 hover:border-zinc-300 dark:hover:border-zinc-700'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-semibold text-zinc-900 dark:text-zinc-100">{item.title}</span>
                          {selected && <Check className="h-3.5 w-3.5 text-zinc-900 dark:text-white" />}
                        </div>
                        <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-tight">{item.desc}</p>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Step 2 Actions */}
              <div className="pt-4 border-t border-zinc-100 dark:border-zinc-800 flex items-center justify-between">
                <button
                  type="button"
                  onClick={() => setCurrentStep(1)}
                  disabled={isSubmitting}
                  className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white cursor-pointer"
                >
                  <ArrowLeft className="h-3.5 w-3.5" />
                  <span>Back</span>
                </button>

                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="flex items-center gap-2 rounded-lg bg-zinc-900 dark:bg-white px-5 py-2.5 text-xs font-semibold text-white dark:text-zinc-900 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors cursor-pointer disabled:opacity-50"
                >
                  {isSubmitting ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      <span>Saving Profile...</span>
                    </>
                  ) : (
                    <>
                      <span>Complete Onboarding &amp; Go to Dashboard</span>
                      <ArrowRight className="h-3.5 w-3.5" />
                    </>
                  )}
                </button>
              </div>
            </form>
          )}
        </div>

        <p className="text-center text-[11px] text-zinc-400 flex items-center justify-center gap-1.5">
          <Lock className="h-3 w-3" />
          <span>All profile and security preferences can be updated or revoked anytime in Settings.</span>
        </p>
      </div>
    </div>
  );
}
