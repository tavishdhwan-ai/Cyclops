'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '../../context/AuthContext';
import {
  Shield,
  User,
  Target,
  AlertTriangle,
  Sliders,
  ArrowRight,
  Check,
  Sparkles,
  Lock,
} from 'lucide-react';

export default function OnboardingPage() {
  const router = useRouter();
  const { user, profile, updateProfile } = useAuth();

  const [displayName, setDisplayName] = useState(profile.displayName || user?.displayName || '');
  const [goal, setGoal] = useState<'personal' | 'family' | 'learning' | ''>(profile.goal || '');
  const [concerns, setConcerns] = useState<string[]>(profile.concerns || []);
  const [experience, setExperience] = useState<'beginner' | 'intermediate' | 'advanced' | ''>(
    profile.experience || ''
  );
  const [isSubmitting, setIsSubmitting] = useState(false);

  const toggleConcern = (key: string) => {
    if (concerns.includes(key)) {
      setConcerns(concerns.filter((c) => c !== key));
    } else {
      setConcerns([...concerns, key]);
    }
  };

  const handleApplyPrototypeDefaults = () => {
    setDisplayName('');
    setGoal('personal');
    setConcerns(['phishing', 'documents']);
    setExperience('beginner');
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);

    await updateProfile({
      displayName: displayName.trim(),
      goal,
      concerns,
      experience,
      onboardingCompleted: true,
    });

    setIsSubmitting(false);
    router.push('/dashboard');
  };

  const handleSkip = async () => {
    setIsSubmitting(true);
    await updateProfile({
      onboardingCompleted: true,
    });
    setIsSubmitting(false);
    router.push('/dashboard');
  };

  return (
    <div className="min-h-[calc(100vh-3.5rem)] flex items-center justify-center p-4 sm:p-6 lg:p-8">
      <div className="w-full max-w-xl space-y-6">
        {/* Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex h-10 w-10 items-center justify-center rounded-xl bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 shadow-sm mb-1">
            <Shield className="h-5 w-5" />
          </div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-100">
            Personalize your security experience
          </h1>
          <p className="text-xs sm:text-sm text-zinc-600 dark:text-zinc-400">
            {user?.email ? `Signed in as ${user.email}. ` : ''}
            Tailor how findings and warnings are explained. All questions are completely optional.
          </p>
        </div>

        {/* Prototype UX Example Notice */}
        <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/60 p-3.5 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-amber-500 shrink-0" />
            <span className="text-zinc-700 dark:text-zinc-300">
              Testing prototype? Load sample choices:
            </span>
          </div>
          <button
            type="button"
            onClick={handleApplyPrototypeDefaults}
            className="font-medium text-xs text-zinc-900 dark:text-white underline hover:opacity-80 cursor-pointer"
          >
            Load prototype example
          </button>
        </div>

        {/* Form Container */}
        <form onSubmit={handleSave} className="rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 sm:p-8 shadow-sm space-y-6">
          {/* 1. Display Name (Optional) */}
          <div className="space-y-1.5">
            <label
              htmlFor="display-name-input"
              className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100 flex items-center justify-between"
            >
              <span className="flex items-center gap-1.5">
                <User className="h-3.5 w-3.5 text-zinc-500" />
                <span>Display Name</span>
              </span>
              <span className="text-[11px] font-normal text-zinc-400">Optional</span>
            </label>
            <input
              id="display-name-input"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Alex"
              maxLength={50}
              className="block w-full rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-xs text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:border-zinc-900 dark:focus:border-zinc-100 focus:outline-hidden focus:ring-2 focus:ring-zinc-200 dark:focus:ring-zinc-800"
            />
          </div>

          {/* 2. Primary Goal */}
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100 flex items-center gap-1.5">
              <Target className="h-3.5 w-3.5 text-zinc-500" />
              <span>What is your primary goal?</span>
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              {[
                {
                  id: 'personal',
                  title: 'Personal Protection',
                  desc: 'Protect my accounts, emails, and links.',
                },
                {
                  id: 'family',
                  title: 'Family Safety',
                  desc: 'Protect non-technical family members.',
                },
                {
                  id: 'learning',
                  title: 'Security Learning',
                  desc: 'Learn to identify phishing and cyber threats.',
                },
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
                      <span className="font-semibold text-zinc-900 dark:text-zinc-100">
                        {item.title}
                      </span>
                      {selected && <Check className="h-3.5 w-3.5 text-zinc-900 dark:text-white" />}
                    </div>
                    <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-tight">
                      {item.desc}
                    </p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* 3. Primary Security Concerns */}
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <AlertTriangle className="h-3.5 w-3.5 text-zinc-500" />
                <span>What are you most concerned about?</span>
              </span>
              <span className="text-[11px] font-normal text-zinc-400">Select all that apply</span>
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {[
                { id: 'phishing', label: 'Phishing & Fake Login Emails' },
                { id: 'documents', label: 'Hidden Macros in PDFs & Word Docs' },
                { id: 'downloads', label: 'Unsafe Downloads & Disguised Files' },
                { id: 'privacy', label: 'Website Trackers & Privacy Leaks' },
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
                    <span className="text-zinc-800 dark:text-zinc-200 text-[11px] font-medium">
                      {item.label}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* 4. Experience Level */}
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-zinc-900 dark:text-zinc-100 flex items-center gap-1.5">
              <Sliders className="h-3.5 w-3.5 text-zinc-500" />
              <span>Security experience level</span>
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              {[
                {
                  id: 'beginner',
                  title: 'Beginner',
                  desc: 'Plain English warnings and simple steps.',
                },
                {
                  id: 'intermediate',
                  title: 'Intermediate',
                  desc: 'Key technical signals and domain details.',
                },
                {
                  id: 'advanced',
                  title: 'Advanced',
                  desc: 'Full raw headers, TLS chains, and hex analysis.',
                },
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
                      <span className="font-semibold text-zinc-900 dark:text-zinc-100">
                        {item.title}
                      </span>
                      {selected && <Check className="h-3.5 w-3.5 text-zinc-900 dark:text-white" />}
                    </div>
                    <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-tight">
                      {item.desc}
                    </p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Action Buttons */}
          <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3">
            <button
              type="button"
              onClick={handleSkip}
              disabled={isSubmitting}
              className="text-xs text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100 underline cursor-pointer order-2 sm:order-1"
            >
              Skip for now (all scanners remain accessible)
            </button>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full sm:w-auto flex items-center justify-center gap-2 rounded-lg bg-zinc-900 dark:bg-white px-5 py-2.5 text-xs font-semibold text-white dark:text-zinc-900 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-xs cursor-pointer order-1 sm:order-2"
            >
              {isSubmitting ? (
                <span>Saving preferences...</span>
              ) : (
                <>
                  <span>Save & Continue</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </>
              )}
            </button>
          </div>
        </form>

        <p className="text-center text-[11px] text-zinc-400 flex items-center justify-center gap-1.5">
          <Lock className="h-3 w-3" />
          <span>Your preferences are stored privately and can be edited or deleted anytime in Settings.</span>
        </p>
      </div>
    </div>
  );
}
