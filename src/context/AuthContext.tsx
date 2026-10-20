'use client';

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { createClient, isSupabaseConfigured } from '../lib/supabase/client';
import { validateEmail, formatAuthError } from '../lib/authUtils';
import { normalizePhoneNumber } from '../lib/phoneUtils';

export interface UserProfile {
  displayName: string;
  goal: 'personal' | 'family' | 'learning' | '';
  concerns: string[];
  experience: 'beginner' | 'intermediate' | 'advanced' | '';
  onboardingCompleted: boolean;
  securityTier?: number;
}

export interface AuthUser {
  id: string;
  email: string;
  phoneNumber?: string;
  displayName?: string;
  avatarUrl?: string;
  securityTier?: number;
}

interface AuthContextType {
  user: AuthUser | null;
  profile: UserProfile;
  isLoading: boolean;
  isConfigured: boolean;
  startSentinelAuth: (
    email: string,
    phoneNumber: string
  ) => Promise<{ success: boolean; transactionId?: string; error?: string }>;
  confirmEmailGate: (
    transactionId: string
  ) => Promise<{ success: boolean; error?: string }>;
  completeSession: (
    transactionId: string
  ) => Promise<{ success: boolean; user?: AuthUser; error?: string }>;
  signOut: () => Promise<void>;
  updateProfile: (updates: Partial<UserProfile>) => Promise<{ success: boolean; error?: string }>;
  deleteAccount: () => Promise<{ success: boolean; error?: string }>;
}

const defaultProfile: UserProfile = {
  displayName: '',
  goal: '',
  concerns: [],
  experience: '',
  onboardingCompleted: false,
  securityTier: 2,
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const LOCAL_STORAGE_PROFILE_KEY = 'sentinel_user_profile';
const LOCAL_STORAGE_USER_KEY = 'sentinel_auth_user';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const router = useRouter();
  const configured = isSupabaseConfigured();

  const [user, setUser] = useState<AuthUser | null>(() => {
    if (typeof window !== 'undefined') {
      try {
        const saved = localStorage.getItem(LOCAL_STORAGE_USER_KEY);
        if (saved) return JSON.parse(saved);
      } catch {}
    }
    return null;
  });

  const [profile, setProfile] = useState<UserProfile>(() => {
    if (typeof window !== 'undefined') {
      try {
        const saved = localStorage.getItem(LOCAL_STORAGE_PROFILE_KEY);
        if (saved) return JSON.parse(saved);
      } catch {}
    }
    return defaultProfile;
  });

  const [isLoading, setIsLoading] = useState<boolean>(() => configured);

  // Restore authenticated session on mount
  useEffect(() => {
    const supabase = createClient();

    // 1. Check Supabase session if configured
    if (supabase && configured) {
      supabase.auth.getSession().then(({ data: { session } }) => {
        if (session?.user) {
          const authUser: AuthUser = {
            id: session.user.id,
            email: session.user.email || '',
            phoneNumber: session.user.phone,
            displayName: session.user.user_metadata?.display_name || session.user.user_metadata?.full_name || '',
            avatarUrl: session.user.user_metadata?.avatar_url,
            securityTier: 2,
          };
          setUser(authUser);
          try {
            localStorage.setItem(LOCAL_STORAGE_USER_KEY, JSON.stringify(authUser));
          } catch {}

          const savedProfile = session.user.user_metadata?.cyclops_profile;
          if (savedProfile) {
            setProfile(savedProfile);
          }
        }
        setIsLoading(false);
      });

      const {
        data: { subscription },
      } = supabase.auth.onAuthStateChange(async (_event, session) => {
        if (session?.user) {
          const authUser: AuthUser = {
            id: session.user.id,
            email: session.user.email || '',
            phoneNumber: session.user.phone,
            displayName: session.user.user_metadata?.display_name || session.user.user_metadata?.full_name || '',
            avatarUrl: session.user.user_metadata?.avatar_url,
            securityTier: 2,
          };
          setUser(authUser);
          try {
            localStorage.setItem(LOCAL_STORAGE_USER_KEY, JSON.stringify(authUser));
          } catch {}
        } else {
          setUser(null);
          setProfile(defaultProfile);
        }
        setIsLoading(false);
      });

      return () => {
        subscription.unsubscribe();
      };
    }
  }, [configured]);

  // Step 1: Start Sentinel Two-Channel Authentication
  const startSentinelAuth = useCallback(
    async (
      email: string,
      phoneNumber: string
    ): Promise<{ success: boolean; transactionId?: string; error?: string }> => {
      const emailVal = validateEmail(email);
      if (!emailVal.isValid) {
        return { success: false, error: emailVal.error };
      }

      const phoneVal = normalizePhoneNumber(phoneNumber);
      if (!phoneVal.isValid) {
        return { success: false, error: phoneVal.error };
      }

      try {
        // 1. Call server to initiate authoritative transaction
        const res = await fetch('/api/auth/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: emailVal.normalized,
            phoneNumber: phoneVal.normalized,
          }),
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          return { success: false, error: errData.detail || 'Failed to start authentication transaction.' };
        }

        const data = await res.json();
        const transactionId = data.transactionId;

        // 2. Dispatch genuine email magic link via Supabase if configured
        const supabase = createClient();
        if (supabase && configured) {
          const origin = typeof window !== 'undefined' ? window.location.origin : '';
          const callbackUrl = `${origin}/auth/callback?tx=${transactionId}`;
          const { error } = await supabase.auth.signInWithOtp({
            email: emailVal.normalized,
            options: {
              emailRedirectTo: callbackUrl,
              shouldCreateUser: true,
            },
          });

          if (error) {
            return { success: false, error: formatAuthError(error) };
          }
        }

        return { success: true, transactionId };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Network error initiating authentication.';
        return { success: false, error: msg };
      }
    },
    [configured]
  );

  // Step 2: Confirm Email Gate 1
  const confirmEmailGate = useCallback(
    async (transactionId: string): Promise<{ success: boolean; error?: string }> => {
      try {
        const res = await fetch('/api/auth/confirm-email', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ transactionId, email: user?.email || '' }),
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          return { success: false, error: errData.detail || 'Failed to confirm email gate.' };
        }

        return { success: true };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Error confirming email gate.';
        return { success: false, error: msg };
      }
    },
    [user]
  );

  // Step 3: Complete Computer Session (revalidates both gates on server)
  const completeSession = useCallback(
    async (transactionId: string): Promise<{ success: boolean; user?: AuthUser; error?: string }> => {
      try {
        const res = await fetch('/api/auth/complete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ transactionId }),
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          return { success: false, error: errData.detail || 'Server-side session authorization failed.' };
        }

        const data = await res.json();
        const authUser: AuthUser = {
          id: data.user.id,
          email: data.user.email,
          phoneNumber: data.user.phoneNumber,
          displayName: data.user.displayName,
          securityTier: data.user.securityTier || 2,
        };

        setUser(authUser);
        try {
          localStorage.setItem(LOCAL_STORAGE_USER_KEY, JSON.stringify(authUser));
        } catch {}

        return { success: true, user: authUser };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Failed to finalize authenticated session.';
        return { success: false, error: msg };
      }
    },
    []
  );

  // Update profile preferences
  const updateProfile = useCallback(
    async (updates: Partial<UserProfile>): Promise<{ success: boolean; error?: string }> => {
      const updated: UserProfile = { ...profile, ...updates };
      setProfile(updated);

      try {
        localStorage.setItem(LOCAL_STORAGE_PROFILE_KEY, JSON.stringify(updated));
      } catch {}

      const supabase = createClient();
      if (supabase && configured && user) {
        try {
          await supabase.auth.updateUser({
            data: {
              cyclops_profile: updated,
              display_name: updated.displayName || user.displayName,
            },
          });
        } catch (e) {
          console.warn('Could not sync profile to Supabase user metadata:', e);
        }
      }

      try {
        await fetch('http://127.0.0.1:8000/api/user/profile', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userId: user?.id, ...updated }),
        });
      } catch {}

      return { success: true };
    },
    [profile, configured, user]
  );

  // Sign out cleanly
  const signOut = useCallback(async () => {
    const supabase = createClient();
    if (supabase && configured) {
      try {
        await supabase.auth.signOut();
      } catch (err) {
        console.error('Sign out error:', err);
      }
    }

    try {
      localStorage.removeItem(LOCAL_STORAGE_USER_KEY);
      localStorage.removeItem(LOCAL_STORAGE_PROFILE_KEY);
      // Remove sentinel_session cookie
      document.cookie = 'sentinel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
    } catch {}

    setUser(null);
    setProfile(defaultProfile);
    router.push('/login');
  }, [configured, router]);

  // Account deletion
  const deleteAccount = useCallback(async (): Promise<{ success: boolean; error?: string }> => {
    if (!user) return { success: false, error: 'No active session' };

    try {
      await fetch('http://127.0.0.1:8000/api/user/account', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: user.id }),
      });
    } catch (e) {
      console.warn('Backend account deletion error:', e);
    }

    await signOut();
    return { success: true };
  }, [user, signOut]);

  return (
    <AuthContext.Provider
      value={{
        user,
        profile,
        isLoading,
        isConfigured: configured,
        startSentinelAuth,
        confirmEmailGate,
        completeSession,
        signOut,
        updateProfile,
        deleteAccount,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
