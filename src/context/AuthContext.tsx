'use client';

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { createClient, isSupabaseConfigured } from '../lib/supabase/client';
import { validateEmail, formatAuthError } from '../lib/authUtils';

export interface UserProfile {
  displayName: string;
  goal: 'personal' | 'family' | 'learning' | '';
  concerns: string[];
  experience: 'beginner' | 'intermediate' | 'advanced' | '';
  onboardingCompleted: boolean;
}

export interface AuthUser {
  id: string;
  email: string;
  displayName?: string;
  avatarUrl?: string;
}

interface AuthContextType {
  user: AuthUser | null;
  profile: UserProfile;
  isLoading: boolean;
  isConfigured: boolean;
  isDemoSession: boolean;
  sendMagicLink: (email: string, redirectTo?: string) => Promise<{ success: boolean; error?: string; isDemo?: boolean }>;
  signInWithGoogle: (redirectTo?: string) => Promise<{ success: boolean; error?: string }>;
  signOut: () => Promise<void>;
  updateProfile: (updates: Partial<UserProfile>) => Promise<{ success: boolean; error?: string }>;
  deleteAccount: () => Promise<{ success: boolean; error?: string }>;
  completeDemoSignIn: (email: string) => Promise<void>;
}

const defaultProfile: UserProfile = {
  displayName: '',
  goal: '',
  concerns: [],
  experience: '',
  onboardingCompleted: false,
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const LOCAL_STORAGE_PROFILE_KEY = 'cyclops_user_profile';
const LOCAL_STORAGE_DEMO_USER_KEY = 'cyclops_demo_user';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const router = useRouter();
  const configured = isSupabaseConfigured();

  const [user, setUser] = useState<AuthUser | null>(() => {
    if (typeof window !== 'undefined') {
      try {
        const savedDemo = localStorage.getItem(LOCAL_STORAGE_DEMO_USER_KEY);
        if (savedDemo) return JSON.parse(savedDemo);
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
  const [isDemoSession, setIsDemoSession] = useState<boolean>(() => {
    if (typeof window !== 'undefined') {
      try {
        return Boolean(localStorage.getItem(LOCAL_STORAGE_DEMO_USER_KEY));
      } catch {}
    }
    return false;
  });

  // Load saved profile or active session on mount
  useEffect(() => {
    const supabase = createClient();

    if (!supabase || !configured) {
      return;
    }

    // 1. Get initial active session from Supabase
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (session?.user) {
        const authUser: AuthUser = {
          id: session.user.id,
          email: session.user.email || '',
          displayName: session.user.user_metadata?.display_name || session.user.user_metadata?.full_name || '',
          avatarUrl: session.user.user_metadata?.avatar_url,
        };
        setUser(authUser);
        setIsDemoSession(false);

        // Restore profile from metadata or backend
        const savedProfile = session.user.user_metadata?.cyclops_profile;
        if (savedProfile) {
          setProfile(savedProfile);
        } else {
          // Check local fallback
          try {
            const local = localStorage.getItem(LOCAL_STORAGE_PROFILE_KEY);
            if (local) setProfile(JSON.parse(local));
          } catch {}
        }
      }
      setIsLoading(false);
    });

    // 2. Listen to ongoing auth changes (sign in, sign out, token refresh)
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange(async (event, session) => {
      if (session?.user) {
        const authUser: AuthUser = {
          id: session.user.id,
          email: session.user.email || '',
          displayName: session.user.user_metadata?.display_name || session.user.user_metadata?.full_name || '',
          avatarUrl: session.user.user_metadata?.avatar_url,
        };
        setUser(authUser);
        setIsDemoSession(false);

        const savedProfile = session.user.user_metadata?.cyclops_profile;
        if (savedProfile) {
          setProfile(savedProfile);
        }
      } else {
        setUser(null);
        setProfile(defaultProfile);
      }
      setIsLoading(false);
    });

    return () => {
      subscription.unsubscribe();
    };
  }, [configured]);

  // Request passwordless email magic link
  const sendMagicLink = useCallback(
    async (email: string, redirectTo?: string): Promise<{ success: boolean; error?: string; isDemo?: boolean }> => {
      const emailValidation = validateEmail(email);
      if (!emailValidation.isValid) {
        return { success: false, error: emailValidation.error };
      }

      const supabase = createClient();
      const origin = typeof window !== 'undefined' ? window.location.origin : '';
      const callbackUrl = redirectTo || `${origin}/auth/callback`;

      if (!supabase || !configured) {
        // Safe development / demo mode fallback when Supabase keys are not yet configured
        return { success: true, isDemo: true };
      }

      try {
        const { error } = await supabase.auth.signInWithOtp({
          email: emailValidation.normalized,
          options: {
            emailRedirectTo: callbackUrl,
            shouldCreateUser: true,
          },
        });

        if (error) {
          return { success: false, error: formatAuthError(error) };
        }

        return { success: true };
      } catch (err: unknown) {
        return { success: false, error: formatAuthError(err) };
      }
    },
    [configured]
  );

  // Google OAuth sign-in
  const signInWithGoogle = useCallback(
    async (redirectTo?: string): Promise<{ success: boolean; error?: string }> => {
      const supabase = createClient();
      const origin = typeof window !== 'undefined' ? window.location.origin : '';
      const callbackUrl = redirectTo || `${origin}/auth/callback`;

      if (!supabase || !configured) {
        return {
          success: false,
          error: 'Google Sign-In requires active Supabase credentials in .env.local with Google OAuth provider enabled.',
        };
      }

      try {
        const { error } = await supabase.auth.signInWithOAuth({
          provider: 'google',
          options: {
            redirectTo: callbackUrl,
            queryParams: {
              access_type: 'offline',
              prompt: 'select_account',
            },
          },
        });

        if (error) {
          return { success: false, error: formatAuthError(error) };
        }

        return { success: true };
      } catch (err: unknown) {
        return { success: false, error: formatAuthError(err) };
      }
    },
    [configured]
  );

  // Demo sign-in completion (for previewing when Supabase keys are pending)
  const completeDemoSignIn = useCallback(async (email: string) => {
    const emailValidation = validateEmail(email);
    const normalizedEmail = emailValidation.isValid ? emailValidation.normalized : 'user@example.com';
    const demoUser: AuthUser = {
      id: 'demo-user-' + Math.random().toString(36).substring(2, 9),
      email: normalizedEmail,
      displayName: normalizedEmail.split('@')[0],
    };
    setUser(demoUser);
    setIsDemoSession(true);
    try {
      localStorage.setItem(LOCAL_STORAGE_DEMO_USER_KEY, JSON.stringify(demoUser));
    } catch {}
  }, []);

  // Update profile and onboarding answers
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
          const { error } = await supabase.auth.updateUser({
            data: {
              cyclops_profile: updated,
              display_name: updated.displayName || user.displayName,
            },
          });
          if (error) {
            console.warn('Profile update warning:', error);
          }
        } catch (e) {
          console.warn('Could not sync profile to Supabase user metadata:', e);
        }
      }

      // Also sync to backend API if available
      try {
        await fetch('http://127.0.0.1:8000/api/user/profile', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userId: user?.id, ...updated }),
        });
      } catch {
        // Backend optional in client offline states
      }

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
      localStorage.removeItem(LOCAL_STORAGE_DEMO_USER_KEY);
      localStorage.removeItem(LOCAL_STORAGE_PROFILE_KEY);
    } catch {}

    setUser(null);
    setProfile(defaultProfile);
    setIsDemoSession(false);
    router.push('/login');
  }, [configured, router]);

  // Delete account end-to-end
  const deleteAccount = useCallback(async (): Promise<{ success: boolean; error?: string }> => {
    if (!user) return { success: false, error: 'No active session' };

    // 1. Call backend account deletion
    try {
      await fetch('http://127.0.0.1:8000/api/user/account', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: user.id }),
      });
    } catch (e) {
      console.warn('Backend account deletion error:', e);
    }

    // 2. Sign out and clear local state
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
        isDemoSession,
        sendMagicLink,
        signInWithGoogle,
        signOut,
        updateProfile,
        deleteAccount,
        completeDemoSignIn,
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
