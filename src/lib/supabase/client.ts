import { createBrowserClient } from '@supabase/ssr';
import type { SupabaseClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';

export const isSupabaseConfigured = (): boolean => {
  return Boolean(
    supabaseUrl &&
    supabaseAnonKey &&
    supabaseUrl.startsWith('https://') &&
    !supabaseUrl.includes('your-project-ref') &&
    !supabaseAnonKey.includes('your-anon-key')
  );
};

let browserClient: SupabaseClient | null = null;

export const createClient = (): SupabaseClient | null => {
  if (!isSupabaseConfigured()) {
    return null;
  }

  if (!browserClient) {
    browserClient = createBrowserClient(supabaseUrl, supabaseAnonKey);
  }

  return browserClient;
};

export const getSupabaseConfigDetails = () => {
  return {
    isConfigured: isSupabaseConfigured(),
    hasUrl: Boolean(supabaseUrl),
    hasKey: Boolean(supabaseAnonKey),
    urlDomain: supabaseUrl ? new URL(supabaseUrl).hostname : null,
  };
};
