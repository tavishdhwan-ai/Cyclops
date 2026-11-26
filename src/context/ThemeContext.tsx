'use client';

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

export type Theme = 'light' | 'soft-light' | 'soft-dark' | 'dark';

export interface ThemeOption {
  id: Theme;
  label: string;
  description: string;
  colorScheme: 'light' | 'dark';
}

export const THEME_OPTIONS: ThemeOption[] = [
  { id: 'light', label: 'Light', description: 'Clean, high-clarity daylight interface', colorScheme: 'light' },
  { id: 'soft-light', label: 'Soft Light', description: 'Warm, matte stone grey with reduced glare', colorScheme: 'light' },
  { id: 'soft-dark', label: 'Soft Dark', description: 'Sophisticated charcoal grey for low light', colorScheme: 'dark' },
  { id: 'dark', label: 'Dark', description: 'Deep high-contrast obsidian black', colorScheme: 'dark' },
];

export const VALID_THEMES: Theme[] = ['light', 'soft-light', 'soft-dark', 'dark'];

export function isValidTheme(value: unknown): value is Theme {
  return typeof value === 'string' && VALID_THEMES.includes(value as Theme);
}

interface ThemeContextType {
  theme: Theme;
  toggleTheme: () => void;
  setTheme: (theme: Theme) => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

const STORAGE_KEY_PRIMARY = 'cyclops_theme';
const STORAGE_KEY_LEGACY = 'sentinel_theme';

/**
 * Immediately apply the theme class to the DOM and update localStorage without
 * waiting for React reconciliation or paint.
 */
function applyThemeImmediately(nextTheme: Theme) {
  if (typeof document === 'undefined') return;

  const root = document.documentElement;

  // Temporarily disable transitions on all elements to prevent any flicker, intermediate flash, or lag
  root.classList.add('disable-transitions');

  // Set authoritative data-theme attribute
  root.setAttribute('data-theme', nextTheme);

  // Maintain clean theme-* marker classes
  root.classList.remove('theme-light', 'theme-soft-light', 'theme-soft-dark', 'theme-dark');
  root.classList.add(`theme-${nextTheme}`);

  // Synchronously update the dark class so Tailwind's dark: variant works seamlessly
  if (nextTheme === 'dark' || nextTheme === 'soft-dark') {
    root.classList.add('dark');
    root.style.colorScheme = 'dark';
  } else {
    root.classList.remove('dark');
    root.style.colorScheme = 'light';
  }

  // Persist preferences synchronously without blocking the visual update
  try {
    localStorage.setItem(STORAGE_KEY_PRIMARY, nextTheme);
    localStorage.setItem(STORAGE_KEY_LEGACY, nextTheme);
  } catch {
    // Ignore in private browsing or storage-restricted environments
  }

  // Re-enable interaction transitions after browser has committed the paint
  if (typeof requestAnimationFrame !== 'undefined') {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        root.classList.remove('disable-transitions');
      });
    });
  } else {
    root.classList.remove('disable-transitions');
  }
}

/**
 * Determine the current theme active on the DOM or in storage/system.
 */
function getInitialTheme(): Theme {
  if (typeof document !== 'undefined') {
    // Check if inline script in <head> set data-theme
    const attr = document.documentElement.getAttribute('data-theme');
    if (isValidTheme(attr)) return attr;

    // Check DOM class for theme-*
    for (const t of VALID_THEMES) {
      if (document.documentElement.classList.contains(`theme-${t}`)) return t;
    }

    try {
      const saved = localStorage.getItem(STORAGE_KEY_PRIMARY) || localStorage.getItem(STORAGE_KEY_LEGACY);
      if (isValidTheme(saved)) return saved;
      if (window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark';
    } catch {
      // Fallback
    }

    // The inline script in <head> has already applied the class to documentElement
    if (document.documentElement.classList.contains('dark')) {
      return 'dark';
    }
  }
  return 'dark';
}

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [theme, setThemeState] = useState<Theme>(getInitialTheme);

  // Synchronize if system preference changes and no explicit preference saved
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = (e: MediaQueryListEvent) => {
      try {
        const saved = localStorage.getItem(STORAGE_KEY_PRIMARY) || localStorage.getItem(STORAGE_KEY_LEGACY);
        if (!saved || !isValidTheme(saved)) {
          const newTheme: Theme = e.matches ? 'dark' : 'light';
          applyThemeImmediately(newTheme);
          setThemeState(newTheme);
        }
      } catch {
        // Ignore
      }
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  const setTheme = useCallback((newTheme: Theme) => {
    if (!isValidTheme(newTheme)) return;
    applyThemeImmediately(newTheme);
    setThemeState(newTheme);
  }, []);

  const toggleTheme = useCallback(() => {
    // Sequential fallback cycle if programmatically invoked: light -> soft-light -> soft-dark -> dark -> light
    const order: Theme[] = ['light', 'soft-light', 'soft-dark', 'dark'];
    const currentIndex = order.indexOf(theme);
    const nextTheme = order[(currentIndex + 1) % order.length];
    applyThemeImmediately(nextTheme);
    setThemeState(nextTheme);
  }, [theme]);

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = (): ThemeContextType => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};
