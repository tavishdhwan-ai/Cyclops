'use client';

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

export type Theme = 'light' | 'dark';

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

  // Synchronously update the class
  if (nextTheme === 'dark') {
    root.classList.add('dark');
  } else {
    root.classList.remove('dark');
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
    // The inline script in <head> has already applied the class to documentElement
    if (document.documentElement.classList.contains('dark')) {
      return 'dark';
    }
    try {
      const saved = localStorage.getItem(STORAGE_KEY_PRIMARY) || localStorage.getItem(STORAGE_KEY_LEGACY);
      if (saved === 'light' || saved === 'dark') return saved;
      if (window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark';
    } catch {
      // Fallback
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
        if (!saved) {
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
    applyThemeImmediately(newTheme);
    setThemeState(newTheme);
  }, []);

  const toggleTheme = useCallback(() => {
    // Always inspect DOM directly to avoid race conditions on rapid repeated clicks
    const isCurrentlyDark =
      typeof document !== 'undefined'
        ? document.documentElement.classList.contains('dark')
        : theme === 'dark';

    const nextTheme: Theme = isCurrentlyDark ? 'light' : 'dark';
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
