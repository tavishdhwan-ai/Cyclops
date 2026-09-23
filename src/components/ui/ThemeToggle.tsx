'use client';

import React from 'react';
import { useDemoContext } from '../../context/DemoContext';
import { Sun, Moon } from 'lucide-react';

interface ThemeToggleProps {
  className?: string;
  size?: 'sm' | 'md';
}

export const ThemeToggle: React.FC<ThemeToggleProps> = ({ className = '', size = 'sm' }) => {
  const { theme, toggleTheme } = useDemoContext();
  const [mounted, setMounted] = React.useState(false);

  React.useEffect(() => {
    setMounted(true);
  }, []);

  const isDark = theme === 'dark';
  const label = isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode';

  const iconSizes = size === 'sm' ? 'h-4 w-4' : 'h-4 w-4';
  const padding = size === 'sm' ? 'p-1.5' : 'p-2';

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={label}
      title={label}
      className={`flex items-center justify-center rounded-lg border border-zinc-300 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-900 text-zinc-700 dark:text-zinc-300 hover:bg-zinc-200 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-100 active:scale-95 transition-all duration-150 cursor-pointer focus:outline-hidden focus:ring-2 focus:ring-zinc-400 dark:focus:ring-zinc-600 ${padding} ${className}`}
    >
      {!mounted ? (
        <span className={`${iconSizes} inline-block`} />
      ) : isDark ? (
        <Sun className={`${iconSizes} text-amber-400 transition-transform duration-150`} />
      ) : (
        <Moon className={`${iconSizes} text-zinc-700 dark:text-zinc-300 transition-transform duration-150`} />
      )}
    </button>
  );
};
