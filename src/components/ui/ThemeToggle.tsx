'use client';

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useTheme, Theme, VALID_THEMES } from '../../context/ThemeContext';
import { Sun, SunDim, Moon, MoonStar, Check } from 'lucide-react';

interface ThemeToggleProps {
  className?: string;
  size?: 'sm' | 'md';
}

const emptySubscribe = () => () => {};

interface ThemeOptionItem {
  id: Theme;
  label: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  iconColor: string;
}

const THEME_OPTIONS: ThemeOptionItem[] = [
  {
    id: 'light',
    label: 'Light',
    description: 'Crisp daylight clarity',
    icon: Sun,
    iconColor: 'text-amber-500',
  },
  {
    id: 'soft-light',
    label: 'Soft Light',
    description: 'Warm matte stone grey',
    icon: SunDim,
    iconColor: 'text-amber-600 dark:text-amber-400',
  },
  {
    id: 'soft-dark',
    label: 'Soft Dark',
    description: 'Sophisticated charcoal',
    icon: MoonStar,
    iconColor: 'text-indigo-400 dark:text-indigo-300',
  },
  {
    id: 'dark',
    label: 'Dark',
    description: 'Deep obsidian black',
    icon: Moon,
    iconColor: 'text-blue-400 dark:text-zinc-300',
  },
];

export const ThemeToggle: React.FC<ThemeToggleProps> = ({ className = '', size = 'sm' }) => {
  const { theme, setTheme } = useTheme();
  const mounted = React.useSyncExternalStore(emptySubscribe, () => true, () => false);

  const [isOpen, setIsOpen] = useState(false);
  const [focusedIndex, setFocusedIndex] = useState(-1);
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    if (!isOpen) return;

    const handleClickOutside = (e: MouseEvent | TouchEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('touchstart', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('touchstart', handleClickOutside);
    };
  }, [isOpen]);

  // Keyboard navigation
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (!isOpen) {
        if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          setIsOpen(true);
          const currentIdx = THEME_OPTIONS.findIndex((t) => t.id === theme);
          setFocusedIndex(currentIdx !== -1 ? currentIdx : 0);
        }
        return;
      }

      switch (e.key) {
        case 'Escape':
          e.preventDefault();
          setIsOpen(false);
          triggerRef.current?.focus();
          break;
        case 'ArrowDown':
          e.preventDefault();
          setFocusedIndex((prev) => (prev + 1) % THEME_OPTIONS.length);
          break;
        case 'ArrowUp':
          e.preventDefault();
          setFocusedIndex((prev) => (prev - 1 + THEME_OPTIONS.length) % THEME_OPTIONS.length);
          break;
        case 'Enter':
        case ' ':
          e.preventDefault();
          if (focusedIndex >= 0 && focusedIndex < THEME_OPTIONS.length) {
            setTheme(THEME_OPTIONS[focusedIndex].id);
            setIsOpen(false);
            triggerRef.current?.focus();
          }
          break;
        case 'Tab':
          setIsOpen(false);
          break;
      }
    },
    [isOpen, focusedIndex, theme, setTheme]
  );

  const activeOption = THEME_OPTIONS.find((t) => t.id === theme) || THEME_OPTIONS[3];
  const ActiveIcon = activeOption.icon;

  const iconSizes = 'h-4 w-4';
  const padding = size === 'sm' ? 'p-1.5' : 'p-2';

  const handleSelect = (selectedTheme: Theme) => {
    setTheme(selectedTheme);
    setIsOpen(false);
    triggerRef.current?.focus();
  };

  return (
    <div ref={containerRef} className="relative inline-block text-left" onKeyDown={handleKeyDown}>
      <button
        ref={triggerRef}
        id="theme-toggle-btn"
        type="button"
        onClick={() => setIsOpen((prev) => !prev)}
        aria-haspopup="listbox"
        aria-expanded={isOpen}
        aria-label={`Appearance theme: ${activeOption.label}. Click to select theme.`}
        title={`Appearance: ${activeOption.label}`}
        className={`flex items-center justify-center rounded-lg border border-zinc-300 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-900 text-zinc-700 dark:text-zinc-300 hover:bg-zinc-200 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-100 active:scale-95 transition-transform duration-150 cursor-pointer focus:outline-hidden focus:ring-2 focus:ring-zinc-400 dark:focus:ring-zinc-600 ${padding} ${className}`}
      >
        {!mounted ? (
          <span className={`${iconSizes} inline-block`} />
        ) : (
          <ActiveIcon className={`${iconSizes} ${activeOption.iconColor} transition-transform duration-150`} />
        )}
      </button>

      {isOpen && (
        <div
          role="listbox"
          aria-label="Appearance Themes"
          className="absolute right-0 top-full mt-2 w-48 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-1.5 shadow-xl backdrop-blur-md z-50 animate-in fade-in zoom-in-95 duration-100"
        >
          <div className="px-2.5 py-1 text-[10px] font-semibold tracking-wider uppercase text-zinc-400 dark:text-zinc-500">
            Appearance
          </div>
          <div className="space-y-0.5">
            {THEME_OPTIONS.map((item, index) => {
              const Icon = item.icon;
              const isSelected = theme === item.id;
              const isFocused = focusedIndex === index;

              return (
                <button
                  key={item.id}
                  role="option"
                  aria-selected={isSelected}
                  type="button"
                  onClick={() => handleSelect(item.id)}
                  onMouseEnter={() => setFocusedIndex(index)}
                  className={`group flex items-center justify-between w-full px-2.5 py-2 rounded-lg text-xs font-medium cursor-pointer transition-colors text-left ${
                    isSelected
                      ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 font-semibold'
                      : isFocused
                      ? 'bg-zinc-50 dark:bg-zinc-800/50 text-zinc-800 dark:text-zinc-200'
                      : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800/40 hover:text-zinc-900 dark:hover:text-zinc-200'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`h-4 w-4 ${item.iconColor} shrink-0`} />
                    <div>
                      <span className="block leading-tight text-zinc-900 dark:text-zinc-100">{item.label}</span>
                      <span className="block text-[10px] text-zinc-400 dark:text-zinc-500 font-normal">
                        {item.description}
                      </span>
                    </div>
                  </div>

                  {isSelected && (
                    <Check className="h-3.5 w-3.5 text-zinc-900 dark:text-zinc-100 shrink-0 ml-2" />
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
