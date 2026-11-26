'use client';

import React from 'react';
import { useTheme, Theme, VALID_THEMES } from '../../context/ThemeContext';
import { Sun, SunDim, Moon, MoonStar, Check, ShieldCheck, Sparkles } from 'lucide-react';

interface ThemeCardData {
  id: Theme;
  name: string;
  subtitle: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  iconColor: string;
  palette: {
    mainBg: string;
    sidebarBg: string;
    cardBg: string;
    border: string;
    textPrimary: string;
    textSecondary: string;
    accent: string;
    badgeBg: string;
    badgeText: string;
  };
}

const THEME_CARDS: ThemeCardData[] = [
  {
    id: 'light',
    name: 'Light',
    subtitle: 'Daylight Mode',
    description: 'Crisp, high-contrast daylight clarity for bright environments.',
    icon: Sun,
    iconColor: 'text-amber-500',
    palette: {
      mainBg: '#fafafa',
      sidebarBg: '#ffffff',
      cardBg: '#ffffff',
      border: '#e4e4e7',
      textPrimary: '#09090b',
      textSecondary: '#71717a',
      accent: '#10b981',
      badgeBg: '#ecfdf5',
      badgeText: '#047857',
    },
  },
  {
    id: 'soft-light',
    name: 'Soft Light',
    subtitle: 'Muted Stone',
    description: 'Warm, matte stone-grey tones that reduce eye strain without glare.',
    icon: SunDim,
    iconColor: 'text-amber-600 dark:text-amber-400',
    palette: {
      mainBg: '#DFDDD6',
      sidebarBg: '#D2D0C9',
      cardBg: '#E8E6DF',
      border: '#C5C2B9',
      textPrimary: '#34332F',
      textSecondary: '#55544F',
      accent: '#059669',
      badgeBg: '#DAD7CE',
      badgeText: '#2B5A42',
    },
  },
  {
    id: 'soft-dark',
    name: 'Soft Dark',
    subtitle: 'Charcoal Grey',
    description: 'Sophisticated charcoal surfaces without stark pure-black contrast.',
    icon: MoonStar,
    iconColor: 'text-indigo-400 dark:text-indigo-300',
    palette: {
      mainBg: '#22252B',
      sidebarBg: '#1C1F24',
      cardBg: '#2C3037',
      border: '#3B4049',
      textPrimary: '#DDE1E7',
      textSecondary: '#A9B0BB',
      accent: '#34d399',
      badgeBg: '#26312F',
      badgeText: '#6EE7B7',
    },
  },
  {
    id: 'dark',
    name: 'Dark',
    subtitle: 'Obsidian Night',
    description: 'Deep high-contrast obsidian black designed for low-light focus.',
    icon: Moon,
    iconColor: 'text-blue-400 dark:text-zinc-300',
    palette: {
      mainBg: '#09090b',
      sidebarBg: '#18181b',
      cardBg: '#18181b',
      border: '#27272a',
      textPrimary: '#f4f4f5',
      textSecondary: '#a1a1aa',
      accent: '#10b981',
      badgeBg: '#064e3b',
      badgeText: '#a7f3d0',
    },
  },
];

export const AppearanceSection: React.FC = () => {
  const { theme, setTheme } = useTheme();

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-200 dark:border-zinc-800 pb-3">
        <div>
          <h2 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-zinc-500" />
            <span>Interface Appearance</span>
          </h2>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
            Select an appearance mode tailored to your lighting conditions and visual preference.
          </p>
        </div>

        <span className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400 self-start sm:self-auto">
          Applies immediately across all sessions
        </span>
      </div>

      {/* Responsive Grid of 4 Theme Cards */}
      <div
        role="radiogroup"
        aria-label="Select interface appearance theme"
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4"
      >
        {THEME_CARDS.map((card) => {
          const Icon = card.icon;
          const isSelected = theme === card.id;
          const { palette } = card;

          return (
            <div
              key={card.id}
              role="radio"
              aria-checked={isSelected}
              tabIndex={0}
              onClick={() => setTheme(card.id)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  setTheme(card.id);
                }
              }}
              className={`group relative rounded-xl border p-3.5 transition-all duration-200 cursor-pointer flex flex-col justify-between text-left focus:outline-hidden focus:ring-2 focus:ring-zinc-400 dark:focus:ring-zinc-500 ${
                isSelected
                  ? 'border-zinc-900 dark:border-white ring-2 ring-zinc-900/10 dark:ring-white/10 bg-zinc-50/80 dark:bg-zinc-800/40 shadow-sm'
                  : 'border-zinc-200 dark:border-zinc-800/90 bg-white/60 dark:bg-zinc-900/30 hover:border-zinc-400 dark:hover:border-zinc-600 hover:scale-[1.01]'
              }`}
            >
              {/* Active Badge */}
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div
                    className={`h-7 w-7 rounded-lg flex items-center justify-center border transition-colors ${
                      isSelected
                        ? 'border-zinc-900/20 dark:border-white/20 bg-zinc-900 text-white dark:bg-white dark:text-zinc-900'
                        : 'border-zinc-200 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300'
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                  </div>
                  <div>
                    <h3 className="text-xs font-bold text-zinc-900 dark:text-zinc-100 leading-tight">
                      {card.name}
                    </h3>
                    <p className="text-[10px] text-zinc-400 dark:text-zinc-500 font-medium">
                      {card.subtitle}
                    </p>
                  </div>
                </div>

                {isSelected ? (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 shadow-xs">
                    <Check className="h-3 w-3" />
                    <span>Active</span>
                  </span>
                ) : (
                  <span className="h-4 w-4 rounded-full border border-zinc-300 dark:border-zinc-700 group-hover:border-zinc-400 dark:group-hover:border-zinc-500 transition-colors" />
                )}
              </div>

              {/* Miniature Cyclops Interface Preview */}
              <div
                className="w-full h-32 rounded-lg border overflow-hidden p-2 flex gap-1.5 transition-transform duration-200 select-none shadow-xs"
                style={{
                  backgroundColor: palette.mainBg,
                  borderColor: palette.border,
                }}
              >
                {/* Miniature Sidebar */}
                <div
                  className="w-11 h-full rounded-md border flex flex-col justify-between p-1 shrink-0"
                  style={{
                    backgroundColor: palette.sidebarBg,
                    borderColor: palette.border,
                  }}
                >
                  <div className="space-y-1">
                    {/* Cyclops Logo */}
                    <div className="flex items-center gap-1 pb-1 border-b" style={{ borderColor: palette.border }}>
                      <div
                        className="h-3.5 w-3.5 rounded flex items-center justify-center"
                        style={{ backgroundColor: palette.cardBg, border: `1px solid ${palette.border}` }}
                      >
                        <ShieldCheck className="h-2 w-2" style={{ color: palette.accent }} />
                      </div>
                      <div className="h-1.5 w-4 rounded" style={{ backgroundColor: palette.textPrimary }} />
                    </div>

                    {/* Nav Items */}
                    <div
                      className="h-2 w-full rounded flex items-center px-0.5"
                      style={{ backgroundColor: palette.cardBg }}
                    >
                      <div className="h-1 w-2 rounded" style={{ backgroundColor: palette.accent }} />
                    </div>
                    <div className="h-2 w-full rounded flex items-center px-0.5 opacity-60">
                      <div className="h-1 w-3 rounded" style={{ backgroundColor: palette.textSecondary }} />
                    </div>
                    <div className="h-2 w-full rounded flex items-center px-0.5 opacity-60">
                      <div className="h-1 w-2.5 rounded" style={{ backgroundColor: palette.textSecondary }} />
                    </div>
                  </div>

                  {/* Sidebar bottom indicator */}
                  <div
                    className="h-2 w-full rounded flex items-center justify-center"
                    style={{ backgroundColor: palette.badgeBg }}
                  >
                    <div className="h-1 w-2 rounded" style={{ backgroundColor: palette.badgeText }} />
                  </div>
                </div>

                {/* Miniature Main Area */}
                <div className="flex-1 flex flex-col gap-1.5 min-w-0">
                  {/* Miniature Top Nav */}
                  <div
                    className="h-4.5 rounded border px-1.5 flex items-center justify-between"
                    style={{
                      backgroundColor: palette.sidebarBg,
                      borderColor: palette.border,
                    }}
                  >
                    <div className="flex items-center gap-1">
                      <div className="h-1.5 w-5 rounded" style={{ backgroundColor: palette.textSecondary }} />
                      <span className="text-[7px]" style={{ color: palette.textSecondary }}>/</span>
                      <div className="h-1.5 w-6 rounded" style={{ backgroundColor: palette.textPrimary }} />
                    </div>
                    <div
                      className="h-2.5 px-1 rounded-full flex items-center gap-0.5"
                      style={{ backgroundColor: palette.badgeBg }}
                    >
                      <div className="h-1 w-1 rounded-full" style={{ backgroundColor: palette.accent }} />
                      <div className="h-1 w-3 rounded" style={{ backgroundColor: palette.badgeText }} />
                    </div>
                  </div>

                  {/* Miniature Content Surface */}
                  <div
                    className="flex-1 rounded border p-1.5 flex flex-col justify-between"
                    style={{
                      backgroundColor: palette.cardBg,
                      borderColor: palette.border,
                    }}
                  >
                    <div className="space-y-1">
                      <div className="flex items-center justify-between">
                        <div className="h-2 w-10 rounded" style={{ backgroundColor: palette.textPrimary }} />
                        <span className="text-[8px] font-bold" style={{ color: palette.accent }}>98%</span>
                      </div>
                      <div className="h-1.5 w-full rounded-full overflow-hidden" style={{ backgroundColor: palette.mainBg }}>
                        <div className="h-full w-4/5 rounded-full" style={{ backgroundColor: palette.accent }} />
                      </div>
                      <div className="h-1.5 w-14 rounded" style={{ backgroundColor: palette.textSecondary, opacity: 0.7 }} />
                    </div>

                    <div className="flex items-center justify-between pt-1 border-t" style={{ borderColor: palette.border }}>
                      <div className="h-1.5 w-8 rounded" style={{ backgroundColor: palette.textSecondary }} />
                      <div
                        className="h-2.5 w-5 rounded flex items-center justify-center text-[6px] font-bold"
                        style={{ backgroundColor: palette.badgeBg, color: palette.badgeText }}
                      >
                        OK
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Description */}
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-3 line-clamp-2 leading-relaxed">
                {card.description}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
};
