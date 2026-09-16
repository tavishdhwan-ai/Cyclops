import React from 'react';
import { RiskLevel, AlertSeverity } from '../../types';

interface BadgeProps {
  level?: RiskLevel | AlertSeverity | string;
  children?: React.ReactNode;
  size?: 'sm' | 'md';
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({ level = 'neutral', children, size = 'sm', className = '' }) => {
  const norm = String(level).toLowerCase();

  let styles = 'bg-zinc-100 dark:bg-zinc-900 text-zinc-600 dark:text-zinc-400 border-zinc-300 dark:border-zinc-800';

  if (norm === 'critical' || norm === 'high' || norm === 'malicious' || norm === 'phishing' || norm === 'flagged') {
    styles = 'bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-400 border-red-200 dark:border-red-900/50';
  } else if (norm === 'warning' || norm === 'medium' || norm === 'suspicious') {
    styles = 'bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-900/50';
  } else if (norm === 'safe' || norm === 'clean' || norm === 'low' || norm === 'reviewed' || norm === 'resolved') {
    styles = 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-900/50';
  }

  const padding = size === 'sm' ? 'px-2 py-0.5 text-xs font-medium' : 'px-2.5 py-1 text-xs font-medium';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border ${styles} ${padding} ${className}`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          norm === 'critical' || norm === 'high' || norm === 'malicious' || norm === 'phishing'
            ? 'bg-red-500 dark:bg-red-400'
            : norm === 'warning' || norm === 'medium' || norm === 'suspicious'
            ? 'bg-amber-500 dark:bg-amber-400'
            : norm === 'safe' || norm === 'clean' || norm === 'low'
            ? 'bg-emerald-500 dark:bg-emerald-400'
            : 'bg-zinc-400'
        }`}
      />
      {children || level}
    </span>
  );
};
