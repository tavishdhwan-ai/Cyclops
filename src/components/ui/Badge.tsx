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

  let styles = 'bg-zinc-900 text-zinc-400 border-zinc-800';

  if (norm === 'critical' || norm === 'high' || norm === 'malicious' || norm === 'phishing' || norm === 'flagged') {
    styles = 'bg-red-950/40 text-red-400 border-red-900/50';
  } else if (norm === 'warning' || norm === 'medium' || norm === 'suspicious') {
    styles = 'bg-amber-950/40 text-amber-400 border-amber-900/50';
  } else if (norm === 'safe' || norm === 'clean' || norm === 'low' || norm === 'reviewed' || norm === 'resolved') {
    styles = 'bg-emerald-950/40 text-emerald-400 border-emerald-900/50';
  }

  const padding = size === 'sm' ? 'px-2 py-0.5 text-xs font-medium' : 'px-2.5 py-1 text-xs font-medium';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border ${styles} ${padding} ${className}`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          norm === 'critical' || norm === 'high' || norm === 'malicious' || norm === 'phishing'
            ? 'bg-red-400'
            : norm === 'warning' || norm === 'medium' || norm === 'suspicious'
            ? 'bg-amber-400'
            : norm === 'safe' || norm === 'clean' || norm === 'low'
            ? 'bg-emerald-400'
            : 'bg-zinc-400'
        }`}
      />
      {children || level}
    </span>
  );
};
