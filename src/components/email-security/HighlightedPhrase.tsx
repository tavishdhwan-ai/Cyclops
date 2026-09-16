'use client';

import React, { useState, useRef, useEffect } from 'react';
import { AlertCircle, Info } from 'lucide-react';

interface HighlightedPhraseProps {
  phrase: string;
  explanation: string;
}

export const HighlightedPhrase: React.FC<HighlightedPhraseProps> = ({ phrase, explanation }) => {
  const [isOpen, setIsOpen] = useState(false);
  const containerRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <span
      ref={containerRef}
      className="relative inline-block"
      onMouseEnter={() => setIsOpen(true)}
      onMouseLeave={() => setIsOpen(false)}
    >
      <button
        type="button"
        onClick={() => setIsOpen((prev) => !prev)}
        onFocus={() => setIsOpen(true)}
        className="rounded px-1.5 py-0.5 text-xs font-semibold text-red-700 dark:text-red-300 bg-red-100 dark:bg-red-950/60 border border-red-300 dark:border-red-800/60 hover:bg-red-200 dark:hover:bg-red-900/80 hover:border-red-400 dark:hover:border-red-600 focus:outline-none focus:ring-2 focus:ring-red-400/50 dark:focus:ring-red-500/50 underline decoration-red-400 dark:decoration-red-400/80 decoration-dotted underline-offset-2 transition-colors cursor-pointer inline-flex items-center gap-1 mx-0.5"
        aria-expanded={isOpen}
      >
        <span>{phrase}</span>
        <AlertCircle className="h-3 w-3 text-red-500 dark:text-red-400 shrink-0 inline" />
      </button>

      {/* Popover / Tooltip */}
      {isOpen && (
        <div
          role="tooltip"
          className="absolute left-0 bottom-full mb-2 z-50 w-72 md:w-80 rounded-lg border border-red-200 dark:border-red-900/60 bg-white dark:bg-zinc-900 p-3 shadow-2xl backdrop-blur-md text-left transition-all"
        >
          <div className="flex items-start gap-2 border-b border-zinc-200 dark:border-zinc-800 pb-2 mb-2">
            <Info className="h-4 w-4 text-red-500 dark:text-red-400 mt-0.5 shrink-0" />
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider text-red-600 dark:text-red-400">
                Suspicious Signal Detected
              </p>
              <p className="text-xs font-mono font-semibold text-zinc-900 dark:text-zinc-100">&quot;{phrase}&quot;</p>
            </div>
          </div>
          <p className="text-xs text-zinc-600 dark:text-zinc-300 leading-relaxed">{explanation}</p>
          <div className="mt-2 pt-1.5 border-t border-zinc-200 dark:border-zinc-800/80 flex items-center justify-between text-[10px] text-zinc-500">
            <span>SentinelAI Signal Analysis</span>
            <span className="text-red-500 dark:text-red-400 font-medium">Risk Score +2.5</span>
          </div>
        </div>
      )}
    </span>
  );
};
