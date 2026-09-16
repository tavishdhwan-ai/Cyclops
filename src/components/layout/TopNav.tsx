'use client';

import React from 'react';
import { usePathname } from 'next/navigation';
import { useDemoContext } from '../../context/DemoContext';
import { Menu, Search, Zap } from 'lucide-react';
import { ThemeToggle } from '../ui/ThemeToggle';

interface TopNavProps {
  mobileOpen: boolean;
  setMobileOpen: (open: boolean) => void;
}

export const TopNav: React.FC<TopNavProps> = ({ mobileOpen, setMobileOpen }) => {
  const pathname = usePathname();
  const { setIsQuickScanOpen, triggerRescan, activeWorkspace } = useDemoContext();

  const getPageTitle = (path: string) => {
    if (path.startsWith('/emails')) return 'Email Security';
    if (path.startsWith('/url-scanner')) return 'URL & Domain Scanner';
    if (path.startsWith('/document-scanner')) return 'Document Security';
    if (path.startsWith('/activity')) return 'Activity Audit Trail';
    if (path.startsWith('/alerts')) return 'Security Alerts Center';
    if (path.startsWith('/settings')) return 'Workspace Settings';
    return 'Security Overview';
  };

  const isEmailPage = pathname.startsWith('/emails');

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-zinc-200 dark:border-zinc-800 bg-white/80 dark:bg-zinc-950/80 px-4 backdrop-blur-md lg:px-6">
      <div className="flex items-center gap-3">
        {/* Mobile menu hamburger */}
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-1.5 text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-900 hover:text-zinc-900 dark:hover:text-zinc-100 lg:hidden"
        >
          <Menu className="h-4 w-4" />
        </button>

        {/* Page title breadcrumb */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs text-zinc-500 dark:text-zinc-400">
            <span>SentinelAI</span>
            <span>/</span>
            <span className="font-medium text-zinc-900 dark:text-zinc-200">{getPageTitle(pathname)}</span>
          </div>
          <span className="rounded-full border border-zinc-200 dark:border-zinc-800 bg-zinc-100 dark:bg-zinc-900 px-2 py-0.5 text-[10px] font-medium text-zinc-600 dark:text-zinc-400">
            Demo Mode
          </span>
        </div>
      </div>

      {/* Center/Right Actions */}
      <div className="flex items-center gap-2.5">
        {/* Theme Toggle for mobile or top nav */}
        <div className="lg:hidden">
          <ThemeToggle size="sm" />
        </div>

        {/* Workspace/User Placeholder */}
        <div className="hidden sm:flex items-center gap-2 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-100/80 dark:bg-zinc-900/60 px-2.5 py-1 text-xs text-zinc-600 dark:text-zinc-400">
          <span className="h-2 w-2 rounded-full bg-emerald-500"></span>
          <span className="font-medium text-zinc-800 dark:text-zinc-300">{activeWorkspace?.name || 'Acme Workspace'}</span>
        </div>

        {/* Rescan Button for Email Security */}
        {isEmailPage && (
          <button
            onClick={triggerRescan}
            className="flex items-center gap-1.5 rounded-lg border border-zinc-300 dark:border-zinc-700 bg-zinc-900 text-zinc-100 dark:bg-zinc-800 dark:text-zinc-100 hover:bg-zinc-800 dark:hover:bg-zinc-700 px-3 py-1.5 text-xs font-semibold transition-colors shadow-xs cursor-pointer"
          >
            <Zap className="h-3.5 w-3.5 text-amber-400" />
            <span>Rescan Email</span>
          </button>
        )}

        {/* Global Search / Command Bar Trigger */}
        <button
          onClick={() => setIsQuickScanOpen(true)}
          className="hidden md:flex items-center gap-3 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-100/80 dark:bg-zinc-900/60 px-3 py-1.5 text-xs text-zinc-500 dark:text-zinc-400 hover:border-zinc-300 dark:hover:border-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-200 transition-colors w-40 lg:w-56 cursor-pointer"
        >
          <Search className="h-3.5 w-3.5 text-zinc-400 dark:text-zinc-500" />
          <span className="flex-1 text-left truncate">Scan URL or Doc...</span>
          <kbd className="rounded border border-zinc-300 dark:border-zinc-700 bg-zinc-200 dark:bg-zinc-800 px-1.5 text-[10px] text-zinc-600 dark:text-zinc-400 font-mono">
            ⌘K
          </kbd>
        </button>

        {/* Quick Action Button */}
        {!isEmailPage && (
          <button
            onClick={() => setIsQuickScanOpen(true)}
            className="flex items-center gap-1.5 rounded-lg bg-zinc-900 text-zinc-100 dark:bg-zinc-100 dark:text-zinc-900 hover:bg-zinc-800 dark:hover:bg-white px-3 py-1.5 text-xs font-semibold transition-colors cursor-pointer"
          >
            <Zap className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">Quick Scan</span>
          </button>
        )}
      </div>
    </header>
  );
};
