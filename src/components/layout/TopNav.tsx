'use client';

import React from 'react';
import { usePathname } from 'next/navigation';
import { useDemoContext } from '../../context/DemoContext';
import { Menu, Search, Zap, LogOut } from 'lucide-react';
import { ThemeToggle } from '../ui/ThemeToggle';
import { useAuth } from '../../context/AuthContext';

interface TopNavProps {
  mobileOpen: boolean;
  setMobileOpen: (open: boolean) => void;
}

export const TopNav: React.FC<TopNavProps> = ({ mobileOpen, setMobileOpen }) => {
  const pathname = usePathname();
  const { setIsQuickScanOpen, triggerRescan } = useDemoContext();
  const { user, signOut } = useAuth();

  const getPageTitle = (path: string) => {
    if (path.startsWith('/emails')) return 'Email Scanner';
    if (path.startsWith('/url-scanner')) return 'Link Scanner';
    if (path.startsWith('/document-scanner')) return 'Document Scanner';
    if (path.startsWith('/history')) return 'Scan History';
    if (path.startsWith('/activity') || path.startsWith('/alerts')) return 'Scan History';
    if (path.startsWith('/settings')) return 'Settings';
    return 'Personal Security Hub';
  };

  const isEmailPage = pathname.startsWith('/emails');

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-[#E5E5E5] dark:border-zinc-800 bg-[#FFFFFF]/90 dark:bg-zinc-950/90 px-4 backdrop-blur-md lg:px-6">
      <div className="flex items-center gap-3">
        {/* Mobile menu hamburger */}
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          aria-label="Toggle navigation menu"
          className="rounded-lg border border-[#E5E5E5] dark:border-zinc-800 p-1.5 text-[#737373] hover:bg-[#FAFAFA] dark:hover:bg-zinc-900 hover:text-[#111111] dark:hover:text-[#FFFFFF] lg:hidden"
        >
          <Menu className="h-4 w-4" />
        </button>

        {/* Page title breadcrumb */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs text-[#737373]">
            <span className="font-semibold text-[#111111] dark:text-[#FFFFFF]">Cyclops</span>
            <span>/</span>
            <span className="font-medium text-[#111111] dark:text-zinc-200">{getPageTitle(pathname)}</span>
          </div>
        </div>
      </div>

      {/* Center/Right Actions */}
      <div className="flex items-center gap-2.5">
        {/* Theme Toggle for mobile or top nav */}
        <div className="lg:hidden">
          <ThemeToggle size="sm" />
        </div>

        {/* Rescan Button for Email Security */}
        {isEmailPage && (
          <button
            onClick={triggerRescan}
            className="flex items-center gap-1.5 rounded-lg border border-[#E5E5E5] dark:border-zinc-700 bg-[#111111] text-[#FFFFFF] dark:bg-zinc-800 dark:text-zinc-100 hover:bg-zinc-800 dark:hover:bg-zinc-700 px-3 py-1.5 text-xs font-semibold transition-colors shadow-xs cursor-pointer"
          >
            <Zap className="h-3.5 w-3.5 text-amber-400" />
            <span>Rescan Email</span>
          </button>
        )}

        {/* Global Search / Command Bar Trigger */}
        <button
          onClick={() => setIsQuickScanOpen(true)}
          className="hidden md:flex items-center gap-2.5 rounded-lg border border-[#E5E5E5] dark:border-zinc-800 bg-[#FAFAFA] dark:bg-zinc-900/60 px-3 py-1.5 text-xs text-[#737373] hover:border-[#111111] dark:hover:border-zinc-600 hover:text-[#111111] dark:hover:text-[#FFFFFF] transition-colors w-40 lg:w-56 cursor-pointer"
        >
          <Search className="h-3.5 w-3.5 text-[#737373]" />
          <span className="flex-1 text-left truncate">Check a link or file...</span>
          <kbd className="rounded border border-[#E5E5E5] dark:border-zinc-700 bg-white dark:bg-zinc-800 px-1.5 text-[10px] text-[#737373] font-mono">
            ⌘K
          </kbd>
        </button>

        {/* Quick Action Button */}
        {!isEmailPage && (
          <button
            onClick={() => setIsQuickScanOpen(true)}
            className="flex items-center gap-1.5 rounded-lg bg-[#111111] text-[#FFFFFF] dark:bg-[#FFFFFF] dark:text-[#111111] hover:bg-zinc-800 dark:hover:bg-zinc-200 px-3 py-1.5 text-xs font-semibold transition-colors cursor-pointer"
          >
            <Zap className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">Quick Check</span>
          </button>
        )}

        {/* Visible Sign Out Button */}
        {user && (
          <button
            onClick={() => signOut()}
            aria-label="Sign Out"
            className="flex items-center gap-1.5 rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50/60 dark:bg-red-950/20 text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/40 px-2.5 py-1.5 text-xs font-semibold transition-colors cursor-pointer shadow-2xs"
          >
            <LogOut className="h-3.5 w-3.5 shrink-0" />
            <span className="hidden sm:inline">Sign Out</span>
          </button>
        )}
      </div>
    </header>
  );
};
