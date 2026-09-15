'use client';

import React from 'react';
import { usePathname } from 'next/navigation';
import { useDemoContext } from '../../context/DemoContext';
import { Menu, Search, Shield, Zap } from 'lucide-react';

interface TopNavProps {
  mobileOpen: boolean;
  setMobileOpen: (open: boolean) => void;
}

export const TopNav: React.FC<TopNavProps> = ({ mobileOpen, setMobileOpen }) => {
  const pathname = usePathname();
  const { setIsQuickScanOpen } = useDemoContext();

  const getPageTitle = (path: string) => {
    if (path.startsWith('/emails')) return 'Email Security';
    if (path.startsWith('/url-scanner')) return 'URL & Domain Scanner';
    if (path.startsWith('/document-scanner')) return 'Document Security';
    if (path.startsWith('/activity')) return 'Activity Audit Trail';
    if (path.startsWith('/alerts')) return 'Security Alerts Center';
    if (path.startsWith('/settings')) return 'Workspace Settings';
    return 'Security Overview';
  };

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-zinc-800 bg-zinc-950/80 px-4 backdrop-blur-md lg:px-6">
      <div className="flex items-center gap-3">
        {/* Mobile menu hamburger */}
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          className="rounded-lg border border-zinc-800 p-1.5 text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100 lg:hidden"
        >
          <Menu className="h-4 w-4" />
        </button>

        {/* Page title breadcrumb */}
        <div>
          <div className="flex items-center gap-1.5 text-xs text-zinc-400">
            <span>SentinelAI</span>
            <span>/</span>
            <span className="font-medium text-zinc-200">{getPageTitle(pathname)}</span>
          </div>
        </div>
      </div>

      {/* Center/Right Actions */}
      <div className="flex items-center gap-3">
        {/* Global Search / Command Bar Trigger */}
        <button
          onClick={() => setIsQuickScanOpen(true)}
          className="hidden sm:flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-1.5 text-xs text-zinc-400 hover:border-zinc-700 hover:text-zinc-200 transition-colors w-48 md:w-64"
        >
          <Search className="h-3.5 w-3.5 text-zinc-500" />
          <span className="flex-1 text-left truncate">Scan URL or Document...</span>
          <kbd className="rounded border border-zinc-700 bg-zinc-800 px-1.5 text-[10px] text-zinc-400 font-mono">
            ⌘K
          </kbd>
        </button>

        {/* System Status Pill */}
        <div className="hidden md:flex items-center gap-1.5 rounded-full border border-emerald-900/50 bg-emerald-950/30 px-2.5 py-1 text-[11px] font-medium text-emerald-400">
          <Shield className="h-3 w-3" />
          Systems Operational
        </div>

        {/* Quick Action Button */}
        <button
          onClick={() => setIsQuickScanOpen(true)}
          className="flex items-center gap-1.5 rounded-lg bg-zinc-100 px-3 py-1.5 text-xs font-semibold text-zinc-900 hover:bg-white transition-colors"
        >
          <Zap className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">Quick Scan</span>
        </button>
      </div>
    </header>
  );
};
