'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  ShieldCheck,
  Home,
  Mail,
  Globe,
  FileSearch,
  History,
  Settings,
  LogIn,
  LogOut,
} from 'lucide-react';
import { ThemeToggle } from '../ui/ThemeToggle';
import { useAuth } from '../../context/AuthContext';

interface SidebarProps {
  mobileOpen?: boolean;
  setMobileOpen?: (open: boolean) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ mobileOpen, setMobileOpen }) => {
  const pathname = usePathname();
  const { user, profile, signOut } = useAuth();

  const navItems = [
    { name: 'Home', href: '/', icon: Home },
    { name: 'Link Scanner', href: '/url-scanner', icon: Globe },
    { name: 'Email Scanner', href: '/emails', icon: Mail },
    { name: 'Document Scanner', href: '/document-scanner', icon: FileSearch },
    { name: 'Scan History', href: '/history', icon: History },
    { name: 'Settings', href: '/settings', icon: Settings },
  ];

  const handleLinkClick = () => {
    if (setMobileOpen) setMobileOpen(false);
  };

  return (
    <aside
      className={`fixed top-0 bottom-0 left-0 z-40 flex w-64 flex-col border-r border-[#E5E5E5] dark:border-zinc-800 bg-[#FFFFFF] dark:bg-zinc-950 p-4 transition-transform duration-200 lg:translate-x-0 ${
        mobileOpen ? 'translate-x-0' : '-translate-x-full'
      }`}
    >
      {/* Cyclops Branding & Theme Toggle */}
      <div className="flex items-center justify-between px-1 py-1 mb-6 border-b border-[#E5E5E5] dark:border-zinc-800/80 pb-3">
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#E5E5E5] dark:border-zinc-700 bg-[#FAFAFA] dark:bg-zinc-900 text-[#111111] dark:text-[#FFFFFF] shadow-xs group-hover:border-[#111111] dark:group-hover:border-zinc-500 transition-colors">
            <ShieldCheck className="h-4 w-4 text-[#111111] dark:text-[#FFFFFF]" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="text-sm font-bold tracking-tight text-[#111111] dark:text-[#FFFFFF]">Cyclops</span>
            </div>
            <p className="text-[10px] text-[#737373] dark:text-zinc-400">Personal Online Safety</p>
          </div>
        </Link>

        {/* Global Theme Toggle Button */}
        <ThemeToggle size="sm" />
      </div>

      {/* Navigation items */}
      <nav className="flex-1 space-y-1">
        {navItems.map((item) => {
          const isActive =
            item.href === '/'
              ? pathname === '/' || pathname === '/dashboard'
              : pathname.startsWith(item.href);
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              onClick={handleLinkClick}
              className={`group flex items-center justify-between rounded-lg px-3 py-2 text-xs font-medium transition-all ${
                isActive
                  ? 'bg-zinc-100 text-[#111111] dark:bg-zinc-800 dark:text-[#FFFFFF] border border-[#E5E5E5] dark:border-zinc-700/60 font-semibold shadow-xs'
                  : 'text-[#737373] dark:text-zinc-400 hover:bg-[#FAFAFA] dark:hover:bg-zinc-900/80 hover:text-[#111111] dark:hover:text-zinc-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon
                  className={`h-4 w-4 transition-colors ${
                    isActive
                      ? 'text-[#111111] dark:text-[#FFFFFF]'
                      : 'text-[#737373] dark:text-zinc-400 group-hover:text-[#111111] dark:group-hover:text-zinc-300'
                  }`}
                />
                <span>{item.name}</span>
              </div>
            </Link>
          );
        })}
      </nav>

      {/* Security Status Card */}
      <div className="mt-auto rounded-lg border border-[#E5E5E5] dark:border-zinc-800 bg-[#FAFAFA] dark:bg-zinc-900/40 p-3 mb-4">
        <div className="flex items-center gap-2 text-xs font-medium text-emerald-600 dark:text-emerald-400">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          Protection Active
        </div>
        <p className="mt-1 text-[11px] text-[#737373] dark:text-zinc-400 leading-tight">
          Passive link checks, email analysis, and static document inspection.
        </p>
      </div>

      {/* User / Session Area */}
      <div className="border-t border-[#E5E5E5] dark:border-zinc-800/80 pt-3 px-1">
        {user ? (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Link
                href="/settings"
                onClick={handleLinkClick}
                className="flex items-center gap-2.5 min-w-0 hover:opacity-80 transition-opacity flex-1"
              >
                <div className="h-8 w-8 rounded-full border border-[#E5E5E5] dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800 flex items-center justify-center text-[#111111] dark:text-[#FFFFFF] shrink-0 font-bold text-xs">
                  {profile.displayName
                    ? profile.displayName.charAt(0).toUpperCase()
                    : user.email.charAt(0).toUpperCase()}
                </div>
                <div className="truncate min-w-0">
                  <p className="text-xs font-semibold text-[#111111] dark:text-zinc-200 leading-tight truncate">
                    {profile.displayName || user.displayName || user.email.split('@')[0]}
                  </p>
                  <p className="text-[10px] text-[#737373] dark:text-zinc-400 truncate">{user.email}</p>
                </div>
              </Link>
              <Link
                href="/settings"
                onClick={handleLinkClick}
                title="Account Settings"
                className="text-[#737373] hover:text-[#111111] dark:text-zinc-400 dark:hover:text-zinc-200 p-1"
              >
                <Settings className="h-3.5 w-3.5" />
              </Link>
            </div>

            {/* Obvious, Accessible Sign Out Button */}
            <button
              type="button"
              onClick={async () => {
                if (setMobileOpen) setMobileOpen(false);
                await signOut();
              }}
              aria-label="Sign out of Sentinel AI"
              className="w-full flex items-center justify-center gap-2 rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50/60 dark:bg-red-950/20 py-2 px-3 text-xs font-semibold text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/40 transition-colors cursor-pointer shadow-2xs"
            >
              <LogOut className="h-3.5 w-3.5 shrink-0" />
              <span>Sign Out</span>
            </button>
          </div>
        ) : (
          <Link
            href="/login"
            onClick={handleLinkClick}
            className="w-full flex items-center justify-between gap-2 rounded-lg border border-[#E5E5E5] dark:border-zinc-800 bg-[#FAFAFA] dark:bg-zinc-900/60 p-2 text-xs font-semibold text-zinc-800 dark:text-zinc-200 hover:border-zinc-400 dark:hover:border-zinc-600 transition-colors"
          >
            <div className="flex items-center gap-2">
              <LogIn className="h-3.5 w-3.5 text-zinc-500" />
              <span>Sign In</span>
            </div>
            <span className="text-[10px] font-normal text-zinc-400">2FA Login</span>
          </Link>
        )}
      </div>
    </aside>
  );
};
