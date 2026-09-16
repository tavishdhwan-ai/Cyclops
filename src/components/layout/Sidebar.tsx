'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useDemoContext } from '../../context/DemoContext';
import {
  ShieldCheck,
  LayoutDashboard,
  Mail,
  Globe,
  FileSearch,
  Activity,
  AlertTriangle,
  Settings,
  ChevronDown,
  Building2,
  Check,
  Zap,
} from 'lucide-react';

import { ThemeToggle } from '../ui/ThemeToggle';

interface SidebarProps {
  mobileOpen?: boolean;
  setMobileOpen?: (open: boolean) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ mobileOpen, setMobileOpen }) => {
  const pathname = usePathname();
  const { alerts, workspaces, activeWorkspace, setActiveWorkspaceById } = useDemoContext();
  const [workspaceMenuOpen, setWorkspaceMenuOpen] = useState(false);

  const activeAlertsCount = alerts.filter((a) => a.status === 'active').length;

  const navItems = [
    { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
    { name: 'Email Security', href: '/emails', icon: Mail },
    { name: 'URL Scanner', href: '/url-scanner', icon: Globe },
    { name: 'Document Scanner', href: '/document-scanner', icon: FileSearch },
    { name: 'Activity Log', href: '/activity', icon: Activity },
    { name: 'Security Alerts', href: '/alerts', icon: AlertTriangle, badge: activeAlertsCount },
    { name: 'Settings', href: '/settings', icon: Settings },
  ];

  const handleLinkClick = () => {
    if (setMobileOpen) setMobileOpen(false);
  };

  return (
    <aside
      className={`fixed top-0 bottom-0 left-0 z-40 flex w-64 flex-col border-r border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 p-4 transition-transform duration-200 lg:translate-x-0 ${
        mobileOpen ? 'translate-x-0' : '-translate-x-full'
      }`}
    >
      {/* SentinelAI Brand Branding & Theme Toggle */}
      <div className="flex items-center justify-between px-1 py-1 mb-4 border-b border-zinc-200 dark:border-zinc-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-zinc-300 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-900 text-zinc-900 dark:text-zinc-100 shadow-xs">
            <ShieldCheck className="h-4 w-4 text-zinc-900 dark:text-zinc-100" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-bold tracking-tight text-zinc-900 dark:text-zinc-100">SentinelAI</span>
              <span className="rounded bg-zinc-200 dark:bg-zinc-800 px-1 py-0.5 text-[9px] font-semibold text-zinc-700 dark:text-zinc-300">
                v1.2
              </span>
            </div>
            <p className="text-[10px] text-zinc-500 dark:text-zinc-400">SMB Cyber Employee</p>
          </div>
        </div>

        {/* Global Theme Toggle Button */}
        <ThemeToggle size="sm" />
      </div>

      {/* Workspace Switcher */}
      <div className="relative mb-6">
        <button
          onClick={() => setWorkspaceMenuOpen(!workspaceMenuOpen)}
          className="flex w-full items-center justify-between rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/60 px-3 py-2 text-left hover:border-zinc-300 dark:hover:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-900 transition-colors"
        >
          <div className="flex items-center gap-2.5 min-w-0">
            <Building2 className="h-4 w-4 text-zinc-500 dark:text-zinc-400 shrink-0" />
            <div className="truncate">
              <p className="truncate text-xs font-semibold text-zinc-900 dark:text-zinc-200">{activeWorkspace.name}</p>
              <p className="text-[10px] text-zinc-500 dark:text-zinc-400">{activeWorkspace.tier}</p>
            </div>
          </div>
          <ChevronDown className="h-3.5 w-3.5 text-zinc-500 dark:text-zinc-400 shrink-0" />
        </button>

        {/* Dropdown menu */}
        {workspaceMenuOpen && (
          <div className="absolute top-full left-0 right-0 z-50 mt-1 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-1 shadow-xl">
            <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
              Workspaces
            </div>
            {workspaces.map((ws) => (
              <button
                key={ws.id}
                onClick={() => {
                  setActiveWorkspaceById(ws.id);
                  setWorkspaceMenuOpen(false);
                }}
                className="flex w-full items-center justify-between rounded-md px-2 py-1.5 text-xs text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
              >
                <div className="text-left">
                  <p className="font-medium text-zinc-900 dark:text-zinc-200">{ws.name}</p>
                  <p className="text-[10px] text-zinc-500 dark:text-zinc-400">{ws.tier}</p>
                </div>
                {activeWorkspace.id === ws.id && <Check className="h-3.5 w-3.5 text-zinc-900 dark:text-zinc-300" />}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Navigation items */}
      <nav className="flex-1 space-y-1">
        {navItems.map((item) => {
          const isActive = pathname === item.href || (item.href !== '/dashboard' && pathname.startsWith(item.href));
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              onClick={handleLinkClick}
              className={`group flex items-center justify-between rounded-lg px-3 py-2 text-xs font-medium transition-all ${
                isActive
                  ? 'bg-zinc-200 text-zinc-900 dark:bg-zinc-800 dark:text-zinc-100 shadow-xs border border-zinc-300 dark:border-zinc-700/60 font-semibold'
                  : 'text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-900/80 hover:text-zinc-900 dark:hover:text-zinc-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`h-4 w-4 transition-colors ${isActive ? 'text-zinc-900 dark:text-zinc-100' : 'text-zinc-500 dark:text-zinc-400 group-hover:text-zinc-900 dark:group-hover:text-zinc-300'}`} />
                <span>{item.name}</span>
              </div>
              {item.badge !== undefined && item.badge > 0 && (
                <span
                  className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                    isActive ? 'bg-red-100 dark:bg-red-950/80 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800/60' : 'bg-red-50 dark:bg-red-950/50 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-900/50'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* System Status Banner */}
      <div className="mt-auto rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/40 p-3 mb-4">
        <div className="flex items-center gap-2 text-xs font-medium text-emerald-600 dark:text-emerald-400">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          AI Guard Active
        </div>
        <p className="mt-1 text-[11px] text-zinc-500 dark:text-zinc-400 leading-tight">
          Monitoring emails, links, and documents across {activeWorkspace.employees} endpoints.
        </p>
      </div>

      {/* User Placeholder */}
      <div className="flex items-center justify-between border-t border-zinc-200 dark:border-zinc-800/80 pt-3 px-1">
        <div className="flex items-center gap-2.5">
          <div className="h-8 w-8 rounded-full border border-zinc-300 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-800 overflow-hidden flex items-center justify-center">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src="https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=100&auto=format&fit=crop&q=80"
              alt="Alex Vance"
              className="h-full w-full object-cover"
            />
          </div>
          <div>
            <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-200 leading-tight">Alex Vance</p>
            <p className="text-[10px] text-zinc-500 dark:text-zinc-400">Security Admin</p>
          </div>
        </div>
        <button
          onClick={() => {}}
          title="Demo Mode"
          className="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"
        >
          <Zap className="h-3.5 w-3.5" />
        </button>
      </div>
    </aside>
  );
};
