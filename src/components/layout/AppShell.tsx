'use client';

import React, { useState } from 'react';
import { Sidebar } from './Sidebar';
import { TopNav } from './TopNav';
import { QuickScanModal } from '../QuickScanModal';
import { Toast } from '../ui/Toast';

export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 antialiased flex transition-colors duration-200">
      {/* Sidebar */}
      <Sidebar mobileOpen={mobileOpen} setMobileOpen={setMobileOpen} />

      {/* Main Content Area */}
      <div className="flex-1 lg:pl-64 flex flex-col min-w-0">
        <TopNav mobileOpen={mobileOpen} setMobileOpen={setMobileOpen} />
        <main className="flex-1 p-4 md:p-6 lg:p-8 max-w-7xl w-full mx-auto">
          {children}
        </main>
      </div>

      {/* Global Modals & Notifications */}
      <QuickScanModal />
      <Toast />
    </div>
  );
};
