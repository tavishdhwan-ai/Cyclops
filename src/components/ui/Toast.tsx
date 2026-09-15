'use client';

import React from 'react';
import { useDemoContext } from '../../context/DemoContext';
import { CheckCircle2, AlertTriangle, Info, AlertCircle } from 'lucide-react';

export const Toast: React.FC = () => {
  const { toast } = useDemoContext();

  if (!toast) return null;

  const iconMap = {
    success: <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />,
    warning: <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />,
    error: <AlertCircle className="h-4 w-4 text-red-400 shrink-0" />,
    info: <Info className="h-4 w-4 text-zinc-400 shrink-0" />,
  };

  return (
    <div className="fixed bottom-5 right-5 z-50 flex items-start gap-3 rounded-lg border border-zinc-800 bg-zinc-900/95 px-4 py-3 shadow-xl backdrop-blur-md transition-all duration-200 max-w-sm">
      {iconMap[toast.type]}
      <div className="text-xs">
        <p className="font-semibold text-zinc-100">{toast.title}</p>
        {toast.description && <p className="mt-0.5 text-zinc-400">{toast.description}</p>}
      </div>
    </div>
  );
};
