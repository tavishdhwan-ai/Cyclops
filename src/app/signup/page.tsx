'use client';

import React, { Suspense } from 'react';
import { LoginFormContent } from '../login/page';

export default function SignUpPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-[calc(100vh-3.5rem)] flex items-center justify-center">
          <div className="h-6 w-6 border-2 border-zinc-900 dark:border-white border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <LoginFormContent defaultMode="signup" />
    </Suspense>
  );
}
