import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import './globals.css';
import { ThemeProvider } from '../context/ThemeContext';
import { AuthProvider } from '../context/AuthContext';
import { DemoProvider } from '../context/DemoContext';
import { AppShell } from '../components/layout/AppShell';

const geistSans = Geist({
  variable: '--font-geist-sans',
  subsets: ['latin'],
});

const geistMono = Geist_Mono({
  variable: '--font-geist-mono',
  subsets: ['latin'],
});

export const metadata: Metadata = {
  title: 'Cyclops | Personal Online Safety & Security Assistant',
  description: 'Your online safety, in one place. Check links, inspect suspicious emails, and scan documents for hidden threats.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} antialiased`} suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                try {
                  var saved = localStorage.getItem('cyclops_theme') || localStorage.getItem('sentinel_theme');
                  var supportDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                  if (saved === 'dark' || (!saved && supportDark)) {
                    document.documentElement.classList.add('dark');
                  } else {
                    document.documentElement.classList.remove('dark');
                  }
                } catch (e) {}
              })();
            `,
          }}
        />
      </head>
      <body className="bg-zinc-50 dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 min-h-screen">
        <ThemeProvider>
          <AuthProvider>
            <DemoProvider>
              <AppShell>{children}</AppShell>
            </DemoProvider>
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
