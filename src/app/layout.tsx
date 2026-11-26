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
                  var valid = ['light', 'soft-light', 'soft-dark', 'dark'];
                  var theme = (saved && valid.indexOf(saved) !== -1) ? saved : null;
                  if (!theme) {
                    var supportDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                    theme = supportDark ? 'dark' : 'light';
                  }
                  var root = document.documentElement;
                  root.setAttribute('data-theme', theme);
                  root.classList.remove('theme-light', 'theme-soft-light', 'theme-soft-dark', 'theme-dark');
                  root.classList.add('theme-' + theme);
                  if (theme === 'dark' || theme === 'soft-dark') {
                    root.classList.add('dark');
                    root.style.colorScheme = 'dark';
                  } else {
                    root.classList.remove('dark');
                    root.style.colorScheme = 'light';
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
