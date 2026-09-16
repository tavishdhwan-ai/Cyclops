'use client';

import React, { createContext, useContext, useState } from 'react';
import {
  SecurityStats,
  SecurityEmail,
  UrlScanResult,
  DocumentScanResult,
  ActivityEvent,
  SecurityAlert,
  WorkspaceSettings,
  RiskLevel,
} from '../types';
import {
  mockStats,
  mockEmails,
  mockUrlScans,
  mockDocumentScans,
  mockActivities,
  mockAlerts,
  defaultSettings,
  mockWorkspaces,
} from '../data/mockData';

interface ToastMessage {
  id: string;
  type: 'success' | 'info' | 'warning' | 'error';
  title: string;
  description?: string;
}

export type Theme = 'light' | 'dark';

interface DemoContextType {
  stats: SecurityStats;
  emails: SecurityEmail[];
  urlScans: UrlScanResult[];
  docScans: DocumentScanResult[];
  activities: ActivityEvent[];
  alerts: SecurityAlert[];
  settings: WorkspaceSettings;
  workspaces: typeof mockWorkspaces;
  activeWorkspace: typeof mockWorkspaces[0];
  toast: ToastMessage | null;
  isQuickScanOpen: boolean;
  rescanKey: number;
  emailReviewStatus: 'pending' | 'reviewed';
  theme: Theme;
  toggleTheme: () => void;
  setTheme: (theme: Theme) => void;
  triggerRescan: () => void;
  setEmailReviewStatus: (status: 'pending' | 'reviewed') => void;
  setIsQuickScanOpen: (open: boolean) => void;
  showToast: (title: string, description?: string, type?: ToastMessage['type']) => void;
  quarantineEmail: (id: string) => void;
  markEmailSafe: (id: string) => void;
  reportEmailPhishing: (id: string) => void;
  scanUrl: (url: string) => Promise<UrlScanResult>;
  scanDocument: (fileName: string, fileSize?: string) => Promise<DocumentScanResult>;
  markAlertReviewed: (id: string) => void;
  resolveAlert: (id: string) => void;
  updateSettings: (newSettings: Partial<WorkspaceSettings>) => void;
  setActiveWorkspaceById: (id: string) => void;
}

const DemoContext = createContext<DemoContextType | undefined>(undefined);

export const DemoProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [stats, setStats] = useState<SecurityStats>(mockStats);
  const [emails, setEmails] = useState<SecurityEmail[]>(mockEmails);
  const [urlScans, setUrlScans] = useState<UrlScanResult[]>(mockUrlScans);
  const [docScans, setDocScans] = useState<DocumentScanResult[]>(mockDocumentScans);
  const [activities, setActivities] = useState<ActivityEvent[]>(mockActivities);
  const [alerts, setAlerts] = useState<SecurityAlert[]>(mockAlerts);
  const [settings, setSettings] = useState<WorkspaceSettings>(defaultSettings);
  const [workspaces] = useState(mockWorkspaces);
  const [activeWorkspace, setActiveWorkspace] = useState(mockWorkspaces[0]);
  const [toast, setToast] = useState<ToastMessage | null>(null);
  const [isQuickScanOpen, setIsQuickScanOpen] = useState(false);
  const [rescanKey, setRescanKey] = useState(0);
  const [emailReviewStatus, setEmailReviewStatus] = useState<'pending' | 'reviewed'>('pending');
  const [theme, setThemeState] = useState<Theme>('dark');

  React.useEffect(() => {
    try {
      const saved = localStorage.getItem('sentinel_theme') as Theme | null;
      if (saved === 'light' || saved === 'dark') {
        setThemeState(saved);
        if (saved === 'dark') {
          document.documentElement.classList.add('dark');
        } else {
          document.documentElement.classList.remove('dark');
        }
      } else {
        const isDarkCurrently = document.documentElement.classList.contains('dark');
        setThemeState(isDarkCurrently ? 'dark' : 'light');
      }
    } catch {
      // Fallback
    }
  }, []);

  const setTheme = (newTheme: Theme) => {
    setThemeState(newTheme);
    try {
      localStorage.setItem('sentinel_theme', newTheme);
    } catch {
      // Ignore
    }
    if (newTheme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  };

  const toggleTheme = () => {
    setThemeState((currentTheme) => {
      const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
      try {
        localStorage.setItem('sentinel_theme', nextTheme);
      } catch {
        // Ignore
      }
      if (nextTheme === 'dark') {
        document.documentElement.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
      }
      return nextTheme;
    });
  };

  const triggerRescan = () => {
    setRescanKey((prev) => prev + 1);
  };

  const showToast = (title: string, description?: string, type: ToastMessage['type'] = 'info') => {
    const id = Math.random().toString(36).substring(2, 9);
    setToast({ id, title, description, type });
    setTimeout(() => {
      setToast((current) => (current?.id === id ? null : current));
    }, 4000);
  };

  const quarantineEmail = (id: string) => {
    setEmails((prev) =>
      prev.map((e) => (e.id === id ? { ...e, status: 'quarantined', riskLevel: 'warning' as RiskLevel } : e))
    );
    showToast('Email Quarantined', 'The email has been moved to quarantine and isolated from user inbox.', 'warning');
  };

  const markEmailSafe = (id: string) => {
    setEmails((prev) =>
      prev.map((e) => (e.id === id ? { ...e, status: 'clean', riskLevel: 'safe' as RiskLevel } : e))
    );
    showToast('Email Marked Safe', 'Email status updated to clean.', 'success');
  };

  const reportEmailPhishing = (id: string) => {
    setEmails((prev) =>
      prev.map((e) => (e.id === id ? { ...e, status: 'quarantined', riskLevel: 'critical' as RiskLevel } : e))
    );
    showToast('Phishing Reported', 'Threat indicators submitted and domain added to workspace blocklist.', 'error');
  };

  const scanUrl = async (rawUrl: string): Promise<UrlScanResult> => {
    let cleanUrl = rawUrl.trim();
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      cleanUrl = 'https://' + cleanUrl;
    }

    let domainName = cleanUrl.replace(/^https?:\/\//, '').split('/')[0];
    const isPhishingDemo = cleanUrl.includes('login') || cleanUrl.includes('verify') || cleanUrl.includes('fix') || cleanUrl.includes('update');
    const isMaliciousDemo = cleanUrl.includes('malware') || cleanUrl.includes('exe') || cleanUrl.includes('bin') || cleanUrl.includes('.ru');

    let verdict: UrlScanResult['verdict'] = 'safe';
    let riskLevel: RiskLevel = 'safe';
    let riskScore = Math.floor(Math.random() * 10) + 2;
    let suspiciousSignals: string[] = [];
    let recommendedAction = 'No malicious indicators detected. Safe to proceed.';

    if (isMaliciousDemo) {
      verdict = 'malicious';
      riskLevel = 'critical';
      riskScore = 96;
      suspiciousSignals = [
        'Direct executable payload detected on path',
        'Flagged by SentinelAI Threat Intelligence database',
        'Hostname resolves to known C2 server IP',
        'No valid TLS certificate found',
      ];
      recommendedAction = 'Block domain network traffic and notify security admin immediately.';
    } else if (isPhishingDemo) {
      verdict = 'phishing';
      riskLevel = 'critical';
      riskScore = 91;
      suspiciousSignals = [
        `Typosquatted domain mimicking official service`,
        'Domain registered recently (< 7 days ago)',
        'Cloned authentication form structure detected',
        'Mismatch between domain registrant and SSL certificate holder',
      ];
      recommendedAction = 'Block URL access across workspace browsers and alert targeted users.';
    }

    const newScan: UrlScanResult = {
      id: `url-${Date.now()}`,
      url: cleanUrl,
      timestamp: 'Just now',
      verdict,
      riskLevel,
      riskScore,
      domainInfo: {
        domain: domainName,
        registrar: isPhishingDemo ? 'NameCheap Inc.' : 'MarkMonitor Inc.',
        registeredDaysAgo: isPhishingDemo ? 4 : 3420,
        ipAddress: isPhishingDemo ? '198.54.117.210' : '104.16.123.96',
        location: isPhishingDemo ? 'Frankfurt, Germany' : 'San Francisco, US',
        sslValid: true,
        sslIssuer: isPhishingDemo ? "Let's Encrypt Authority X3" : 'DigiCert TLS RSA SHA256',
      },
      suspiciousSignals,
      recommendedAction,
    };

    setUrlScans((prev) => [newScan, ...prev]);
    setStats((prev) => ({ ...prev, urlsScanned: prev.urlsScanned + 1 }));

    // Add activity event
    const newActivity: ActivityEvent = {
      id: `act-${Date.now()}`,
      employeeName: 'Alex Vance (Admin)',
      employeeEmail: 'alex.v@acmecorp.com',
      employeeAvatar: 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=100&auto=format&fit=crop&q=80',
      role: 'IT Security Admin',
      eventType: 'url_check',
      title: `URL Scanned: ${domainName}`,
      description: `Scan completed with verdict: ${verdict.toUpperCase()}`,
      severity: riskLevel,
      timestamp: 'Just now',
      ipAddress: '192.168.1.50',
      device: 'MacBook Air (macOS 14.2)',
    };
    setActivities((prev) => [newActivity, ...prev]);

    return newScan;
  };

  const scanDocument = async (fileName: string, fileSize: string = '1.2 MB'): Promise<DocumentScanResult> => {
    const isExe = fileName.endsWith('.exe') || fileName.endsWith('.bin') || fileName.includes('.pdf.exe');
    const isMacro = fileName.endsWith('.xlsm') || fileName.endsWith('.docm');

    let verdict: DocumentScanResult['verdict'] = 'clean';
    let riskLevel: RiskLevel = 'safe';
    let detectedSignals: string[] = ['Clean file header', 'No executable code found'];
    let aiSummary = 'Document scan complete. No malicious macros or embedded scripts were detected.';
    let recommendedAction = 'File is safe to download and open.';

    if (isExe) {
      verdict = 'malicious';
      riskLevel = 'critical';
      detectedSignals = [
        'Executable binary file extension',
        'Matched signature Win32.Agent.X payload',
        'Attempts silent persistence registry modification',
      ];
      aiSummary = 'High-risk executable binary payload masquerading as a document file.';
      recommendedAction = 'Do not open file. File has been isolated in browser sandbox.';
    } else if (isMacro) {
      verdict = 'suspicious';
      riskLevel = 'warning';
      detectedSignals = [
        'VBA Macro script auto-execute hook',
        'Encoded PowerShell payload string',
        'External HTTP connection attempt in script code',
      ];
      aiSummary = 'Macro-enabled document containing obfuscated shell script hooks.';
      recommendedAction = 'Open in read-only protected view or strip macros before running.';
    }

    const newDoc: DocumentScanResult = {
      id: `doc-${Date.now()}`,
      fileName,
      fileSize,
      fileType: isExe ? 'Executable (.exe)' : isMacro ? 'Macro Excel (.xlsm)' : 'PDF Document (.pdf)',
      fileHash: Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
      timestamp: 'Just now',
      riskLevel,
      verdict,
      detectedSignals,
      macroDetected: isMacro,
      externalConnections: isMacro ? ['http://external-payload.net/script.ps1'] : [],
      aiSummary,
      recommendedAction,
    };

    setDocScans((prev) => [newDoc, ...prev]);
    setStats((prev) => ({ ...prev, documentsChecked: prev.documentsChecked + 1 }));

    // Add activity event
    const newActivity: ActivityEvent = {
      id: `act-${Date.now()}`,
      employeeName: 'Alex Vance (Admin)',
      employeeEmail: 'alex.v@acmecorp.com',
      employeeAvatar: 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=100&auto=format&fit=crop&q=80',
      role: 'IT Security Admin',
      eventType: 'document_analysis',
      title: `Document Analyzed: ${fileName}`,
      description: `Scan completed with verdict: ${verdict.toUpperCase()}`,
      severity: riskLevel,
      timestamp: 'Just now',
      ipAddress: '192.168.1.50',
      device: 'MacBook Air (macOS 14.2)',
    };
    setActivities((prev) => [newActivity, ...prev]);

    return newDoc;
  };

  const markAlertReviewed = (id: string) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === id ? { ...a, status: 'reviewed' } : a))
    );
    showToast('Alert Reviewed', 'Alert status changed to reviewed.', 'info');
  };

  const resolveAlert = (id: string) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === id ? { ...a, status: 'resolved' } : a))
    );
    setStats((prev) => ({ ...prev, activeAlertsCount: Math.max(0, prev.activeAlertsCount - 1) }));
    showToast('Alert Resolved', 'Threat threat has been marked as resolved.', 'success');
  };

  const updateSettings = (newSettings: Partial<WorkspaceSettings>) => {
    setSettings((prev) => ({ ...prev, ...newSettings }));
    showToast('Settings Saved', 'Workspace security policies have been updated successfully.', 'success');
  };

  const setActiveWorkspaceById = (id: string) => {
    const ws = mockWorkspaces.find((w) => w.id === id);
    if (ws) {
      setActiveWorkspace(ws);
      showToast('Workspace Switched', `Switched active workspace to ${ws.name}`, 'info');
    }
  };

  return (
    <DemoContext.Provider
      value={{
        stats,
        emails,
        urlScans,
        docScans,
        activities,
        alerts,
        settings,
        workspaces,
        activeWorkspace,
        toast,
        isQuickScanOpen,
        rescanKey,
        emailReviewStatus,
        theme,
        toggleTheme,
        setTheme,
        triggerRescan,
        setEmailReviewStatus,
        setIsQuickScanOpen,
        showToast,
        quarantineEmail,
        markEmailSafe,
        reportEmailPhishing,
        scanUrl,
        scanDocument,
        markAlertReviewed,
        resolveAlert,
        updateSettings,
        setActiveWorkspaceById,
      }}
    >
      {children}
    </DemoContext.Provider>
  );
};

export const useDemoContext = () => {
  const context = useContext(DemoContext);
  if (!context) {
    throw new Error('useDemoContext must be used within a DemoProvider');
  }
  return context;
};
