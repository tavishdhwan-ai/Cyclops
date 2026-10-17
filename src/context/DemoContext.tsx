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
  DocEmbeddedLinkItem,
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

import { Theme, useTheme } from './ThemeContext';
export type { Theme };

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
  scanDocument: (fileName: string, fileSize?: string, rawFile?: File) => Promise<DocumentScanResult>;
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
  const { theme, toggleTheme, setTheme } = useTheme();

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
    const trimmed = rawUrl.trim();
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

    try {
      const response = await fetch(`${apiUrl}/scan-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `Backend scan failed (HTTP ${response.status})`);
      }

      const data = await response.json();

      // Map backend AggregatedUrlReport into frontend UrlScanResult
      let mappedRiskLevel: RiskLevel = 'safe';
      if (data.risk_level === 'CRITICAL') mappedRiskLevel = 'critical';
      else if (data.risk_level === 'HIGH' || data.risk_level === 'MEDIUM') mappedRiskLevel = 'warning';
      else if (data.risk_level === 'LOW') mappedRiskLevel = 'safe';
      else mappedRiskLevel = 'neutral';

      let mappedVerdict: UrlScanResult['verdict'] = 'safe';
      if (data.verdict === 'malicious') mappedVerdict = 'malicious';
      else if (data.verdict === 'phishing') mappedVerdict = 'phishing';
      else if (data.verdict === 'suspicious') mappedVerdict = 'suspicious';
      else mappedVerdict = 'safe';

      const signalsList: string[] = (data.signals || []).map((s: { title: string; description: string }) => `${s.title}: ${s.description}`);
      if (signalsList.length === 0 && data.risk_factors && data.risk_factors.length > 0) {
        signalsList.push(...data.risk_factors);
      }

      const domainName = data.normalization?.ascii_hostname || trimmed.replace(/^https?:\/\//, '').split('/')[0];
      const primaryIp = data.hosting_intelligence?.ip_address || (data.dns_intelligence?.resolved_ips && data.dns_intelligence.resolved_ips[0]) || 'Unresolved';
      const geoLoc = data.hosting_intelligence?.country
        ? `${data.hosting_intelligence.city ? data.hosting_intelligence.city + ', ' : ''}${data.hosting_intelligence.country}`
        : 'Unknown Location';

      const liveResult: UrlScanResult = {
        id: data.id || `url-${Date.now()}`,
        url: data.sanitized_display_url || data.normalized_url || trimmed,
        timestamp: 'Just now',
        verdict: mappedVerdict,
        riskLevel: mappedRiskLevel,
        riskScore: Math.round((data.threat_score || 0) * 10), // convert 0-10 to 0-100 scale for UI progress
        threat_score: data.threat_score,
        summary: data.summary,
        plain_english_explanation: data.plain_english_explanation,
        domainInfo: {
          domain: domainName,
          registrar: data.domain_registration?.registrar || 'Unknown / Private',
          registeredDaysAgo: data.domain_registration?.domain_age_days ?? -1,
          ipAddress: primaryIp,
          location: geoLoc,
          sslValid: data.normalization?.scheme === 'https',
          sslIssuer: data.normalization?.scheme === 'https' ? 'TLS Encrypted' : 'None (HTTP)',
        },
        suspiciousSignals: signalsList,
        recommendedAction: data.recommended_action || 'Review security observations before proceeding.',
        reassuring_factors: data.reassuring_factors || [],
        risk_factors: data.risk_factors || [],
        missing_data_notes: data.missing_data_notes || [],
        signals: data.signals || [],
        normalization: data.normalization,
        redirect_analysis: data.redirect_analysis,
        dns_intelligence: data.dns_intelligence,
        hosting_intelligence: data.hosting_intelligence,
        domain_registration: data.domain_registration,
        page_content: data.page_content,
        reputation_providers: data.reputation_providers || [],
        ssl_certificate: data.ssl_certificate,
        sensitive_input_audit: data.sensitive_input_audit,
        download_safety: data.download_safety,
        hosting_footprint: data.hosting_footprint || data.hosting_intelligence,
        security_authority_checklist: data.security_authority_checklist,
        isLiveScan: true,
      };

      setUrlScans((prev) => [liveResult, ...prev]);
      setStats((prev) => ({ ...prev, urlsScanned: prev.urlsScanned + 1 }));

      const newActivity: ActivityEvent = {
        id: `act-${Date.now()}`,
        employeeName: 'Security Analyst',
        employeeEmail: 'analyst@cyclops.internal',
        employeeAvatar: 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=100&auto=format&fit=crop&q=80',
        role: 'AppSec Team',
        eventType: 'url_check',
        title: `URL Scanned: ${domainName}`,
        description: `Backend scan completed: ${data.risk_level} (${data.verdict.toUpperCase()})`,
        severity: mappedRiskLevel,
        timestamp: 'Just now',
        ipAddress: primaryIp,
        device: 'Cyclops Web Engine',
      };
      setActivities((prev) => [newActivity, ...prev]);

      return liveResult;
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : 'Unknown scan error';
      showToast('Scan Error', errMsg, 'error');
      throw err;
    }
  };

  const scanDocument = async (fileName: string, fileSize: string = '1.2 MB', rawFile?: File): Promise<DocumentScanResult> => {
    try {
      let data: (Partial<DocumentScanResult> & {
        file_name?: string;
        file_size_formatted?: string;
        file_type?: string;
        sha256_hash?: string;
        risk_score?: number;
        detected_signals?: string[];
        executive_summary?: string;
        recommended_action?: string;
        risk_level?: RiskLevel;
      }) | null = null;

      if (rawFile) {
        const formData = new FormData();
        formData.append('file', rawFile);
        const res = await fetch('http://127.0.0.1:8000/scan-document', {
          method: 'POST',
          body: formData,
        });
        if (res.ok) {
          data = await res.json();
        }
      } else {
        const res = await fetch('http://127.0.0.1:8000/scan-document-json', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ file_name: fileName, preset: fileName }),
        });
        if (res.ok) {
          data = await res.json();
        }
      }

      if (data) {
        const liveDoc: DocumentScanResult = {
          id: data.id || `doc-${Date.now()}`,
          fileName: data.file_name || fileName,
          fileSize: data.file_size_formatted || fileSize,
          fileType: data.file_type || 'Document',
          fileHash: data.sha256_hash || '',
          timestamp: 'Just now',
          riskLevel: data.risk_level || 'safe',
          verdict: data.verdict || 'clean',
          riskScore: data.risk_score,
          detectedSignals: data.detected_signals || [],
          macroDetected: data.macro_inspection?.macro_detected ?? false,
          externalConnections: data.embedded_links?.links?.map((l: DocEmbeddedLinkItem) => l.destination_url) || [],
          aiSummary: data.executive_summary || '',
          recommendedAction: data.recommended_action || '',
          macro_inspection: data.macro_inspection,
          html_safety: data.html_safety,
          embedded_links: data.embedded_links,
          exploit_indicators: data.exploit_indicators,
          forms_and_submission: data.forms_and_submission,
          safe_view: data.safe_view,
          brand_domain_consistency: data.brand_domain_consistency,
          script_translator: data.script_translator,
          hidden_content: data.hidden_content,
          checks_summary: data.checks_summary,
        };

        setDocScans((prev) => [liveDoc, ...prev]);
        setStats((prev) => ({ ...prev, documentsChecked: prev.documentsChecked + 1 }));

        const newActivity: ActivityEvent = {
          id: `act-${Date.now()}`,
          employeeName: 'Alex Vance (Admin)',
          employeeEmail: 'alex.v@acmecorp.com',
          employeeAvatar: 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=100&auto=format&fit=crop&q=80',
          role: 'IT Security Admin',
          eventType: 'document_analysis',
          title: `Document Analyzed: ${fileName}`,
          description: `Live scan completed: ${liveDoc.verdict.toUpperCase()}`,
          severity: liveDoc.riskLevel,
          timestamp: 'Just now',
          ipAddress: '192.168.1.50',
          device: 'MacBook Air (macOS 14.2)',
        };
        setActivities((prev) => [newActivity, ...prev]);
        return liveDoc;
      }
    } catch {
      // Fallback to local mock below if backend unreachable
    }

    // Check if preset matches any mockDocumentScans
    const existingMatch = mockDocumentScans.find((d) => d.fileName.toLowerCase() === fileName.toLowerCase());
    if (existingMatch) {
      const cloned: DocumentScanResult = {
        ...existingMatch,
        id: `doc-${Date.now()}`,
        timestamp: 'Just now',
      };
      setDocScans((prev) => [cloned, ...prev]);
      setStats((prev) => ({ ...prev, documentsChecked: prev.documentsChecked + 1 }));
      return cloned;
    }

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
