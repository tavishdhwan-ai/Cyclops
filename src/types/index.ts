export type RiskLevel = 'safe' | 'warning' | 'critical' | 'neutral';

export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';
export type AlertStatus = 'active' | 'reviewed' | 'resolved';

export interface SecurityStats {
  riskScore: number; // e.g. 88 (out of 100)
  scoreGrade: 'Good' | 'Fair' | 'Needs Attention' | 'Critical';
  emailsAnalyzed: number;
  urlsScanned: number;
  documentsChecked: number;
  threatsBlocked: number;
  activeAlertsCount: number;
  phishingDefenseScore: number;
  urlReputationScore: number;
  documentSafetyScore: number;
  employeeAwarenessScore: number;
}

export interface SecurityEmail {
  id: string;
  sender: string;
  senderEmail: string;
  senderAvatar?: string;
  subject: string;
  bodySnippet: string;
  riskLevel: RiskLevel;
  status: 'flagged' | 'clean' | 'quarantined';
  detectedSignals: string[];
  timestamp: string;
  spfStatus: 'pass' | 'fail' | 'neutral';
  dkimStatus: 'pass' | 'fail' | 'neutral';
  dmarcStatus: 'pass' | 'fail' | 'neutral';
  domainAge: string;
  linksFound: { url: string; risk: RiskLevel; reason: string }[];
  attachmentsFound: { name: string; size: string; type: string; risk: RiskLevel }[];
  aiAnalysisSummary: string;
}

export interface UrlScanResult {
  id: string;
  url: string;
  timestamp: string;
  verdict: 'safe' | 'suspicious' | 'phishing' | 'malicious';
  riskLevel: RiskLevel;
  riskScore: number; // 0-100
  domainInfo: {
    domain: string;
    registrar: string;
    registeredDaysAgo: number;
    ipAddress: string;
    location: string;
    sslValid: boolean;
    sslIssuer: string;
  };
  suspiciousSignals: string[];
  recommendedAction: string;
}

export interface DocumentScanResult {
  id: string;
  fileName: string;
  fileSize: string;
  fileType: string;
  fileHash: string; // SHA-256 demo
  timestamp: string;
  riskLevel: RiskLevel;
  verdict: 'clean' | 'suspicious' | 'malicious';
  detectedSignals: string[];
  macroDetected: boolean;
  externalConnections: string[];
  aiSummary: string;
  recommendedAction: string;
}

export interface ActivityEvent {
  id: string;
  employeeName: string;
  employeeEmail: string;
  employeeAvatar: string;
  role: string;
  eventType: 'email_scan' | 'url_check' | 'document_analysis' | 'auth_event' | 'policy_change';
  title: string;
  description: string;
  severity: RiskLevel;
  timestamp: string;
  ipAddress: string;
  device: string;
}

export interface SecurityAlert {
  id: string;
  title: string;
  description: string;
  category: 'Phishing Attempt' | 'Suspicious URL' | 'Malicious Attachment' | 'Unusual Login' | 'Policy Violation';
  severity: AlertSeverity;
  status: AlertStatus;
  affectedEmployee: string;
  timestamp: string;
  aiMitigationPlan: string;
  technicalDetails: {
    sourceIp?: string;
    targetResource?: string;
    threatIndicators?: string[];
  };
}

export interface WorkspaceSettings {
  companyName: string;
  adminEmail: string;
  securityTier: 'Standard' | 'Pro' | 'Enterprise';
  autoQuarantinePhishing: boolean;
  scanExternalUrls: boolean;
  blockExecutableAttachments: boolean;
  requireTwoFactor: boolean;
  weeklySummaryReports: boolean;
  emailAlertsCriticalOnly: boolean;
  slackWebhookEnabled: boolean;
  slackWebhookUrl: string;
  browserExtensionPolicy: 'enforce' | 'optional' | 'disabled';
}

export interface PhishingHighlight {
  phrase: string;
  explanation: string;
}

export interface SentinelEmailFinding {
  id: string;
  title: string;
  severity: 'Medium' | 'High' | 'Critical';
  explanation: string;
  iconName?: string;
}

export interface AttachmentScanItem {
  id: string;
  fileName: string;
  fileType: 'PDF' | 'DOCX' | 'JPG' | 'ICS' | 'PKPASS' | string;
  threatScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  findings: string[];
  recommendation: string;
  status: 'Scanning' | 'Analysis complete' | 'Reviewed';
}

