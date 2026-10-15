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

export interface NormalizedUrlDetail {
  raw_input: string;
  normalized_url: string;
  sanitized_display_url: string;
  scheme: string;
  hostname: string;
  raw_hostname: string;
  ascii_hostname: string;
  unicode_hostname: string;
  port?: number | null;
  path: string;
  query?: string | null;
  fragment?: string | null;
  is_ip: boolean;
  ip_version?: number | null;
  is_private_ip: boolean;
  is_loopback: boolean;
  is_link_local: boolean;
  is_multicast: boolean;
  is_reserved: boolean;
  is_punycode: boolean;
  has_homograph_chars: boolean;
  homograph_details: string[];
  subdomain_count: number;
  is_shortener: boolean;
  credentials_detected: boolean;
  heuristic_notes: string[];
}

export interface RedirectHopItem {
  hop_number: number;
  url: string;
  status_code: number;
  resolved_ip: string;
  headers: Record<string, string>;
  hostname_changed: boolean;
  scheme_downgraded: boolean;
}

export interface RedirectAnalysisDetail {
  final_url: string;
  initial_url: string;
  redirect_chain: RedirectHopItem[];
  final_status_code?: number | null;
  final_resolved_ip?: string | null;
  content_type?: string | null;
  content_length: number;
  headers: Record<string, string>;
  stopped_reason?: string | null;
  tls_version?: string | null;
  tls_cipher?: string | null;
  error?: string | null;
}

export interface DnsRecordItem {
  record_type: string;
  value: string;
}

export interface DnsIntelligenceDetail {
  hostname: string;
  resolved_ips: string[];
  dns_records: DnsRecordItem[];
  canonical_cname?: string | null;
  error?: string | null;
}

export interface HostingIntelligenceDetail {
  ip_address: string;
  hostname?: string | null;
  country?: string | null;
  country_code?: string | null;
  region?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  asn?: string | null;
  organization?: string | null;
  isp?: string | null;
  is_cloud_or_cdn: boolean;
  provider_name?: string | null;
  is_shared_hosting: boolean;
  contextual_note?: string | null;
  data_provider: string;
  status: string;
}

export interface DomainRegistrationDetail {
  domain: string;
  registrar?: string | null;
  created_date?: string | null;
  expires_date?: string | null;
  domain_age_days?: number | null;
  is_recently_registered: boolean;
  status_codes: string[];
  nameservers: string[];
  privacy_protected: boolean;
  source: string;
  status: string;
  error?: string | null;
}

export interface FormAnalysisItem {
  action_url?: string | null;
  method: string;
  is_external_action: boolean;
  has_password_field: boolean;
  has_email_field: boolean;
  has_credit_card_field: boolean;
  input_field_names: string[];
}

export interface PageContentDetail {
  title?: string | null;
  meta_description?: string | null;
  meta_refresh_target?: string | null;
  forms_found: FormAnalysisItem[];
  has_password_input: boolean;
  has_external_form_action: boolean;
  has_credential_harvesting_terms: boolean;
  matched_phrases: string[];
  script_count: number;
  iframe_count: number;
  contains_hidden_inputs: boolean;
  status: string;
  limitations: string[];
}

export interface ProviderResultItem {
  provider_name: string;
  status: string;
  is_malicious?: boolean | null;
  threat_details?: string | null;
  reputation_score?: number | null;
  timestamp?: string | null;
  error_message?: string | null;
}

export interface SecuritySignalItem {
  id: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  is_positive: boolean;
  weight: number;
}

export interface UrlScanResult {
  id: string;
  url: string;
  timestamp: string;
  verdict: 'safe' | 'clean' | 'suspicious' | 'phishing' | 'malicious' | 'unknown';
  riskLevel: RiskLevel;
  riskScore: number; // 0-100 or continuous
  threat_score?: number; // 0.0 - 10.0
  summary?: string;
  plain_english_explanation?: string;
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
  reassuring_factors?: string[];
  risk_factors?: string[];
  missing_data_notes?: string[];
  signals?: SecuritySignalItem[];
  normalization?: NormalizedUrlDetail;
  redirect_analysis?: RedirectAnalysisDetail;
  dns_intelligence?: DnsIntelligenceDetail;
  hosting_intelligence?: HostingIntelligenceDetail;
  domain_registration?: DomainRegistrationDetail;
  page_content?: PageContentDetail;
  reputation_providers?: ProviderResultItem[];
  isLiveScan?: boolean;
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

