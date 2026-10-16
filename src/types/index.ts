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
  cdn_provider?: string | null;
  reverse_dns?: string | null;
  footprint_summary?: string | null;
  lookup_timestamp?: string | null;
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
  action_host?: string | null;
  has_password_field: boolean;
  has_email_field: boolean;
  has_credit_card_field: boolean;
  has_hidden_fields?: boolean;
  submits_to_http?: boolean;
  input_field_names: string[];
}

export interface SensitiveInputAudit {
  password_fields_detected: number;
  email_login_fields_detected: number;
  payment_fields_detected: number;
  form_submission_destinations: string[];
  cross_origin_submission_detected: boolean;
  cross_origin_details: string[];
  submits_over_insecure_http: boolean;
  is_https_page: boolean;
  evidence_based_explanation: string;
  warnings: string[];
  contextual_notes: string[];
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
  sensitive_input_audit?: SensitiveInputAudit;
  status: string;
  limitations: string[];
}

export interface SslCertificateIntelligence {
  hostname: string;
  port: number;
  status: 'valid' | 'expired' | 'hostname_mismatch' | 'self_signed' | 'untrusted' | 'unencrypted_http' | 'unable_to_verify';
  connection_status: string;
  is_valid: boolean;
  is_public_ca: boolean;
  issuer: string;
  issuer_org?: string | null;
  subject: string;
  subject_org?: string | null;
  subject_alt_names: string[];
  valid_from?: string | null;
  valid_until?: string | null;
  days_remaining?: number | null;
  hostname_match: boolean;
  certificate_chain_status: string;
  tls_version?: string | null;
  cipher_suite?: string | null;
  plain_language_explanation: string;
  warnings: string[];
  limitations: string[];
}

export interface DownloadSafetyResult {
  is_download: boolean;
  server_reported_filename?: string | null;
  effective_extension?: string | null;
  mime_type?: string | null;
  magic_byte_signature?: string | null;
  detected_format?: string | null;
  has_double_extension: boolean;
  is_executable_or_script: boolean;
  mismatch_detected: boolean;
  warning?: string | null;
  explanation: string;
  inspection_limitations: string[];
}

export interface AuthorityChecklistItem {
  authority_name: string;
  target_checked: string;
  check_type: string;
  status: 'threat_reported' | 'no_threat_reported' | 'not_configured' | 'check_unavailable' | 'not_applicable';
  verdict_label: string;
  evidence_summary: string;
  last_checked: string;
  queried_successfully: boolean;
}

export interface SecurityAuthorityChecklist {
  items: AuthorityChecklistItem[];
  threats_reported_count: number;
  clean_verdicts_count: number;
  unconfigured_count: number;
  unavailable_count: number;
  summary: string;
  disclaimer: string;
}

export interface ProviderResultItem {
  provider_name: string;
  category?: string;
  status: string;
  is_malicious?: boolean | null;
  detection_category?: string | null;
  threat_details?: string | null;
  reputation_score?: number | null;
  timestamp?: string | null;
  error_message?: string | null;
  reference_url?: string | null;
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

  // Six Advanced URL Security Features
  ssl_certificate?: SslCertificateIntelligence;
  sensitive_input_audit?: SensitiveInputAudit;
  download_safety?: DownloadSafetyResult;
  hosting_footprint?: HostingIntelligenceDetail;
  security_authority_checklist?: SecurityAuthorityChecklist;

  isLiveScan?: boolean;
}


export interface DocMacroInspection {
  macro_detected: boolean;
  status: 'detected' | 'not_detected' | 'unable_to_inspect' | 'unsupported';
  embedded_objects_detected: string[];
  suspicious_indicators?: string[];
  extracted_code_status?: string;
  extracted_snippets?: string[];
  affected_components?: string[];
  evidence_count?: number;
  explanation: string;
  warnings?: string[];
}

export interface DocHtmlSafety {
  is_html: boolean;
  login_fields_found: string[];
  password_fields_found: string[];
  external_form_destinations: string[];
  remote_scripts_detected: string[];
  suspicious_redirects_or_frames: string[];
  brand_domain_mismatches: string[];
  obfuscated_scripts: string[];
  inspection_limitations: string[];
  explanation: string;
  risk_level: RiskLevel;
}

export interface DocEmbeddedLinkItem {
  visible_text: string;
  destination_url: string;
  destination_domain: string;
  location?: string;
  mismatch_warning?: string | null;
  threat_verdict?: string;
  recommended_action?: string;
  is_mismatched?: boolean;
  risk_score?: number;
  reasons?: string[];
}

export interface DocEmbeddedLinks {
  total_links_found: number;
  mismatched_links_count: number;
  links?: DocEmbeddedLinkItem[];
  items?: DocEmbeddedLinkItem[];
  summary?: string;
  warnings?: string[];
}

export interface DocExploitIndicators {
  structural_anomalies: string[];
  suspicious_actions: string[];
  embedded_payloads?: string[];
  known_signature_matches: string[];
  parser_warnings?: string[];
  compression_ratio: number;
  engine_version?: string;
  coverage_and_limitations: string;
  explanation?: string;
}

export interface DocFormSubmission {
  interactive_forms_detected: boolean;
  form_type: string;
  sensitive_fields_detected: string[];
  submission_actions: string[];
  external_destinations: string[];
  event_triggered_behavior: string[];
  evidence: string[];
  limitations: string;
  explanation: string;
}

export interface DocSafeViewPage {
  page_number: number;
  image_data_url: string;
  width: number;
  height: number;
  extracted_text_snippet: string;
}

export interface DocSafeView {
  preview_id: string;
  status: 'available' | 'unavailable' | 'rendering_failed';
  total_pages: number;
  pages: DocSafeViewPage[];
  disclaimer: string;
  retention_policy: string;
}

export interface DocBrandDomainConsistency {
  claimed_organization?: string | null;
  primary_domain?: string | null;
  destination_domains: string[];
  domain_relationship_assessment: string;
  mismatches: string[];
  supporting_evidence: string[];
  confidence_or_uncertainty_explanation: string;
}

export interface DocScriptTranslation {
  has_script: boolean;
  language?: string;
  plain_english_summary: string;
  observed_operations: string[];
  inferred_intent_warning?: string;
  evidence_lines?: string[];
  intent?: string;
}

export interface DocHiddenContentItem {
  extracted_text: string;
  location?: string;
  classification_reason: string;
  detection_type?: 'structural' | 'visual_inference';
  context_snippet?: string;
  page_number?: number;
  element_type?: string;
}

export interface DocHiddenContent {
  has_hidden_content?: boolean;
  hidden_elements_count: number;
  items: DocHiddenContentItem[];
  summary: string;
  explanation: string;
}

export interface DocumentCheckItem {
  id: string;
  name: string;
  category: string;
  status: 'completed' | 'skipped' | 'failed' | 'unavailable';
  description: string;
  findings_count: number;
  limitations?: string | null;
}

export interface DocumentChecksSummary {
  total_checks: number;
  completed: number;
  skipped: number;
  failed: number;
  unavailable: number;
  limitations: string[];
  checks: DocumentCheckItem[];
}

export interface DocumentScanResult {
  id: string;
  fileName: string;
  fileSize: string;
  fileType: string;
  fileHash: string; // SHA-256
  timestamp: string;
  riskLevel: RiskLevel;
  verdict: 'clean' | 'suspicious' | 'malicious';
  detectedSignals: string[];
  macroDetected: boolean;
  externalConnections: string[];
  aiSummary: string;
  recommendedAction: string;
  riskScore?: number; // 0-100
  fileSizeBytes?: number;
  fileSizeHuman?: string;
  confidenceScore?: number;
  summary?: string;
  indicators?: string[];
  uploadedAt?: string;

  // Nine Advanced Document Security Features
  macro_inspection?: DocMacroInspection;
  html_safety?: DocHtmlSafety;
  embedded_links?: DocEmbeddedLinks;
  exploit_indicators?: DocExploitIndicators;
  forms_and_submission?: DocFormSubmission;
  safe_view?: DocSafeView;
  brand_domain_consistency?: DocBrandDomainConsistency;
  script_translator?: DocScriptTranslation;
  hidden_content?: DocHiddenContent;

  // Checks Execution Tracking
  checks_summary?: DocumentChecksSummary;
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

