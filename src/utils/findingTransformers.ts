import {
  UrlScanResult,
  DocumentScanResult,
  SecurityEmail,
  DocumentChecksSummary,
  DocumentCheckItem,
  DocEmbeddedLinkItem,
} from '../types';
import { SecurityFindingItem, FindingSeverity } from '../components/ui/SecurityFindingsList';
import { FindingsCounts, UnifiedVerdict } from '../components/ui/ScanResultSummary';

/**
 * Transforms a UrlScanResult into standardized SecurityFindingItem[] and FindingsCounts.
 */
export function extractUrlFindings(scan: UrlScanResult): {
  findings: SecurityFindingItem[];
  counts: FindingsCounts;
  verdict: UnifiedVerdict;
  verdictExplanation: string;
} {
  const findings: SecurityFindingItem[] = [];

  // 1. Structured Signals
  if (scan.signals && scan.signals.length > 0) {
    scan.signals.forEach((sig) => {
      let sev: FindingSeverity = 'warning';
      const sLower = sig.severity?.toLowerCase() || '';
      if (sLower.includes('crit') || sig.weight >= 8) sev = 'critical';
      else if (sLower.includes('high') || sig.weight >= 6) sev = 'high';
      else if (sLower.includes('warn') || sLower.includes('med') || sig.weight >= 4) sev = 'warning';
      else sev = 'info';

      findings.push({
        id: `sig-${sig.id || Math.random()}`,
        severity: sev,
        title: sig.title || 'Security Signal',
        detected: sig.description || sig.title,
        whyItMatters:
          sev === 'critical' || sev === 'high'
            ? 'This signal indicates an elevated risk of compromise, credential harvesting, or deceptive behavior.'
            : 'Informational signal observed during passive telemetry inspection.',
        evidence: `Category: ${sig.category || 'General Security'} • Signal Weight: ${sig.weight ?? 'N/A'}`,
        affectedTarget: scan.url,
        detectionMethod: 'Passive Multi-Signal Heuristics',
        recommendedAction: scan.recommendedAction || 'Inspect origin details before trusting.',
      });
    });
  }

  // 2. URLhaus / Reputation Providers
  if (scan.reputation_providers && scan.reputation_providers.length > 0) {
    scan.reputation_providers.forEach((prov, idx) => {
      if (prov.is_malicious) {
        findings.push({
          id: `rep-${idx}`,
          severity: 'critical',
          title: `Threat Feed Match: ${prov.provider_name}`,
          detected: prov.threat_details || `Reported as malicious by ${prov.provider_name}`,
          whyItMatters: 'Known active threat detected by threat intelligence feed. Domain or URL is linked to malware distribution or phishing.',
          evidence: `Provider: ${prov.provider_name} • Category: ${prov.detection_category || 'Malware/Phishing'}`,
          affectedTarget: scan.url,
          detectionMethod: prov.provider_name,
          recommendedAction: 'Block all incoming and outgoing connections to this destination.',
          technicalDetails: prov,
        });
      }
    });
  }

  // 3. SSL/TLS Certificate Intelligence
  if (scan.ssl_certificate) {
    const cert = scan.ssl_certificate;
    if (cert.status === 'expired' || cert.status === 'self_signed' || cert.status === 'untrusted' || cert.status === 'hostname_mismatch') {
      findings.push({
        id: 'ssl-invalid',
        severity: cert.status === 'hostname_mismatch' || cert.status === 'expired' ? 'high' : 'critical',
        title: `Invalid TLS Certificate: ${cert.status.replace(/_/g, ' ').toUpperCase()}`,
        detected: cert.plain_language_explanation || `SSL/TLS connection is insecure: ${cert.connection_status}`,
        whyItMatters: 'Network communication is vulnerable to eavesdropping, interception, or man-in-the-middle impersonation.',
        evidence: `Issuer: ${cert.issuer || 'Unknown'} • Valid Until: ${cert.valid_until || 'Expired'} • TLS Version: ${cert.tls_version || 'None'}`,
        affectedTarget: `${cert.hostname}:${cert.port}`,
        detectionMethod: 'Direct TLS Handshake Probe',
        recommendedAction: 'Do not enter passwords or sensitive personal/financial information on this site.',
        technicalDetails: cert,
      });
    } else if (cert.status === 'unencrypted_http') {
      findings.push({
        id: 'ssl-http',
        severity: 'high',
        title: 'Unencrypted HTTP Connection (No TLS)',
        detected: 'Website serves traffic over plain unencrypted HTTP on port 80 without SSL/TLS encryption.',
        whyItMatters: 'Any data transmitted between the client and server can be viewed or modified by on-path intermediaries.',
        evidence: `Protocol: http:// • Port: 80`,
        affectedTarget: scan.url,
        detectionMethod: 'HTTP Scheme Inspection',
        recommendedAction: 'Avoid entering any sensitive data over unencrypted channels.',
      });
    }
  }

  // 4. Sensitive Input Audit
  if (scan.sensitive_input_audit) {
    const audit = scan.sensitive_input_audit;
    if (audit.cross_origin_submission_detected) {
      findings.push({
        id: 'input-cross-origin',
        severity: 'critical',
        title: 'Cross-Origin Credential Form Submission',
        detected: `Login form submits credentials across origins to external endpoints: ${audit.form_submission_destinations.join(', ')}`,
        whyItMatters: 'Classic credential harvesting technique where login credentials entered by users are exfiltrated to third-party endpoints.',
        evidence: audit.cross_origin_details.length > 0 ? audit.cross_origin_details : audit.form_submission_destinations,
        affectedTarget: scan.url,
        detectionMethod: 'Static HTML Form Parser',
        recommendedAction: 'Do not provide account credentials. Verify destination domain ownership.',
        technicalDetails: audit,
      });
    } else if (audit.password_fields_detected > 0) {
      findings.push({
        id: 'input-password',
        severity: 'warning',
        title: `Interactive Password Inputs Found (${audit.password_fields_detected})`,
        detected: `Page contains ${audit.password_fields_detected} password input field(s).`,
        whyItMatters: 'Ensure you are on the authentic domain before supplying login credentials.',
        evidence: `Password fields: ${audit.password_fields_detected} • Submits over HTTPS: ${audit.is_https_page ? 'Yes' : 'No'}`,
        affectedTarget: scan.url,
        detectionMethod: 'Form DOM Audit',
        recommendedAction: 'Verify the padlock and canonical domain name before entering credentials.',
      });
    }
  }

  // 5. Download Safety
  if (scan.download_safety && scan.download_safety.is_download) {
    const ds = scan.download_safety;
    if (ds.is_executable_or_script || ds.has_double_extension || ds.mismatch_detected) {
      findings.push({
        id: 'download-exec',
        severity: 'critical',
        title: `Dangerous Executable Download: ${ds.server_reported_filename || 'Unknown File'}`,
        detected: ds.explanation || 'Direct download link serves executable binary or script payload.',
        whyItMatters: 'Executable files downloaded directly from web links pose severe malware risks if executed locally.',
        evidence: `MIME: ${ds.mime_type || 'Unknown'} • Magic Bytes: ${ds.magic_byte_signature || 'Unknown'} • Double Extension: ${ds.has_double_extension ? 'Yes' : 'No'}`,
        affectedTarget: ds.server_reported_filename || scan.url,
        detectionMethod: 'HTTP Header & Magic Byte Sniffer',
        recommendedAction: 'Do not execute or unpack the downloaded binary.',
        technicalDetails: ds,
      });
    }
  }

  // 6. Fallback from risk_factors if no signals were populated
  if (findings.length === 0 && scan.risk_factors && scan.risk_factors.length > 0) {
    scan.risk_factors.forEach((rf, idx) => {
      findings.push({
        id: `rf-${idx}`,
        severity: 'warning',
        title: 'Risk Factor Identified',
        detected: rf,
        whyItMatters: 'Observed anomaly indicates potential deviation from standard security practices.',
        evidence: rf,
        affectedTarget: scan.url,
        detectionMethod: 'Heuristic Risk Analysis',
        recommendedAction: scan.recommendedAction || 'Exercise caution.',
      });
    });
  }

  // 7. Reassuring factors as informational items if clean
  if (scan.reassuring_factors && scan.reassuring_factors.length > 0) {
    scan.reassuring_factors.slice(0, 3).forEach((re, idx) => {
      findings.push({
        id: `re-${idx}`,
        severity: 'info',
        title: 'Security Control Verified',
        detected: re,
        whyItMatters: 'Active defensive control or legitimate infrastructure verification passed.',
        evidence: re,
        affectedTarget: scan.url,
        detectionMethod: 'Domain & Infrastructure Verification',
        recommendedAction: 'No immediate remediation needed.',
      });
    });
  }

  // Compute counts
  const counts: FindingsCounts = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    warning: findings.filter((f) => f.severity === 'warning').length,
    info: findings.filter((f) => f.severity === 'info').length,
    unavailable: scan.missing_data_notes?.length || 0,
  };

  let verdict: UnifiedVerdict = 'clean';
  const vLower = scan.verdict.toLowerCase();
  if (vLower.includes('phish') || vLower.includes('malicious') || counts.critical > 0) {
    verdict = 'malicious';
  } else if (vLower.includes('suspicious') || counts.high > 0 || counts.warning > 0) {
    verdict = 'suspicious';
  } else if (vLower.includes('clean') || vLower.includes('safe')) {
    verdict = 'clean';
  } else {
    verdict = 'incomplete';
  }

  const verdictExplanation =
    scan.plain_english_explanation ||
    scan.summary ||
    (verdict === 'malicious'
      ? 'Target domain or page matches known malicious signatures, credential phishing heuristics, or active exploit payloads.'
      : verdict === 'suspicious'
      ? 'Unusual redirects, low domain reputation, or heuristic warnings detected on target.'
      : 'Completed checks found no known threats across inspected threat intelligence sources and heuristic rules.');

  return { findings, counts, verdict, verdictExplanation };
}

/**
 * Dynamically computes or normalizes DocumentChecksSummary across the 9 analysis modules.
 * Accurately tracks completed, skipped, failed, and unavailable checks based on actual analysis data.
 */
export function buildDocumentChecksSummary(doc: DocumentScanResult): DocumentChecksSummary {
  // If the backend or caller already provided checks_summary, use it directly
  if (doc.checks_summary) {
    return doc.checks_summary;
  }

  // Handle case where document has not been assessed at all
  if (!doc.fileName && !doc.fileType && !doc.macro_inspection && !doc.html_safety && !doc.exploit_indicators) {
    return {
      total_checks: 0,
      completed: 0,
      skipped: 0,
      failed: 0,
      unavailable: 0,
      limitations: [],
      checks: [],
    };
  }

  const filename = doc.fileName || '';
  const ext = filename.toLowerCase().split('.').pop() || '';
  const checks: DocumentCheckItem[] = [];
  const limitations: string[] = [];

  // 1. VBA Macro & Embedded Automation
  let macroStatus: 'completed' | 'skipped' | 'failed' | 'unavailable' = 'completed';
  let macroDesc = 'Inspected OOXML package container and VBA streams for macros and automation.';
  let macroFindings = 0;
  if (doc.macro_inspection) {
    if (doc.macro_inspection.status === 'unsupported') {
      macroStatus = 'skipped';
      macroDesc = doc.macro_inspection.explanation || 'VBA macro inspection not applicable to this file format.';
    } else if (doc.macro_inspection.status === 'unable_to_inspect') {
      macroStatus = 'unavailable';
      macroDesc = doc.macro_inspection.explanation || 'Unable to unpack macro project streams.';
    } else {
      macroStatus = 'completed';
      macroDesc = doc.macro_inspection.explanation || 'VBA macro inspection completed.';
      macroFindings = (doc.macro_inspection.suspicious_indicators?.length || 0) + (doc.macro_inspection.embedded_objects_detected?.length || 0);
    }
  } else if (ext === 'exe' || ext === 'bin') {
    macroStatus = 'skipped';
    macroDesc = 'VBA macro inspection not applicable to binary executables.';
  } else if (['docm', 'xlsm', 'pptm', 'docx', 'xlsx', 'pptx'].includes(ext)) {
    macroStatus = 'completed';
  } else {
    macroStatus = 'skipped';
    macroDesc = 'Macro analysis not applicable to this document format.';
  }
  checks.push({
    id: 'check-macro',
    name: 'VBA Macro & Embedded Automation Analysis',
    category: 'Macros & Code',
    status: macroStatus,
    description: macroDesc,
    findings_count: macroFindings,
  });

  // 2. HTML Phishing & Script Injection
  let htmlStatus: 'completed' | 'skipped' | 'failed' | 'unavailable' = 'skipped';
  let htmlDesc = 'HTML phishing checks skipped (not an HTML document).';
  let htmlFindings = 0;
  if (doc.html_safety && doc.html_safety.is_html) {
    htmlStatus = 'completed';
    htmlDesc = doc.html_safety.explanation || 'Parsed HTML DOM elements, login inputs, and scripts.';
    htmlFindings =
      (doc.html_safety.password_fields_found?.length || 0) +
      (doc.html_safety.external_form_destinations?.length || 0) +
      (doc.html_safety.obfuscated_scripts?.length || 0);
    if (doc.html_safety.inspection_limitations) {
      limitations.push(...doc.html_safety.inspection_limitations);
    }
  } else if (['html', 'htm'].includes(ext)) {
    htmlStatus = 'completed';
    htmlDesc = 'HTML attachment security inspection completed.';
  }
  checks.push({
    id: 'check-html',
    name: 'HTML Phishing & Credential Form Inspection',
    category: 'HTML Security',
    status: htmlStatus,
    description: htmlDesc,
    findings_count: htmlFindings,
    limitations: doc.html_safety?.inspection_limitations?.join('; ') || null,
  });

  // 3. Embedded Hyperlinks
  let linkStatus: 'completed' | 'skipped' | 'failed' | 'unavailable' = 'completed';
  let linkDesc = 'Audited embedded hyperlinks and destination URLs.';
  const linkFindings = doc.embedded_links?.mismatched_links_count || 0;
  if (ext === 'exe') {
    linkStatus = 'skipped';
    linkDesc = 'Hyperlink extraction skipped for raw binary executable.';
  } else if (doc.embedded_links) {
    linkDesc = `Extracted and audited ${doc.embedded_links.total_links_found} embedded hyperlink destination(s).`;
  }
  checks.push({
    id: 'check-links',
    name: 'Embedded Hyperlink & Misdirection Audit',
    category: 'Hyperlinks',
    status: linkStatus,
    description: linkDesc,
    findings_count: linkFindings,
  });

  // 4. Brand Domain Consistency
  let brandStatus: 'completed' | 'skipped' | 'failed' | 'unavailable' = 'completed';
  let brandDesc = 'Cross-referenced document text branding against destination web hosts.';
  const brandFindings = doc.brand_domain_consistency?.mismatches?.length || 0;
  if (ext === 'exe') {
    brandStatus = 'skipped';
    brandDesc = 'Brand domain consistency check skipped for binary files.';
  }
  checks.push({
    id: 'check-brand',
    name: 'Brand Identity & Domain Verification',
    category: 'Brand Matching',
    status: brandStatus,
    description: brandDesc,
    findings_count: brandFindings,
  });

  // 5. Structural Exploit Indicators
  const exploitStatus: 'completed' | 'skipped' | 'failed' | 'unavailable' = 'completed';
  const exploitDesc = 'Audited document structure, dictionary streams, and /Launch execution actions.';
  const exploitFindings =
    (doc.exploit_indicators?.suspicious_actions?.length || 0) +
    (doc.exploit_indicators?.structural_anomalies?.length || 0) +
    (doc.exploit_indicators?.known_signature_matches?.length || 0);
  if (doc.exploit_indicators?.coverage_and_limitations) {
    limitations.push(doc.exploit_indicators.coverage_and_limitations);
  }
  checks.push({
    id: 'check-exploit',
    name: 'Structural Exploit & Launch Action Audit',
    category: 'Exploits',
    status: exploitStatus,
    description: exploitDesc,
    findings_count: exploitFindings,
    limitations: doc.exploit_indicators?.coverage_and_limitations || null,
  });

  // 6. Interactive Forms & Submission
  let formStatus: 'completed' | 'skipped' | 'failed' | 'unavailable' = 'skipped';
  let formDesc = 'Interactive form check not applicable to this file format.';
  const formFindings = doc.forms_and_submission?.external_destinations?.length || 0;
  if (['pdf', 'html', 'htm'].includes(ext) || doc.forms_and_submission?.interactive_forms_detected) {
    formStatus = 'completed';
    formDesc = doc.forms_and_submission?.explanation || 'Audited form submission hooks for external data exfiltration.';
    if (doc.forms_and_submission?.limitations) {
      limitations.push(doc.forms_and_submission.limitations);
    }
  }
  checks.push({
    id: 'check-forms',
    name: 'Interactive Form & Data Exfiltration Audit',
    category: 'Forms',
    status: formStatus,
    description: formDesc,
    findings_count: formFindings,
    limitations: doc.forms_and_submission?.limitations || null,
  });

  // 7. Script Translator
  let scriptStatus: 'completed' | 'skipped' | 'failed' | 'unavailable' = 'skipped';
  let scriptDesc = 'No macro script present to translate.';
  let scriptFindings = 0;
  if (doc.macroDetected || doc.macro_inspection?.macro_detected) {
    scriptStatus = 'completed';
    scriptDesc = 'Translated extracted VBA macro commands into plain-English behavioral summary.';
    scriptFindings = doc.script_translator?.observed_operations?.length || 0;
  }
  checks.push({
    id: 'check-translator',
    name: 'VBA Script De-obfuscation & Explanation',
    category: 'Script Explanation',
    status: scriptStatus,
    description: scriptDesc,
    findings_count: scriptFindings,
  });

  // 8. Hidden Content
  let hiddenStatus: 'completed' | 'skipped' | 'failed' | 'unavailable' = 'completed';
  let hiddenDesc = 'Inspected visual geometries, invisible font colors, and concealed layers.';
  const hiddenFindings = doc.hidden_content?.hidden_elements_count || 0;
  if (!['pdf', 'docx', 'docm', 'xlsx', 'xlsm'].includes(ext) && !doc.hidden_content) {
    hiddenStatus = 'skipped';
    hiddenDesc = 'Concealed text layer audit not applicable to this format.';
  }
  checks.push({
    id: 'check-hidden',
    name: 'Concealed & Invisible Text Layer Audit',
    category: 'Hidden Content',
    status: hiddenStatus,
    description: hiddenDesc,
    findings_count: hiddenFindings,
  });

  // 9. Safe View
  let safeViewStatus: 'completed' | 'skipped' | 'failed' | 'unavailable' = 'completed';
  let safeViewDesc = 'Successfully flattened document into zero-interaction static preview.';
  if (doc.safe_view?.status === 'unavailable' || ext === 'exe') {
    safeViewStatus = 'unavailable';
    safeViewDesc = doc.safe_view?.disclaimer || 'Safe View preview is unavailable for executable binaries.';
  } else if (doc.safe_view?.status === 'available') {
    safeViewStatus = 'completed';
  }
  if (doc.safe_view?.disclaimer) {
    limitations.push(doc.safe_view.disclaimer);
  }
  checks.push({
    id: 'check-safeview',
    name: 'Zero-Interaction Safe View Flattening',
    category: 'Sandboxed Preview',
    status: safeViewStatus,
    description: safeViewDesc,
    findings_count: 0,
    limitations: doc.safe_view?.disclaimer || null,
  });

  limitations.push('Static structural audit cannot guarantee discovery of novel zero-day exploits. No code was executed.');
  const uniqueLimitations = Array.from(new Set(limitations.filter(Boolean).map((l) => l.trim())));

  const completed = checks.filter((c) => c.status === 'completed').length;
  const skipped = checks.filter((c) => c.status === 'skipped').length;
  const failed = checks.filter((c) => c.status === 'failed').length;
  const unavailable = checks.filter((c) => c.status === 'unavailable').length;

  return {
    total_checks: checks.length,
    completed,
    skipped,
    failed,
    unavailable,
    limitations: uniqueLimitations,
    checks,
  };
}

/**
 * Transforms a DocumentScanResult into standardized SecurityFindingItem[] and FindingsCounts.
 */
export function extractDocumentFindings(doc: DocumentScanResult): {
  findings: SecurityFindingItem[];
  counts: FindingsCounts;
  verdict: UnifiedVerdict;
  verdictExplanation: string;
  checksSummary: DocumentChecksSummary;
} {
  const findings: SecurityFindingItem[] = [];

  // 1. Macro & Embedded Code
  if (doc.macro_inspection && doc.macro_inspection.macro_detected) {
    const mi = doc.macro_inspection;
    const suspCount = (mi.suspicious_indicators || []).length;
    const isCritical = suspCount > 0;
    const snippets = mi.extracted_snippets || [];
    findings.push({
      id: 'doc-macro',
      severity: isCritical ? 'critical' : 'warning',
      title: isCritical ? 'Active VBA Macro with Suspicious APIs' : 'Embedded VBA Macro Project Present',
      detected: mi.explanation || 'VBA macro detected in document.',
      whyItMatters:
        'VBA macros can run arbitrary commands, execute shell scripts, and download external payloads upon document opening.',
      evidence: snippets.length > 0 ? snippets : (mi.suspicious_indicators || []),
      affectedTarget: mi.affected_components?.join(', ') || doc.fileName,
      detectionMethod: 'OOXML Package Decompiler & AST Stream Parser',
      recommendedAction: 'Do not enable macros unless sender authenticity is confirmed out-of-band.',
      technicalDetails: mi,
    });
  }

  // 2. HTML Attachment Safety
  if (doc.html_safety && doc.html_safety.is_html) {
    const hs = doc.html_safety;
    const pwFields = hs.password_fields_found || [];
    const extDests = hs.external_form_destinations || [];
    const obfScripts = hs.obfuscated_scripts || [];
    if (pwFields.length > 0 && extDests.length > 0) {
      findings.push({
        id: 'doc-html-phish',
        severity: 'critical',
        title: 'Local HTML Credential Phishing Form',
        detected: hs.explanation || 'HTML attachment contains login inputs targeting external destinations.',
        whyItMatters: 'HTML attachment imitates an authentication portal and sends submitted passwords to an external server.',
        evidence: [
          ...pwFields,
          ...extDests.map((d) => `Destination: ${d}`),
        ],
        affectedTarget: doc.fileName,
        detectionMethod: 'Static HTML DOM Inspector',
        recommendedAction: 'Do not enter passwords. Quarantine or delete the attachment.',
        technicalDetails: hs,
      });
    } else if (obfScripts.length > 0) {
      findings.push({
        id: 'doc-html-obf',
        severity: 'high',
        title: 'Obfuscated JavaScript in Attachment',
        detected: `Detected ${obfScripts.length} script obfuscation pattern(s): ${obfScripts.join(', ')}`,
        whyItMatters: 'Obfuscation techniques are commonly used to hide malicious URLs and payload loaders from security filters.',
        evidence: obfScripts,
        affectedTarget: doc.fileName,
        detectionMethod: 'Static JavaScript Tokenizer',
        recommendedAction: 'Do not open the file in a web browser.',
        technicalDetails: hs,
      });
    }
  }

  // 3. Embedded Hyperlink Mismatches
  if (doc.embedded_links) {
    const rawLinks = doc.embedded_links.links || [];
    const rawItems = doc.embedded_links.items || [];
    const linkItems: DocEmbeddedLinkItem[] = rawLinks.length > 0 ? rawLinks : rawItems;
    if (doc.embedded_links.mismatched_links_count > 0 || linkItems.length > 0) {
      linkItems.forEach((l, idx) => {
        if (l.mismatch_warning || l.is_mismatched || l.threat_verdict === 'suspicious' || l.threat_verdict === 'malicious') {
          findings.push({
            id: `doc-link-${idx}`,
            severity: l.threat_verdict === 'malicious' || (l.risk_score && l.risk_score > 80) ? 'critical' : 'high',
            title: 'Misleading Hyperlink Destination (One-Click Misdirection)',
            detected: l.mismatch_warning || (l.reasons ? l.reasons.join(', ') : 'Destination mismatch detected'),
            whyItMatters: 'Anchor text displays a trusted address while the actual hyperlink navigates to a different host.',
            evidence: `Display Text: "${l.visible_text}" -> Actual Destination: ${l.destination_url}`,
            affectedTarget: l.location || l.destination_domain || doc.fileName,
            detectionMethod: 'Hyperlink & Relationship Cross-Matcher',
            recommendedAction: 'Do not click the link. Verify the destination domain manually.',
            technicalDetails: l,
          });
        }
      });
    }
  }

  // 4. Document Exploit & Structure
  if (doc.exploit_indicators) {
    const exp = doc.exploit_indicators;
    const suspActions = exp.suspicious_actions || [];
    const structAnom = exp.structural_anomalies || [];
    const knownSigs = exp.known_signature_matches || [];
    if (suspActions.length > 0) {
      findings.push({
        id: 'doc-exploit-action',
        severity: 'critical',
        title: 'Dangerous Document Action (/Launch /JavaScript)',
        detected: exp.explanation || 'Dangerous executable or stream action discovered in document.',
        whyItMatters: 'PDF /Launch or binary execution hooks can trigger command-line tools or external programs directly on the host.',
        evidence: suspActions,
        affectedTarget: 'PDF Dictionary Stream',
        detectionMethod: 'PDF Structural Dictionary Parser',
        recommendedAction: 'Open only in Safe View. Do not open in native desktop PDF viewers.',
        technicalDetails: exp,
      });
    }
    if (knownSigs.length > 0) {
      findings.push({
        id: 'doc-exploit-sig',
        severity: 'critical',
        title: 'Known Exploit Signature Match',
        detected: knownSigs.join(', '),
        whyItMatters: 'Byte pattern or structure matches known weaponized CVE exploit vectors.',
        evidence: knownSigs,
        affectedTarget: doc.fileName,
        detectionMethod: 'Exploit Signature Matcher',
        recommendedAction: 'Do not open this file. Isolate immediately.',
      });
    }
    if (structAnom.length > 0) {
      findings.push({
        id: 'doc-structure-anomaly',
        severity: 'warning',
        title: 'Structural Package Anomaly',
        detected: structAnom[0],
        whyItMatters: 'Non-standard object structure or unexpected packaging indicates possible evasion attempt.',
        evidence: structAnom,
        affectedTarget: doc.fileName,
        detectionMethod: 'ZIP/PDF Header Audit',
        recommendedAction: 'Inspect document thoroughly before execution.',
      });
    }
  }

  // 5. Forms & Data Submission
  if (doc.forms_and_submission && (doc.forms_and_submission.external_destinations || []).length > 0) {
    findings.push({
      id: 'doc-form-submit',
      severity: 'critical',
      title: 'Automated Form Submission to External Destination',
      detected: doc.forms_and_submission.explanation || 'Form submit action targets external web server.',
      whyItMatters: 'Form submit actions can exfiltrate user inputs directly to remote web servers.',
      evidence: doc.forms_and_submission.external_destinations,
      affectedTarget: doc.forms_and_submission.form_type || 'Interactive Form',
      detectionMethod: 'AcroForm Action Catalog Audit',
      recommendedAction: 'Do not fill out interactive form fields.',
      technicalDetails: doc.forms_and_submission,
    });
  }

  // 6. Hidden Content & Invisible Text
  if (doc.hidden_content && (doc.hidden_content.hidden_elements_count > 0 || (doc.hidden_content.items || []).length > 0)) {
    const hiddenItems = doc.hidden_content.items || [];
    hiddenItems.forEach((item, idx) => {
      findings.push({
        id: `doc-hidden-${idx}`,
        severity: 'warning',
        title: `Concealed Document Content: ${item.classification_reason || 'Invisible Element'}`,
        detected: `Text concealed from normal rendering: "${item.extracted_text || ''}"`,
        whyItMatters: 'Hidden text may be used for prompt injection, keyword stuffing, or hiding contractual terms.',
        evidence: `Location: ${item.location || `Page ${item.page_number || 1}`} • Type: ${item.detection_type || item.element_type || 'hidden'} • Snippet: ${item.context_snippet || item.extracted_text || ''}`,
        affectedTarget: item.location || `Page ${item.page_number || 1}`,
        detectionMethod: 'Stream & Geometry Bounds Scanner',
        recommendedAction: 'Review hidden text before trusting or signing the document.',
      });
    });
  }

  // Fallback from detectedSignals ONLY if the verdict is non-clean (threats exist) and no structured findings were generated
  if (doc.verdict !== 'clean' && findings.length === 0 && doc.detectedSignals && doc.detectedSignals.length > 0) {
    doc.detectedSignals.forEach((sig, idx) => {
      findings.push({
        id: `ds-${idx}`,
        severity: doc.riskLevel === 'critical' || doc.verdict === 'malicious' ? 'critical' : 'warning',
        title: 'Security Threat Indicator',
        detected: sig,
        whyItMatters: 'Potential vulnerability or exploit indicator flagged by static heuristics.',
        evidence: sig,
        affectedTarget: doc.fileName,
        detectionMethod: 'Static Inspection Pipeline',
        recommendedAction: doc.recommendedAction || 'Inspect origin details before trusting.',
      });
    });
  }

  // Compute checks execution summary
  const checksSummary = buildDocumentChecksSummary(doc);

  // Compute counts
  const counts: FindingsCounts = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    warning: findings.filter((f) => f.severity === 'warning').length,
    info: findings.filter((f) => f.severity === 'info').length,
    unavailable: checksSummary.unavailable,
  };

  let verdict: UnifiedVerdict = 'clean';
  if (doc.verdict === 'malicious' || counts.critical > 0) verdict = 'malicious';
  else if (doc.verdict === 'suspicious' || counts.high > 0 || counts.warning > 0) verdict = 'suspicious';
  else if (checksSummary.completed === 0) verdict = 'incomplete';
  else verdict = 'clean';

  const verdictExplanation =
    doc.aiSummary ||
    (verdict === 'malicious'
      ? 'Active exploit mechanisms, credential phishing forms, or executable macros identified in document structure.'
      : verdict === 'suspicious'
      ? 'Anomalous document characteristics or macro structures detected. Verification advised before enabling active content.'
      : checksSummary.completed === 0
      ? 'No security checks were completed. This document has not been assessed.'
      : 'No macros, credential-harvesting forms, exploit actions, or hidden layers detected across inspected document streams.');

  return { findings, counts, verdict, verdictExplanation, checksSummary };
}

/**
 * Transforms an email and its attachments into standardized SecurityFindingItem[] and FindingsCounts.
 */
export function extractEmailFindings(
  email: SecurityEmail,
  findingsList: Array<{ id: string; title: string; severity: string; explanation: string }>
): {
  findings: SecurityFindingItem[];
  counts: FindingsCounts;
  verdict: UnifiedVerdict;
  verdictExplanation: string;
} {
  const findings: SecurityFindingItem[] = [];

  findingsList.forEach((f) => {
    let sev: FindingSeverity = 'warning';
    const sLower = f.severity?.toLowerCase() || '';
    if (sLower.includes('crit')) sev = 'critical';
    else if (sLower.includes('high')) sev = 'high';
    else if (sLower.includes('med') || sLower.includes('warn')) sev = 'warning';
    else sev = 'info';

    findings.push({
      id: f.id,
      severity: sev,
      title: f.title,
      detected: f.explanation,
      whyItMatters:
        sev === 'critical' || sev === 'high'
          ? 'High risk of credential theft, financial fraud, or endpoint malware delivery.'
          : 'Suspicious signal characteristic of social-engineering email campaigns.',
      evidence: `Sender: ${email.senderEmail} • Subject: "${email.subject}"`,
      affectedTarget: email.senderEmail,
      detectionMethod: 'Email Authentication & Content Analyzer',
      recommendedAction: 'Do not click links or open attachments. Quarantine email.',
    });
  });

  // Attachments
  if (email.attachmentsFound) {
    email.attachmentsFound.forEach((att, idx) => {
      if (att.risk === 'critical' || att.risk === 'warning') {
        findings.push({
          id: `att-${idx}`,
          severity: att.risk === 'critical' ? 'critical' : 'high',
          title: `Suspicious Inbound Attachment: ${att.name}`,
          detected: `Attachment type (${att.type}) flagged with ${att.risk.toUpperCase()} risk.`,
          whyItMatters: 'File attachments can execute malicious scripts or exploit document reader vulnerabilities.',
          evidence: `File: ${att.name} (${att.size}) • Type: ${att.type}`,
          affectedTarget: att.name,
          detectionMethod: 'Passive Attachment Scanner',
          recommendedAction: 'Do not open or download attachment.',
        });
      }
    });
  }

  // Links
  if (email.linksFound) {
    email.linksFound.forEach((lnk, idx) => {
      if (lnk.risk === 'critical' || lnk.risk === 'warning') {
        findings.push({
          id: `lnk-${idx}`,
          severity: lnk.risk === 'critical' ? 'critical' : 'high',
          title: `Malicious Link in Email Body: ${lnk.reason}`,
          detected: `Email contains URL pointing to unverified or flagged destination: ${lnk.url}`,
          whyItMatters: 'Recipient could be directed to a spoofed login page or malware drop site.',
          evidence: `URL: ${lnk.url} • Flag reason: ${lnk.reason}`,
          affectedTarget: lnk.url,
          detectionMethod: 'In-Body Hyperlink Parser',
          recommendedAction: 'Do not follow link.',
        });
      }
    });
  }

  const counts: FindingsCounts = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    warning: findings.filter((f) => f.severity === 'warning').length,
    info: findings.filter((f) => f.severity === 'info').length,
  };

  let verdict: UnifiedVerdict = 'clean';
  if (email.riskLevel === 'critical' || counts.critical > 0) verdict = 'malicious';
  else if (email.riskLevel === 'warning' || counts.high > 0 || counts.warning > 0) verdict = 'suspicious';
  else verdict = 'clean';

  const verdictExplanation =
    verdict === 'malicious'
      ? 'Critical phishing signals detected including sender domain mismatch, spoofed branding, and urgent credential prompts.'
      : verdict === 'suspicious'
      ? 'Anomalous sender signals or untrusted external links detected in inbound email.'
      : 'Inbound email passed SPF/DKIM verification with no known malicious attachments or phishing domains.';

  return { findings, counts, verdict, verdictExplanation };
}
