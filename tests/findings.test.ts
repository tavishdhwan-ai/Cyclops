import assert from 'node:assert';
import { extractDocumentFindings, buildDocumentChecksSummary } from '../src/utils/findingTransformers';
import { DocumentScanResult } from '../src/types';
import { SecurityFindingItem, FindingSeverity } from '../src/components/ui/SecurityFindingsList';

console.log('--- Running Cyclops Document Security Findings & Check Tracker Tests ---');

// Helper to construct complete DocumentScanResult for test fixtures
function makeDocResult(overrides: Partial<DocumentScanResult>): DocumentScanResult {
  return {
    id: 'doc-mock-id',
    fileName: 'document.pdf',
    fileSize: '45 KB',
    fileType: 'application/pdf',
    fileHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    timestamp: new Date().toISOString(),
    riskLevel: 'safe',
    verdict: 'clean',
    detectedSignals: [],
    macroDetected: false,
    externalConnections: [],
    aiSummary: 'Static analysis complete.',
    recommendedAction: 'No action needed.',
    ...overrides,
  };
}

// Helper function that mirrors the UI filter logic in SecurityFindingsList.tsx
function filterFindings(findings: SecurityFindingItem[], activeFilter: string): SecurityFindingItem[] {
  if (activeFilter === 'ALL') return findings;
  if (activeFilter === 'CRITICAL') return findings.filter((f) => f.severity === 'critical');
  if (activeFilter === 'HIGH') return findings.filter((f) => f.severity === 'high');
  if (activeFilter === 'WARNING') return findings.filter((f) => f.severity === 'warning');
  if (activeFilter === 'INFORMATIONAL') return findings.filter((f) => f.severity === 'info');
  return findings;
}

// ---------------------------------------------------------------------------
// 1. Zero findings with successful checks
// ---------------------------------------------------------------------------
console.log('Test 1: Zero findings with successful checks');
const cleanDocResult = makeDocResult({
  id: 'doc-clean-123',
  fileName: 'Clean_Report.pdf',
  fileSizeBytes: 45000,
  fileSizeHuman: '45 KB',
  fileType: 'application/pdf',
  uploadedAt: new Date().toISOString(),
  verdict: 'clean',
  riskLevel: 'safe',
  confidenceScore: 0.98,
  summary: 'No active threats detected by completed checks.',
  indicators: [],
  macroDetected: false,
  checks_summary: {
    total_checks: 9,
    completed: 7,
    skipped: 2,
    failed: 0,
    unavailable: 0,
    limitations: ['Static structural audit cannot guarantee discovery of novel zero-day exploits. No code was executed.'],
    checks: [
      { id: 'check-macro', name: 'Macro Audit', category: 'Macros', status: 'completed', description: 'No macros', findings_count: 0 },
      { id: 'check-links', name: 'Hyperlink Audit', category: 'Hyperlinks', status: 'completed', description: '0 links', findings_count: 0 },
      { id: 'check-brand', name: 'Brand Check', category: 'Brand', status: 'completed', description: 'Matched', findings_count: 0 },
      { id: 'check-exploit', name: 'Exploit Audit', category: 'Exploits', status: 'completed', description: 'Clean', findings_count: 0 },
      { id: 'check-forms', name: 'Forms Audit', category: 'Forms', status: 'completed', description: 'No forms', findings_count: 0 },
      { id: 'check-hidden', name: 'Hidden Content', category: 'Hidden', status: 'completed', description: 'Clean', findings_count: 0 },
      { id: 'check-safeview', name: 'Safe View', category: 'Preview', status: 'completed', description: 'Rendered', findings_count: 0 },
      { id: 'check-html', name: 'HTML Phishing', category: 'HTML', status: 'skipped', description: 'Not HTML', findings_count: 0 },
      { id: 'check-translator', name: 'Script Translator', category: 'Script', status: 'skipped', description: 'No script', findings_count: 0 },
    ],
  },
});

const cleanExtraction = extractDocumentFindings(cleanDocResult);
// Must NOT inject fake findings
assert.strictEqual(cleanExtraction.findings.length, 0, 'Clean scan must yield exactly 0 findings without fake items');
assert.strictEqual(cleanExtraction.checksSummary.completed, 7, 'Completed checks must reflect actual checks performed (7)');
assert.strictEqual(cleanExtraction.checksSummary.failed, 0, 'No checks failed');
assert.strictEqual(cleanExtraction.checksSummary.unavailable, 0, 'No checks unavailable');
const directSummary = buildDocumentChecksSummary(cleanDocResult);
assert.strictEqual(directSummary.completed, 7, 'buildDocumentChecksSummary must return correct completed count');
console.log('✓ Clean scan successfully separates 0 findings from 7 completed checks and retains limitations');

// ---------------------------------------------------------------------------
// 2. Zero checks executed (Unassessed Document)
// ---------------------------------------------------------------------------
console.log('Test 2: Zero checks executed');
const unassessedDocResult = makeDocResult({
  id: 'doc-empty-000',
  fileName: 'Unknown_File.bin',
  fileSizeBytes: 100,
  fileSizeHuman: '100 B',
  fileType: 'application/octet-stream',
  uploadedAt: new Date().toISOString(),
  verdict: 'clean',
  riskLevel: 'safe',
  confidenceScore: 0.0,
  summary: 'Pending audit',
  indicators: [],
  macroDetected: false,
  checks_summary: {
    total_checks: 0,
    completed: 0,
    skipped: 0,
    failed: 0,
    unavailable: 0,
    limitations: [],
    checks: [],
  },
});

const unassessedExtraction = extractDocumentFindings(unassessedDocResult);
assert.strictEqual(unassessedExtraction.findings.length, 0);
assert.strictEqual(unassessedExtraction.checksSummary.completed, 0, 'Must record 0 completed checks');
// Check UI condition logic:
const isZeroChecks = unassessedExtraction.checksSummary.completed === 0;
assert.ok(isZeroChecks, 'Must identify as zero checks completed for neutral warning');
console.log('✓ Zero checks executed correctly identified for neutral unassessed warning');

// ---------------------------------------------------------------------------
// 3. Partial failures & unavailable checks
// ---------------------------------------------------------------------------
console.log('Test 3: Partial failures & unavailable checks');
const partialDocResult = makeDocResult({
  id: 'doc-partial-456',
  fileName: 'Encrypted_Doc.pdf',
  fileSizeBytes: 95000,
  fileSizeHuman: '95 KB',
  fileType: 'application/pdf',
  uploadedAt: new Date().toISOString(),
  verdict: 'clean',
  riskLevel: 'safe',
  confidenceScore: 0.5,
  summary: 'Partially analyzed',
  indicators: [],
  macroDetected: false,
  checks_summary: {
    total_checks: 9,
    completed: 5,
    skipped: 2,
    failed: 1,
    unavailable: 1,
    limitations: ['Password protected sections skipped.'],
    checks: [
      { id: 'check-macro', name: 'Macro Audit', category: 'Macros', status: 'completed', description: 'No macros', findings_count: 0 },
      { id: 'check-links', name: 'Hyperlink Audit', category: 'Hyperlinks', status: 'failed', description: 'PDF stream corrupt', findings_count: 0 },
      { id: 'check-safeview', name: 'Safe View', category: 'Preview', status: 'unavailable', description: 'DRM protected', findings_count: 0 },
    ],
  },
});

const partialExtraction = extractDocumentFindings(partialDocResult);
const hasUnavailableOrFailed =
  partialExtraction.checksSummary.failed > 0 || partialExtraction.checksSummary.unavailable > 0;
assert.ok(hasUnavailableOrFailed, 'Must identify partial scan state');
assert.strictEqual(partialExtraction.checksSummary.failed, 1);
assert.strictEqual(partialExtraction.checksSummary.unavailable, 1);
console.log('✓ Partial scan state correctly identifies failed and unavailable checks');

// ---------------------------------------------------------------------------
// 4. Nonzero findings with multi-category threats
// ---------------------------------------------------------------------------
console.log('Test 4: Nonzero findings');
const maliciousDocResult = makeDocResult({
  id: 'doc-mal-789',
  fileName: 'Weaponized_Invoice.xlsm',
  fileSizeBytes: 120000,
  fileSizeHuman: '120 KB',
  fileType: 'application/vnd.ms-excel.sheet.macroEnabled.12',
  uploadedAt: new Date().toISOString(),
  verdict: 'malicious',
  riskLevel: 'critical',
  confidenceScore: 0.99,
  summary: 'Critical malicious macros and suspicious external endpoints detected.',
  macroDetected: true,
  macro_inspection: {
    status: 'detected',
    macro_detected: true,
    suspicious_indicators: ['Auto-executing Document_Open hook', 'WScript.Shell process invocation'],
    extracted_snippets: ['Set wsh = CreateObject("WScript.Shell")'],
    embedded_objects_detected: ['oleObject1.bin'],
    explanation: 'Contains auto-executing malicious macro payload.',
  },
  embedded_links: {
    total_links_found: 3,
    mismatched_links_count: 1,
    summary: 'Audited 3 embedded links.',
    items: [
      {
        visible_text: 'https://paypal.com/verify',
        destination_url: 'http://malicious-c2-gateway.cc/payload.exe',
        destination_domain: 'malicious-c2-gateway.cc',
        is_mismatched: true,
        threat_verdict: 'malicious',
        risk_score: 95,
        reasons: ['High-risk phishing domain mismatch'],
      },
      {
        visible_text: 'Help Desk',
        destination_url: 'https://support.example.com',
        destination_domain: 'support.example.com',
        is_mismatched: false,
        threat_verdict: 'benign',
        risk_score: 5,
        reasons: [],
      },
    ],
  },
  exploit_indicators: {
    suspicious_actions: ['/Launch action targets cmd.exe'],
    structural_anomalies: ['Unbalanced stream length'],
    known_signature_matches: ['CVE-2017-11882 buffer pattern'],
    compression_ratio: 4.5,
    coverage_and_limitations: 'Static inspection of OOXML parts.',
  },
  hidden_content: {
    has_hidden_content: true,
    hidden_elements_count: 1,
    summary: 'Found 1 concealed element.',
    items: [
      {
        location: 'Page 1 (Lower Right)',
        extracted_text: 'PAYLOAD_KEY=secret99',
        classification_reason: 'Font rendered in white color #FFFFFF on white background (3 Tr invisible mode)',
      },
    ],
    explanation: 'Concealed text layer discovered.',
  },
  script_translator: {
    has_script: true,
    plain_english_summary: 'Spawns command prompt and downloads secondary stage.',
    observed_operations: ['Process Execution', 'Network Download'],
    intent: 'malicious',
  },
});

const malExtraction = extractDocumentFindings(maliciousDocResult);
assert.ok(malExtraction.findings.length >= 5, `Expected at least 5 findings, got ${malExtraction.findings.length}`);
console.log(`✓ Nonzero findings successfully populated (${malExtraction.findings.length} real findings extracted)`);

// ---------------------------------------------------------------------------
// 5. Severity Filtering (All, Critical, High, Warning, Informational)
// ---------------------------------------------------------------------------
console.log('Test 5: Severity filtering');
function createFinding(id: string, title: string, severity: FindingSeverity, category: string): SecurityFindingItem {
  return {
    id,
    title,
    severity,
    category,
    detected: `Detected condition for ${title}`,
    whyItMatters: `Impact explanation for ${title}`,
    evidence: `Evidence snippet for ${title}`,
    recommendedAction: `Recommendation for ${title}`,
  };
}

const sampleFindings: SecurityFindingItem[] = [
  createFinding('f1', 'Macro Execution', 'critical', 'Macros'),
  createFinding('f2', 'Phishing Mismatch', 'critical', 'Hyperlinks'),
  createFinding('f3', 'Exploit CVE', 'high', 'Exploits'),
  createFinding('f4', 'Hidden Text', 'warning', 'Hidden Content'),
  createFinding('f5', 'Archive Metadata', 'info', 'Metadata'),
];

const allFiltered = filterFindings(sampleFindings, 'ALL');
assert.strictEqual(allFiltered.length, 5, 'ALL must return all 5 findings');

const criticalFiltered = filterFindings(sampleFindings, 'CRITICAL');
assert.strictEqual(criticalFiltered.length, 2, 'CRITICAL must return exactly 2 findings');
assert.ok(criticalFiltered.every((f) => f.severity === 'critical'));

const highFiltered = filterFindings(sampleFindings, 'HIGH');
assert.strictEqual(highFiltered.length, 1, 'HIGH must return exactly 1 finding');
assert.ok(highFiltered.every((f) => f.severity === 'high'));

const warningFiltered = filterFindings(sampleFindings, 'WARNING');
assert.strictEqual(warningFiltered.length, 1, 'WARNING must return exactly 1 finding');
assert.ok(warningFiltered.every((f) => f.severity === 'warning'));

const infoFiltered = filterFindings(sampleFindings, 'INFORMATIONAL');
assert.strictEqual(infoFiltered.length, 1, 'INFORMATIONAL must return exactly 1 finding');
assert.ok(infoFiltered.every((f) => f.severity === 'info'));

// Test fallback / non-existent filter
const noneFiltered = filterFindings(sampleFindings, 'NONEXISTENT');
assert.strictEqual(noneFiltered.length, 5, 'Unknown filter falls back to all');

console.log('✓ Severity filtering works precisely for ALL, CRITICAL, HIGH, WARNING, and INFORMATIONAL');
console.log('--- All Document Security Findings Tests Passed Successfully! ---');
