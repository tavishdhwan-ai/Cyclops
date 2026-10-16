"""
Feature 8: Macro-to-English Script Translator
Translates suspicious extracted code and macro operations into clear, plain-language explanations.
Distinguishes observed static operations from inferred intent.
"""
from typing import List, Dict, Any, Optional
from app.schemas import ScriptTranslationResult, MacroInspectionResult

# Translation dictionary mapping observed operations to plain-language descriptions
OPERATION_TRANSLATIONS = [
    (
        r"(?i)\b(?:autoopen|auto_open|document_open|workbook_open|autoexec)\b",
        "Auto-Execution on Open",
        "The script automatically triggers execution immediately when the document is opened, without requiring user interaction.",
    ),
    (
        r"(?i)\b(?:wscript\.shell|shell\.application|createobject\s*\(\s*[\"']wscript\.shell[\"']\s*\))",
        "System Shell Spawning",
        "Static analysis found code that appears to spawn a system command interpreter (WScript.Shell).",
    ),
    (
        r"(?i)\b(?:cmd\.exe|powershell(?:\.exe)?|mshta(?:\.exe)?|cscript(?:\.exe)?|rundll32(?:\.exe)?)",
        "Command-Line Process Launch",
        "The script invokes external command line binaries or PowerShell to run system commands.",
    ),
    (
        r"(?i)\b(?:urldownloadtofile|msxml2\.xmlhttp|winhttp\.winhttprequest)",
        "Remote File Download Attempt",
        "Static analysis found code that appears to retrieve an external file or payload from a remote server.",
    ),
    (
        r"(?i)\b(?:environ\s*\(\s*[\"'](?:temp|appdata)[\"']\s*\))",
        "Payload Staging in Temp Directory",
        "The script accesses the local system %TEMP% or %APPDATA% directory, typically used to stage downloaded payloads before execution.",
    ),
    (
        r"(?i)(?:chr(?:w)?\s*\(\s*\d+\s*\)\s*&\s*){3,}",
        "Character Code Obfuscation",
        "The script uses chained character code conversion (Chr/ChrW) to disguise URLs, commands, or executable payloads from static scanners.",
    ),
    (
        r"(?i)\bstrreverse\s*\(",
        "String Reversal Obfuscation",
        "The script reverses character order to conceal readable keywords from signature inspection.",
    ),
    (
        r"(?i)\b(?:kill\s+|scripting\.filesystemobject)",
        "Local File Deletion or Modification",
        "The script contains routines to alter, delete, or inspect files on the local filesystem.",
    ),
]


def translate_macro_script(
    macro_result: MacroInspectionResult,
    raw_snippets: Optional[List[str]] = None
) -> ScriptTranslationResult:
    """
    Translates observed macro operations into plain-English behavioral descriptions.
    """
    res = ScriptTranslationResult()

    if not macro_result.macro_detected:
        res.has_script = False
        res.language = "None"
        res.plain_english_summary = "No macro code or active automation routines were found in this document."
        return res

    res.has_script = True
    res.language = "VBA (Visual Basic for Applications)"

    snippets_to_scan = (raw_snippets or []) + macro_result.extracted_snippets

    observed_ops = []
    evidence_lines = []

    # Match rules against snippets and indicators
    all_text = " ".join(snippets_to_scan) + " " + " ".join(macro_result.suspicious_indicators)

    import re
    for pattern, title, explanation in OPERATION_TRANSLATIONS:
        if re.search(pattern, all_text):
            observed_ops.append(f"{title}: {explanation}")

    for snip in snippets_to_scan[:6]:
        evidence_lines.append(snip)

    res.observed_operations = observed_ops
    res.evidence_lines = evidence_lines

    # Synthesize plain-language summary
    if any("Process Launch" in op or "Shell Spawning" in op for op in observed_ops) and any("Download" in op for op in observed_ops):
        res.plain_english_summary = (
            "Static analysis found code that appears to launch a command-line process and attempt to download a file from an external server."
        )
    elif any("Process Launch" in op or "Shell Spawning" in op for op in observed_ops):
        res.plain_english_summary = (
            "Static analysis found code designed to launch external system commands or scripts without user intervention."
        )
    elif any("Download" in op for op in observed_ops):
        res.plain_english_summary = (
            "Static analysis identified routines designed to reach out over the network and retrieve external remote content."
        )
    elif observed_ops:
        res.plain_english_summary = (
            f"Static analysis identified automation routines including: {observed_ops[0].split(':')[0]}."
        )
    else:
        res.plain_english_summary = (
            "The document contains embedded macro structures, but static analysis did not identify known dangerous system calls or remote download patterns."
        )

    res.inferred_intent_warning = (
        "This translation describes observed static operations. "
        "It does not claim that a file was successfully downloaded or malware was executed, "
        "as no code was run in an execution environment."
    )

    return res
