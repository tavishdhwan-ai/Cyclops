"""
SSL/TLS Certificate Intelligence Inspector for Cyclops URL Scanner.

Safely retrieves, inspects, and validates website TLS certificates.
Enforces:
- Strict SSRF protection on destination IP before establishing connection.
- Strict connection and handshake timeouts.
- Safe parsing of certificate metadata: Issuer, Subject, SANs, Validity window, Expiry.
- Chain validation and public CA detection.
- Honest error reporting: never fabricates identity, never guesses if verification fails.
- Explicit security context: HTTPS guarantees transport encryption, NOT business legitimacy.
"""
import ssl
import socket
import ipaddress
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from app.scanner.ssrf import resolve_and_validate_hostname, SSRFValidationError, is_ip_blocked


# Commonly trusted public Certificate Authority organization/common names
PUBLIC_CA_SIGNATURES = [
    "let's encrypt", "digicert", "sectigo", "godaddy", "globalsign",
    "google trust services", "amazon", "cloudflare", "identrust",
    "entrust", "certum", "comodo", "verisign", "usertrust", "geotrust",
    "baltimore cybertrust", "quovadis", "buypass", "actalis", "zerossl",
    "trustwave", "ssl.com", "swissign", "harica"
]


class SslCertificateIntelligence(BaseModel):
    hostname: str
    port: int = 443
    status: str  # "valid", "expired", "hostname_mismatch", "self_signed", "untrusted", "unencrypted_http", "unable_to_verify"
    connection_status: str  # "HTTPS (TLS Encrypted)", "HTTP (Unencrypted)", "TLS Handshake Failed", "Connection Refused"
    is_valid: bool = False
    is_public_ca: bool = False
    issuer: str = "Unknown"
    issuer_org: Optional[str] = None
    subject: str = "Unknown"
    subject_org: Optional[str] = None
    subject_alt_names: List[str] = Field(default_factory=list)
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    days_remaining: Optional[int] = None
    hostname_match: bool = False
    certificate_chain_status: str = "unverified"  # "valid_trusted", "expired", "hostname_mismatch", "self_signed", "untrusted_root", "none"
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    plain_language_explanation: str = "HTTPS encrypts your connection, but it does not guarantee that this website is legitimate."
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


def _parse_x509_name(name_tuple: tuple) -> Dict[str, str]:
    """Extracts CN, O, OU from ssl cert tuple format: ((('commonName', 'val'),), ...)."""
    result = {}
    if not name_tuple:
        return result
    for rdn in name_tuple:
        for key, val in rdn:
            result[key] = val
    return result


def _matches_hostname(hostname: str, san_list: List[str], common_name: str) -> bool:
    """Case-insensitive wildcard and exact hostname matching."""
    norm_host = hostname.strip().lower()
    candidates = [cn.strip().lower() for cn in san_list]
    if common_name:
        candidates.append(common_name.strip().lower())

    for pattern in candidates:
        if pattern == norm_host:
            return True
        if pattern.startswith("*."):
            suffix = pattern[2:]
            host_parts = norm_host.split(".")
            if len(host_parts) >= 2 and norm_host.endswith("." + suffix):
                if norm_host.count(".") == pattern.count("."):
                    return True
    return False


async def inspect_tls_certificate(
    hostname: str,
    port: int = 443,
    is_https: bool = True,
    ip_override: Optional[str] = None,
    timeout: float = 4.0
) -> SslCertificateIntelligence:
    """
    Safely inspects TLS certificate for hostname without exposing the host to SSRF attacks.
    Executes socket connection directly to validated IP.
    """
    clean_host = hostname.strip().lower().strip("[]")

    if not is_https:
        return SslCertificateIntelligence(
            hostname=clean_host,
            port=port,
            status="unencrypted_http",
            connection_status="HTTP (Unencrypted)",
            is_valid=False,
            certificate_chain_status="none",
            plain_language_explanation="The target site was queried over unencrypted HTTP. Data sent to or from this page can be intercepted or modified in transit.",
            warnings=["No TLS encryption in use. Passwords, tokens, and sensitive inputs can be viewed by network eavesdroppers."],
            limitations=["Certificate inspection does not apply to plaintext HTTP connections."]
        )

    # 1. SSRF Validation on destination IP
    safe_ip: Optional[str] = None
    if ip_override:
        try:
            ip_obj = ipaddress.ip_address(ip_override)
            blocked, reason = is_ip_blocked(ip_obj)
            if blocked:
                return SslCertificateIntelligence(
                    hostname=clean_host,
                    port=port,
                    status="unable_to_verify",
                    connection_status="Connection Blocked",
                    plain_language_explanation=f"TLS certificate check blocked: IP address is in a private/restricted network range ({reason}).",
                    warnings=["Target IP blocked by SSRF defense policy."]
                )
            safe_ip = ip_override
        except ValueError:
            pass

    if not safe_ip:
        try:
            resolved = resolve_and_validate_hostname(clean_host)
            safe_ip = resolved[0]
        except SSRFValidationError as e:
            return SslCertificateIntelligence(
                hostname=clean_host,
                port=port,
                status="unable_to_verify",
                connection_status="Connection Blocked",
                plain_language_explanation=f"TLS inspection blocked: {str(e)}",
                warnings=[f"SSRF violation: {str(e)}"]
            )
        except Exception as e:
            return SslCertificateIntelligence(
                hostname=clean_host,
                port=port,
                status="unable_to_verify",
                connection_status="Unable to resolve host",
                plain_language_explanation="Unable to resolve hostname to inspect TLS certificate.",
                warnings=[f"DNS resolution failure: {str(e)}"]
            )

    # 2. Establish TLS Connection with default validating context
    ctx = ssl.create_default_context()
    raw_cert = None
    tls_version = None
    cipher_suite = None
    verification_error = None
    is_valid_chain = False

    try:
        with socket.create_connection((safe_ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                raw_cert = ssock.getpeercert()
                tls_version = ssock.version()
                cipher_tuple = ssock.cipher()
                cipher_suite = cipher_tuple[0] if cipher_tuple else None
                is_valid_chain = True
    except ssl.SSLCertVerificationError as e:
        verification_error = str(e)
        # Attempt fallback to unverified context strictly to inspect peer certificate fields for user visibility
        try:
            unverified_ctx = ssl._create_unverified_context()
            with socket.create_connection((safe_ip, port), timeout=timeout) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                    raw_cert = ssock.getpeercert(binary_form=False)
                    tls_version = ssock.version()
                    cipher_tuple = ssock.cipher()
                    cipher_suite = cipher_tuple[0] if cipher_tuple else None
        except Exception:
            pass
    except (socket.timeout, TimeoutError):
        return SslCertificateIntelligence(
            hostname=clean_host,
            port=port,
            status="unable_to_verify",
            connection_status="TLS Connection Timed Out",
            plain_language_explanation="Unable to verify certificate: Server did not complete TLS handshake within timeout.",
            warnings=["TLS handshake timed out after 4 seconds."]
        )
    except ConnectionRefusedError:
        return SslCertificateIntelligence(
            hostname=clean_host,
            port=port,
            status="unable_to_verify",
            connection_status="Connection Refused",
            plain_language_explanation="Unable to verify certificate: Port 443 refused connection.",
            warnings=["Server refused HTTPS connection on port 443."]
        )
    except Exception as exc:
        return SslCertificateIntelligence(
            hostname=clean_host,
            port=port,
            status="unable_to_verify",
            connection_status="TLS Handshake Failed",
            plain_language_explanation=f"Unable to verify certificate: {type(exc).__name__}",
            warnings=[str(exc)]
        )

    # If no certificate could be obtained even in fallback
    if not raw_cert:
        return SslCertificateIntelligence(
            hostname=clean_host,
            port=port,
            status="unable_to_verify",
            connection_status="TLS Handshake Failed",
            plain_language_explanation="Unable to retrieve certificate details from target server.",
            warnings=[verification_error or "TLS peer provided no extractable certificate."]
        )

    # 3. Extract Certificate Details
    issuer_dict = _parse_x509_name(raw_cert.get("issuer", ()))
    subject_dict = _parse_x509_name(raw_cert.get("subject", ()))

    issuer_cn = issuer_dict.get("commonName", "Unknown Issuer")
    issuer_org = issuer_dict.get("organizationName")
    issuer_display = issuer_org or issuer_cn

    subject_cn = subject_dict.get("commonName", clean_host)
    subject_org = subject_dict.get("organizationName")
    subject_display = subject_org or subject_cn

    # SANs
    san_entries: List[str] = []
    for item in raw_cert.get("subjectAltName", ()):
        if item[0].lower() == "dns":
            san_entries.append(item[1])

    # Hostname matching
    hostname_match = _matches_hostname(clean_host, san_entries, subject_cn)

    # Validity Dates
    not_before_str = raw_cert.get("notBefore")
    not_after_str = raw_cert.get("notAfter")
    valid_from = None
    valid_until = None
    days_remaining = None
    is_expired = False

    if not_after_str:
        try:
            # Format: 'May  4 12:00:00 2025 GMT'
            exp_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            valid_until = exp_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            now_dt = datetime.now(timezone.utc)
            delta = exp_dt - now_dt
            days_remaining = delta.days
            if days_remaining < 0:
                is_expired = True
        except Exception:
            valid_until = not_after_str

    if not_before_str:
        try:
            nb_dt = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            valid_from = nb_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            valid_from = not_before_str

    # Public CA check
    combined_issuer = f"{issuer_display} {issuer_cn} {issuer_org or ''}".lower()
    is_public_ca = any(ca_sig in combined_issuer for ca_sig in PUBLIC_CA_SIGNATURES)

    # Determine status & chain assessment
    warnings: List[str] = []
    if is_expired:
        status = "expired"
        chain_status = "expired"
        warnings.append("The certificate has expired. Modern web browsers will block access with a security warning.")
    elif not hostname_match:
        status = "hostname_mismatch"
        chain_status = "hostname_mismatch"
        warnings.append(f"Certificate hostname mismatch: Hostname '{clean_host}' does not match certificate names ({', '.join(san_entries[:3]) or subject_cn}).")
    elif verification_error:
        if "self-signed" in verification_error.lower() or "self signed" in verification_error.lower():
            status = "self_signed"
            chain_status = "self_signed"
            warnings.append("Certificate is self-signed and was not issued by a recognized root certificate authority.")
        else:
            status = "untrusted"
            chain_status = "untrusted_root"
            warnings.append(f"Certificate chain validation failed: {verification_error}")
    else:
        status = "valid"
        chain_status = "valid_trusted"

    if days_remaining is not None and 0 <= days_remaining <= 14:
        warnings.append(f"Certificate will expire soon (in {days_remaining} day{'s' if days_remaining != 1 else ''}).")

    # Plain language explanation adheres strictly to user prompt requirements
    if status == "valid":
        plain_explanation = (
            "HTTPS encrypts your connection, but it does not guarantee that this website is legitimate. "
            "The certificate was issued by a recognized certificate authority and matches the requested hostname."
        )
    elif status == "expired":
        plain_explanation = (
            "The certificate for this domain has expired. While the connection may be encrypted, "
            "an expired certificate indicates poor maintenance or potential certificate hijacking."
        )
    elif status == "hostname_mismatch":
        plain_explanation = (
            f"The certificate presented by this server was issued for a different domain ({', '.join(san_entries[:2]) or subject_cn}) "
            f"and does not match '{clean_host}'. This can occur during man-in-the-middle attacks or server misconfiguration."
        )
    elif status == "self_signed":
        plain_explanation = (
            "This server uses a self-signed certificate not trusted by standard web authorities. "
            "Connection encryption exists, but the identity of the server cannot be independently verified."
        )
    else:
        plain_explanation = (
            "The TLS certificate could not be fully verified against public root stores. "
            "Proceed with caution before submitting sensitive data."
        )

    limitations = [
        "Free and automated domain-validation (DV) certificates are common and legitimate; DV certificates confirm domain control, not legal business identity.",
        "A valid TLS certificate does NOT establish that a website or organization is safe, trustworthy, or lawful."
    ]

    return SslCertificateIntelligence(
        hostname=clean_host,
        port=port,
        status=status,
        connection_status="HTTPS (TLS Encrypted)" if is_valid_chain else "HTTPS (Verification Issue)",
        is_valid=(status == "valid"),
        is_public_ca=is_public_ca,
        issuer=issuer_display,
        issuer_org=issuer_org,
        subject=subject_display,
        subject_org=subject_org,
        subject_alt_names=san_entries,
        valid_from=valid_from,
        valid_until=valid_until,
        days_remaining=days_remaining,
        hostname_match=hostname_match,
        certificate_chain_status=chain_status,
        tls_version=tls_version,
        cipher_suite=cipher_suite,
        plain_language_explanation=plain_explanation,
        warnings=warnings,
        limitations=limitations
    )
