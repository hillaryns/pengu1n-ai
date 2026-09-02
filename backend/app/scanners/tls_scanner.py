import ipaddress
import socket
import ssl
from datetime import datetime, timezone

from app.models.result import Finding
from app.scanners.rate_limiter import RateLimiter

TLS_TIMEOUT = 5.0
CATEGORY = "TLS Security"


def _parse_cert_datetime(value: str) -> datetime:
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )


def _get_certificate(
    host: str,
    port: int,
    *,
    rate_limiter: RateLimiter | None = None,
) -> dict | None:
    try:
        if rate_limiter is not None:
            rate_limiter.acquire()

        pem_cert = ssl.get_server_certificate((host, port), timeout=TLS_TIMEOUT)
        der_cert = ssl.PEM_cert_to_DER_cert(pem_cert)
        return ssl._ssl._test_decode_cert(der_cert)
    except (OSError, ssl.SSLError, ValueError, IndexError):
        return None


def _hostname_matches_certificate(host: str, cert: dict) -> bool:
    host_lower = host.lower()

    for san_type, san_value in cert.get("subjectAltName", ()):
        if san_type == "DNS" and san_value.lower() == host_lower:
            return True
        if san_type == "IP Address":
            try:
                if ipaddress.ip_address(san_value) == ipaddress.ip_address(host):
                    return True
            except ValueError:
                continue

    for rdn in cert.get("subject", ()):
        for attribute, value in rdn:
            if attribute == "commonName" and value.lower() == host_lower:
                return True

    return False


def _certificate_expired(cert: dict, now: datetime) -> bool:
    not_after = cert.get("notAfter")
    if not not_after:
        return False

    return _parse_cert_datetime(not_after) < now


def _certificate_not_yet_valid(cert: dict, now: datetime) -> bool:
    not_before = cert.get("notBefore")
    if not not_before:
        return False

    return _parse_cert_datetime(not_before) > now


def _check_tls_version(host: str, tls_version: str | None, port: int) -> list[Finding]:
    if not tls_version:
        return []

    if tls_version in ("TLSv1.2", "TLSv1.3"):
        return [
            Finding(
                id="TLS-MODERN-VERSION",
                title=f"TLS {tls_version} Negotiated (port {port})",
                description=(
                    f"The service negotiated {tls_version}, which is a modern TLS "
                    "protocol version suitable for secure communications."
                ),
                severity="INFO",
                category=CATEGORY,
                recommendation=(
                    "Continue using modern TLS versions and disable legacy protocol "
                    "versions where possible."
                ),
                target=host,
                port=port,
                evidence=(
                    f"TLS handshake on {host}:{port} negotiated {tls_version}."
                ),
            )
        ]

    return [
        Finding(
            id="TLS-OBSOLETE-VERSION",
            title=f"Obsolete TLS Version Negotiated (port {port})",
            description=(
                f"The service negotiated {tls_version}. Older TLS versions have known "
                "security weaknesses and are deprecated for production use."
            ),
            severity="MEDIUM",
            category=CATEGORY,
            recommendation=(
                "Disable TLS 1.0 and TLS 1.1, and configure the service to use TLS 1.2 "
                "or TLS 1.3 only."
            ),
            target=host,
            port=port,
            evidence=(
                f"TLS handshake on {host}:{port} negotiated {tls_version}."
            ),
        )
    ]


def _check_certificate_validity(
    host: str,
    cert: dict | None,
    port: int,
    *,
    hostname_verified: bool,
) -> list[Finding]:
    if cert is None:
        return [
            Finding(
                id="TLS-CERTIFICATE-UNAVAILABLE",
                title=f"TLS Certificate Unavailable (port {port})",
                description=(
                    "The scanner could not retrieve a TLS certificate from the service. "
                    "This may indicate a misconfigured or incomplete TLS setup."
                ),
                severity="HIGH",
                category=CATEGORY,
                recommendation=(
                    "Ensure the HTTPS service presents a valid TLS certificate during "
                    "the handshake."
                ),
                target=host,
                port=port,
                evidence=(
                    f"TLS handshake on {host}:{port} completed without a retrievable "
                    "certificate."
                ),
            )
        ]

    findings: list[Finding] = []
    now = datetime.now(timezone.utc)

    if _certificate_not_yet_valid(cert, now):
        not_before = cert.get("notBefore", "unknown date")
        findings.append(
            Finding(
                id="TLS-CERTIFICATE-NOT-YET-VALID",
                title=f"TLS Certificate Not Yet Valid (port {port})",
                description=(
                    "The presented TLS certificate is not yet valid. Clients may reject "
                    "the connection until the certificate becomes active."
                ),
                severity="HIGH",
                category=CATEGORY,
                recommendation=(
                    "Install a certificate whose validity period includes the current date."
                ),
                target=host,
                port=port,
                evidence=(
                    f"TLS certificate presented on {host}:{port} is not valid before "
                    f"{not_before}."
                ),
            )
        )

    if _certificate_expired(cert, now):
        not_after = cert.get("notAfter", "unknown date")
        findings.append(
            Finding(
                id="TLS-EXPIRED-CERTIFICATE",
                title=f"Expired TLS Certificate (port {port})",
                description=(
                    "The presented TLS certificate has expired. Browsers and clients may "
                    "block or warn users about the connection."
                ),
                severity="HIGH",
                category=CATEGORY,
                recommendation=(
                    "Renew the TLS certificate and reload it on the service."
                ),
                target=host,
                port=port,
                evidence=(
                    f"TLS certificate presented on {host}:{port} expired on {not_after}."
                ),
            )
        )

    if not hostname_verified and not _hostname_matches_certificate(host, cert):
        findings.append(
            Finding(
                id="TLS-HOSTNAME-MISMATCH",
                title=f"TLS Certificate Hostname Mismatch (port {port})",
                description=(
                    f"The certificate presented by the service does not match the "
                    f"scanned host '{host}'."
                ),
                severity="MEDIUM",
                category=CATEGORY,
                recommendation=(
                    "Issue a certificate whose subject or Subject Alternative Name "
                    "matches the hostname clients use to reach the service."
                ),
                target=host,
                port=port,
                evidence=(
                    f"TLS certificate presented on {host}:{port} does not include "
                    f"'{host}' in its subject or SAN entries."
                ),
            )
        )

    return findings


def _get_tls_version(
    host: str,
    port: int,
    *,
    verify: bool,
    rate_limiter: RateLimiter | None = None,
) -> str | None:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        if rate_limiter is not None:
            rate_limiter.acquire()

        with socket.create_connection((host, port), timeout=TLS_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                return tls_sock.version()
    except (ssl.SSLError, socket.timeout, OSError):
        return None


def scan_tls_service(
    host: str,
    port: int,
    *,
    rate_limiter: RateLimiter | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    negotiated_version: str | None = None
    verified_cert: dict | None = None
    hostname_verified = False

    context = ssl.create_default_context()

    try:
        if rate_limiter is not None:
            rate_limiter.acquire()

        with socket.create_connection((host, port), timeout=TLS_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                negotiated_version = tls_sock.version()
                verified_cert = tls_sock.getpeercert()
                hostname_verified = True
    except ssl.SSLCertVerificationError:
        negotiated_version = _get_tls_version(
            host,
            port,
            verify=False,
            rate_limiter=rate_limiter,
        )
        verified_cert = _get_certificate(host, port, rate_limiter=rate_limiter)
    except (ssl.SSLError, socket.timeout, OSError):
        return findings

    if negotiated_version is None:
        negotiated_version = _get_tls_version(
            host,
            port,
            verify=False,
            rate_limiter=rate_limiter,
        )

    if verified_cert is None:
        verified_cert = _get_certificate(host, port, rate_limiter=rate_limiter)

    findings.extend(_check_tls_version(host, negotiated_version, port))
    findings.extend(
        _check_certificate_validity(
            host,
            verified_cert,
            port,
            hostname_verified=hostname_verified,
        )
    )

    return findings
