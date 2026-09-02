import re

import httpx

from app.models.result import Finding
from app.scanners.rate_limiter import RateLimiter

HTTP_TIMEOUT = 5.0
CATEGORY = "HTTP Security"

REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}

HTTP_SECURITY_HEADERS = {
    "content-security-policy": {
        "id": "HTTP-MISSING-CSP",
        "display_name": "Content-Security-Policy",
        "title": "Missing Content-Security-Policy Header",
        "description": (
            "Content-Security-Policy helps prevent cross-site scripting (XSS), "
            "data injection, and other content-based attacks by restricting which "
            "resources the browser is allowed to load."
        ),
        "severity": "MEDIUM",
        "category": CATEGORY,
        "recommendation": (
            "Define a Content-Security-Policy header that restricts script, style, "
            "and resource sources to trusted origins appropriate for your application."
        ),
    },
    "strict-transport-security": {
        "id": "HTTP-MISSING-HSTS",
        "display_name": "Strict-Transport-Security",
        "title": "Missing Strict-Transport-Security Header",
        "description": (
            "Strict-Transport-Security (HSTS) instructs browsers to connect only over "
            "HTTPS, reducing the risk of protocol downgrade and man-in-the-middle attacks."
        ),
        "severity": "MEDIUM",
        "category": CATEGORY,
        "recommendation": (
            "Add a Strict-Transport-Security header with an appropriate max-age value "
            "for HTTPS endpoints."
        ),
    },
    "x-content-type-options": {
        "id": "HTTP-MISSING-X-CONTENT-TYPE-OPTIONS",
        "display_name": "X-Content-Type-Options",
        "title": "Missing X-Content-Type-Options Header",
        "description": (
            "X-Content-Type-Options prevents browsers from MIME-sniffing a response "
            "away from the declared content type, which can reduce certain attack surfaces."
        ),
        "severity": "LOW",
        "category": CATEGORY,
        "recommendation": (
            'Set X-Content-Type-Options to "nosniff" for HTTP responses.'
        ),
    },
    "x-frame-options": {
        "id": "HTTP-MISSING-X-FRAME-OPTIONS",
        "title": "Missing X-Frame-Options Header",
        "display_name": "X-Frame-Options",
        "description": (
            "X-Frame-Options helps protect against clickjacking by controlling whether "
            "the page can be embedded in frames on other sites."
        ),
        "severity": "LOW",
        "category": CATEGORY,
        "recommendation": (
            'Set X-Frame-Options to "DENY" or "SAMEORIGIN", '
            "or use frame-ancestors in CSP."
        ),
    },
    "referrer-policy": {
        "id": "HTTP-MISSING-REFERRER-POLICY",
        "display_name": "Referrer-Policy",
        "title": "Missing Referrer-Policy Header",
        "description": (
            "Referrer-Policy controls how much referrer information is sent with requests, "
            "helping protect user privacy and reduce unintended information leakage."
        ),
        "severity": "LOW",
        "category": CATEGORY,
        "recommendation": (
            "Set an appropriate Referrer-Policy such as "
            "strict-origin-when-cross-origin or no-referrer."
        ),
    },
}

SERVER_VERSION_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9+._-]*/\S+|\d+\.\d+")


def _response_headers(response: httpx.Response) -> dict[str, str]:
    return {
        name.lower(): value
        for name, value in response.headers.items()
    }


def _parse_cookie_name(cookie_header: str) -> str:
    return cookie_header.split("=", 1)[0].strip()


def _cookie_has_attribute(cookie_header: str, attribute: str) -> bool:
    attributes = cookie_header.split(";")[1:]
    attribute = attribute.lower()
    return any(
        part.strip().lower() == attribute
        or part.strip().lower().startswith(f"{attribute}=")
        for part in attributes
    )


def _check_missing_security_headers(
    host: str,
    port: int,
    service_name: str,
    response_headers: dict[str, str],
) -> list[Finding]:
    findings: list[Finding] = []

    for header_name, header_info in HTTP_SECURITY_HEADERS.items():
        if service_name == "HTTP" and header_name == "strict-transport-security":
            continue

        if header_name in response_headers:
            continue

        findings.append(
            Finding(
                id=header_info["id"],
                title=f"{header_info['title']} (port {port})",
                description=header_info["description"],
                severity=header_info["severity"],
                category=header_info["category"],
                recommendation=header_info["recommendation"],
                target=host,
                port=port,
                evidence=(
                    f"{service_name} response from port {port} did not include the "
                    f"{header_info['display_name']} header."
                ),
            )
        )

    return findings


def _check_server_disclosure(
    host: str,
    port: int,
    service_name: str,
    server_header: str | None,
) -> list[Finding]:
    if not server_header or not server_header.strip():
        return []

    server_value = server_header.strip()
    if server_value == "*":
        return []

    exposes_product_or_version = (
        "/" in server_value
        or SERVER_VERSION_PATTERN.search(server_value) is not None
        or server_value.isalnum()
    )
    if not exposes_product_or_version:
        return []

    return [
        Finding(
            id="HTTP-SERVER-DISCLOSURE",
            title=f"Server Header Information Disclosure (port {port})",
            description=(
                "The Server response header can reveal software product or version "
                "information that may help attackers fingerprint the application stack."
            ),
            severity="LOW",
            category=CATEGORY,
            recommendation=(
                "Consider minimizing or genericizing the Server header in production "
                "environments."
            ),
            target=host,
            port=port,
            evidence=(
                f"{service_name} response from port {port} included a Server header "
                f"identifying '{server_value}'."
            ),
        )
    ]


def _check_cookie_security(
    host: str,
    port: int,
    service_name: str,
    set_cookie_headers: list[str],
) -> list[Finding]:
    if not set_cookie_headers or service_name != "HTTPS":
        return []

    missing_secure: list[str] = []
    missing_httponly: list[str] = []
    missing_samesite: list[str] = []

    for cookie_header in set_cookie_headers:
        cookie_name = _parse_cookie_name(cookie_header)
        if not cookie_name:
            continue

        if not _cookie_has_attribute(cookie_header, "secure"):
            missing_secure.append(cookie_name)
        if not _cookie_has_attribute(cookie_header, "httponly"):
            missing_httponly.append(cookie_name)
        if not _cookie_has_attribute(cookie_header, "samesite"):
            missing_samesite.append(cookie_name)

    findings: list[Finding] = []

    if missing_secure:
        findings.append(
            Finding(
                id="HTTP-COOKIE-MISSING-SECURE",
                title=f"Cookie Missing Secure Attribute (port {port})",
                description=(
                    "Cookies served over HTTPS should include the Secure attribute so "
                    "browsers only send them over encrypted connections."
                ),
                severity="MEDIUM",
                category=CATEGORY,
                recommendation=(
                    "Add the Secure attribute to sensitive cookies served over HTTPS."
                ),
                target=host,
                port=port,
                evidence=(
                    f"HTTPS response from port {port} set cookie(s) without the Secure "
                    f"attribute: {', '.join(missing_secure)}."
                ),
            )
        )

    if missing_httponly:
        findings.append(
            Finding(
                id="HTTP-COOKIE-MISSING-HTTPONLY",
                title=f"Cookie Missing HttpOnly Attribute (port {port})",
                description=(
                    "The HttpOnly attribute helps prevent client-side scripts from "
                    "accessing cookie values."
                ),
                severity="LOW",
                category=CATEGORY,
                recommendation="Add the HttpOnly attribute to sensitive cookies.",
                target=host,
                port=port,
                evidence=(
                    f"HTTPS response from port {port} set cookie(s) without the HttpOnly "
                    f"attribute: {', '.join(missing_httponly)}."
                ),
            )
        )

    if missing_samesite:
        findings.append(
            Finding(
                id="HTTP-COOKIE-MISSING-SAMESITE",
                title=f"Cookie Missing SameSite Attribute (port {port})",
                description=(
                    "The SameSite attribute helps reduce cross-site request risks by "
                    "controlling when cookies are sent with cross-origin requests."
                ),
                severity="LOW",
                category=CATEGORY,
                recommendation=(
                    "Set an appropriate SameSite value such as Lax or Strict for cookies."
                ),
                target=host,
                port=port,
                evidence=(
                    f"HTTPS response from port {port} set cookie(s) without the SameSite "
                    f"attribute: {', '.join(missing_samesite)}."
                ),
            )
        )

    return findings


def _check_https_redirect(
    host: str,
    port: int,
    response: httpx.Response,
) -> list[Finding]:
    if response.status_code in REDIRECT_STATUS_CODES:
        location = response.headers.get("location", "").strip()
        if location.lower().startswith("https://"):
            return []

    return [
        Finding(
            id="HTTP-NO-HTTPS-REDIRECT",
            title=f"No HTTPS Redirect Configured (port {port})",
            description=(
                "The HTTP service did not redirect clients to HTTPS. Serving content over "
                "plain HTTP can expose traffic to interception when HTTPS is available."
            ),
            severity="LOW",
            category=CATEGORY,
            recommendation=(
                "Configure the service to redirect HTTP requests to the equivalent HTTPS "
                "endpoint where appropriate."
            ),
            target=host,
            port=port,
            evidence=(
                f"HTTP response from port {port} did not redirect to an HTTPS location."
            ),
        )
    ]


def _check_trace_enabled(
    host: str,
    port: int,
    service_name: str,
    url: str,
    *,
    rate_limiter: RateLimiter | None = None,
) -> list[Finding]:
    try:
        if rate_limiter is not None:
            rate_limiter.acquire()

        options_response = httpx.request(
            "OPTIONS",
            url,
            timeout=HTTP_TIMEOUT,
            follow_redirects=False,
        )
    except httpx.HTTPError:
        return []

    allow_header = options_response.headers.get("allow", "")
    allowed_methods = {
        method.strip().upper()
        for method in allow_header.split(",")
        if method.strip()
    }

    if "TRACE" not in allowed_methods:
        return []

    return [
        Finding(
            id="HTTP-TRACE-ENABLED",
            title=f"TRACE Method Advertised (port {port})",
            description=(
                "The service advertises the TRACE HTTP method. TRACE is rarely needed in "
                "production and has historically been associated with cross-site tracing risks."
            ),
            severity="LOW",
            category=CATEGORY,
            recommendation=(
                "Disable the TRACE method unless it is explicitly required."
            ),
            target=host,
            port=port,
            evidence=(
                f"{service_name} service on port {port} advertised TRACE in the Allow "
                "response header."
            ),
        )
    ]


def scan_http_service(
    host: str,
    port: int,
    service_name: str,
    *,
    rate_limiter: RateLimiter | None = None,
) -> list[Finding]:
    if service_name not in ("HTTP", "HTTPS"):
        return []

    scheme = "https" if service_name == "HTTPS" else "http"
    url = f"{scheme}://{host}:{port}"

    try:
        if rate_limiter is not None:
            rate_limiter.acquire()

        response = httpx.get(
            url,
            timeout=HTTP_TIMEOUT,
            follow_redirects=False,
        )
    except httpx.HTTPError:
        return []

    response_headers = _response_headers(response)
    set_cookie_headers = response.headers.get_list("set-cookie")

    findings: list[Finding] = []
    findings.extend(
        _check_missing_security_headers(host, port, service_name, response_headers)
    )
    findings.extend(
        _check_server_disclosure(
            host,
            port,
            service_name,
            response_headers.get("server"),
        )
    )
    findings.extend(
        _check_cookie_security(host, port, service_name, set_cookie_headers)
    )

    if service_name == "HTTP":
        findings.extend(_check_https_redirect(host, port, response))

    findings.extend(
        _check_trace_enabled(
            host,
            port,
            service_name,
            url,
            rate_limiter=rate_limiter,
        )
    )

    return findings
