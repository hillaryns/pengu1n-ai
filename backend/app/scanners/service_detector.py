import re
import socket
import ssl

from app.models.result import Service
from app.scanners.rate_limiter import RateLimiter

BANNER_TIMEOUT = 1.0
MAX_BANNER_BYTES = 512

HTTP_PORTS = {80, 8080, 8000}
LINE_BANNER_PORTS = {21, 22, 23, 25, 110, 143}

HTTP_PROBE = (
    b"GET / HTTP/1.0\r\n"
    b"Host: probe.local\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP",
    8000: "HTTP",
}


def _recv_banner(sock: socket.socket) -> bytes:
    try:
        return sock.recv(MAX_BANNER_BYTES)
    except (socket.timeout, OSError):
        return b""


def _decode_banner(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").strip()


def _extract_http_header(data: bytes, header_name: bytes) -> str | None:
    for line in data.split(b"\r\n"):
        if line.lower().startswith(header_name.lower()):
            _, _, value = line.partition(b":")
            value = value.strip().decode("utf-8", errors="replace")
            return value or None
    return None


def _parse_ssh_version(banner: str) -> str | None:
    match = re.match(r"SSH-\d+\.\d+-(.+)", banner)
    if not match:
        return None
    return match.group(1).strip() or None


def _parse_smtp_version(banner: str) -> str | None:
    if not banner.startswith("220"):
        return None
    return banner[3:].strip() or None


def _parse_ftp_version(banner: str) -> str | None:
    if not banner.startswith("220"):
        return None
    return banner[3:].strip() or None


def _probe_line_banner(
    host: str,
    port: int,
    *,
    rate_limiter: RateLimiter | None = None,
) -> Service | None:
    if rate_limiter is not None:
        rate_limiter.acquire()

    with socket.create_connection((host, port), timeout=BANNER_TIMEOUT) as sock:
        sock.settimeout(BANNER_TIMEOUT)
        banner = _decode_banner(_recv_banner(sock))
        if not banner:
            return None

        if banner.startswith("SSH-"):
            return Service(
                port=port,
                name="SSH",
                version=_parse_ssh_version(banner),
            )

        if banner.startswith("220"):
            if port == 21 or "ftp" in banner.lower():
                return Service(
                    port=port,
                    name="FTP",
                    version=_parse_ftp_version(banner),
                )
            if port == 25 or "smtp" in banner.lower() or "esmtp" in banner.lower():
                return Service(
                    port=port,
                    name="SMTP",
                    version=_parse_smtp_version(banner),
                )
            return Service(port=port, name=SERVICE_MAP.get(port, "SMTP"))

        if banner.startswith("+OK"):
            return Service(port=port, name="POP3", version=banner[3:].strip() or None)

        if banner.upper().startswith("* OK"):
            return Service(port=port, name="IMAP", version=banner[4:].strip() or None)

        if port == 23:
            return Service(port=port, name="Telnet", version=banner or None)

    return None


def _probe_http(
    host: str,
    port: int,
    *,
    use_tls: bool,
    rate_limiter: RateLimiter | None = None,
) -> Service | None:
    if rate_limiter is not None:
        rate_limiter.acquire()

    sock = socket.create_connection((host, port), timeout=BANNER_TIMEOUT)
    try:
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.settimeout(BANNER_TIMEOUT)
        sock.sendall(HTTP_PROBE)
        response = _recv_banner(sock)
    finally:
        sock.close()

    if b"HTTP/" not in response:
        return None

    return Service(
        port=port,
        name="HTTPS" if use_tls else "HTTP",
        version=_extract_http_header(response, b"Server:"),
    )


def _probe_mysql(
    host: str,
    port: int,
    *,
    rate_limiter: RateLimiter | None = None,
) -> Service | None:
    if rate_limiter is not None:
        rate_limiter.acquire()

    with socket.create_connection((host, port), timeout=BANNER_TIMEOUT) as sock:
        sock.settimeout(BANNER_TIMEOUT)
        data = _recv_banner(sock)

    if len(data) < 6:
        return None

    payload = data[4:]
    if payload[0] != 0x0A:
        return None

    null_index = payload.find(b"\x00", 1)
    if null_index == -1:
        return None

    version = payload[1:null_index].decode("utf-8", errors="replace").strip()
    if not version:
        return None

    return Service(port=port, name="MySQL", version=version)


def _identify_service(
    host: str,
    port: int,
    *,
    rate_limiter: RateLimiter | None = None,
) -> Service:
    fallback_name = SERVICE_MAP.get(port, f"Unknown service on port {port}")

    try:
        if port == 443:
            detected = _probe_http(host, port, use_tls=True, rate_limiter=rate_limiter)
        elif port in HTTP_PORTS:
            detected = _probe_http(host, port, use_tls=False, rate_limiter=rate_limiter)
        elif port == 3306:
            detected = _probe_mysql(host, port, rate_limiter=rate_limiter)
        elif port in LINE_BANNER_PORTS:
            detected = _probe_line_banner(host, port, rate_limiter=rate_limiter)
        else:
            detected = _probe_line_banner(host, port, rate_limiter=rate_limiter)

        if detected is not None:
            return detected
    except (socket.timeout, OSError, ssl.SSLError, UnicodeDecodeError):
        pass

    return Service(port=port, name=fallback_name)


def detect_services(
    host: str,
    open_ports: list[int],
    *,
    rate_limiter: RateLimiter | None = None,
) -> list[Service]:
    return [
        _identify_service(host, port, rate_limiter=rate_limiter)
        for port in open_ports
    ]
