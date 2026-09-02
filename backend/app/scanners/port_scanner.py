import socket

from app.scanners.rate_limiter import RateLimiter
from app.scanners.scan_profiles import COMMON_PORTS


def scan_ports(
    target: str,
    ports: list[int] | None = None,
    *,
    rate_limiter: RateLimiter | None = None,
) -> list[int]:
    open_ports = []
    ports_to_scan = ports if ports is not None else COMMON_PORTS

    for port in ports_to_scan:
        if rate_limiter is not None:
            rate_limiter.acquire()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        try:
            result = sock.connect_ex((target, port))

            if result == 0:
                open_ports.append(port)

        except (socket.timeout, socket.gaierror, OSError):
            pass

        finally:
            sock.close()

    return open_ports
