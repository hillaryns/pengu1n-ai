from dataclasses import dataclass
from typing import Literal

ScanProfile = Literal["quick", "standard", "deep", "bug_bounty"]

COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    8080,  # HTTP alternate
    8000,  # development server
]

QUICK_PORTS = [
    22,    # SSH
    80,    # HTTP
    443,   # HTTPS
    8080,  # HTTP alternate
    8000,  # development server
]

DEEP_ADDITIONAL_PORTS = [
    135,    # MS RPC
    139,    # NetBIOS
    1433,   # MSSQL
    1521,   # Oracle
    2049,   # NFS
    3000,   # common dev server
    5000,   # common dev server
    5900,   # VNC
    6379,   # Redis
    8443,   # HTTPS alternate
    8888,   # HTTP alternate
    9000,   # common application port
    27017,  # MongoDB
    9200,   # Elasticsearch
]


@dataclass(frozen=True)
class ProfileConfig:
    name: ScanProfile
    ports: tuple[int, ...]
    enable_http_scan: bool
    enable_tls_scan: bool
    requests_per_second: float | None = None


def get_profile_config(profile: ScanProfile) -> ProfileConfig:
    if profile == "quick":
        return ProfileConfig(
            name="quick",
            ports=tuple(QUICK_PORTS),
            enable_http_scan=True,
            enable_tls_scan=False,
        )

    if profile == "deep":
        ports = tuple(sorted(set(COMMON_PORTS) | set(DEEP_ADDITIONAL_PORTS)))
        return ProfileConfig(
            name="deep",
            ports=ports,
            enable_http_scan=True,
            enable_tls_scan=True,
        )

    if profile == "bug_bounty":
        return ProfileConfig(
            name="bug_bounty",
            ports=tuple(COMMON_PORTS),
            enable_http_scan=True,
            enable_tls_scan=True,
            requests_per_second=2.0,
        )

    return ProfileConfig(
        name="standard",
        ports=tuple(COMMON_PORTS),
        enable_http_scan=True,
        enable_tls_scan=True,
    )
