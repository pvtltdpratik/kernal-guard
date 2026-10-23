"""Stable host identification."""

from __future__ import annotations

import socket
import sys


def machine_guid() -> str | None:
    """Windows MachineGuid (read-only registry access). Survives hostname changes."""
    if sys.platform != "win32":
        return None
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            return str(value).lower()
    except OSError:
        return None


def resolve_host_id(configured: str | None) -> str:
    return configured or machine_guid() or socket.gethostname().lower()
