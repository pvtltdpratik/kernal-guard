"""Path and binary classification used by rules.

These are heuristics about *where* a file lives, not judgements about the
file. Every match is reported as an observation, never as proof.
"""

from __future__ import annotations

import ntpath
import re

# Locations writable by standard users where legitimately installed software
# rarely executes from. AppData\Local\<Vendor> is deliberately excluded:
# per-user installers (Squirrel, Electron apps) run from there routinely.
_USER_WRITABLE = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"^[a-z]:\\users\\[^\\]+\\appdata\\local\\temp\\",
        r"^[a-z]:\\windows\\temp\\",
        r"^[a-z]:\\users\\public\\",
        r"^[a-z]:\\programdata\\[^\\]+\.(exe|dll|scr|ps1|vbs|js|bat|cmd|hta)$",  # files directly in ProgramData
        r"^[a-z]:\\\$recycle\.bin\\",
        r"^[a-z]:\\perflogs\\",
        r"\\appdata\\roaming\\[^\\]+\.(exe|dll|scr)$",  # binaries directly in Roaming root
    )
]

_DOWNLOADS = re.compile(r"^[a-z]:\\users\\[^\\]+\\downloads\\", re.IGNORECASE)
_STARTUP_FOLDER = re.compile(r"\\start menu\\programs\\startup\\", re.IGNORECASE)

EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx"}
SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".bat", ".cmd", ".wsf"}

# Built-in binaries frequently used to run or fetch code (LOLBins).
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe"}
PROXY_EXECUTION = {"rundll32.exe", "regsvr32.exe", "msiexec.exe", "installutil.exe", "regasm.exe", "regsvcs.exe"}
# curl.exe ships with Windows and is in everyday developer use; it is
# deliberately not treated as a LOLBin downloader.
DOWNLOADERS = {"certutil.exe", "bitsadmin.exe"}


def basename(path: str | None) -> str:
    return ntpath.basename(path or "").lower()


def normalize_path(path: str | None) -> str:
    """Lower-case, strip quotes/arguments, expand the common \\??\\ prefix."""
    if not path:
        return ""
    text = path.strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        text = text[1:end] if end > 0 else text[1:]
    text = re.sub(r"^\\\?\?\\", "", text)
    return text.lower()


def executable_from_command(command: str | None) -> str:
    """First token of a command line / service ImagePath, as a normalised path."""
    if not command:
        return ""
    text = command.strip()
    if text.startswith('"'):
        return normalize_path(text)
    match = re.match(r"^(.+?\.(exe|dll|sys|com|bat|cmd|ps1|vbs|js|hta))\b", text, re.IGNORECASE)
    return normalize_path(match.group(1) if match else text.split(" ")[0])


def is_user_writable(path: str | None) -> bool:
    normalized = normalize_path(path)
    return any(p.search(normalized) for p in _USER_WRITABLE)


def is_downloads(path: str | None) -> bool:
    return bool(_DOWNLOADS.search(normalize_path(path)))


def is_startup_folder(path: str | None) -> bool:
    return bool(_STARTUP_FOLDER.search(normalize_path(path)))


# Directories that hold many unrelated programs: sharing one of these does not
# make two files part of the same installation.
_GENERIC_CONTAINERS = re.compile(
    r"^[a-z]:(\\(windows(\\(system32|syswow64))?|program files( \(x86\))?|programdata"
    r"|users(\\[^\\]+(\\(appdata(\\(local|roaming|locallow)(\\temp)?)?|downloads|desktop|documents))?)?))?$",
    re.IGNORECASE,
)


def same_installation(path_a: str | None, path_b: str | None) -> bool:
    """True when both files live under one application's own folder, e.g.
    ``C:\\Program Files\\Git\\...`` — not merely under Temp or System32."""
    a, b = ntpath.dirname(normalize_path(path_a)), ntpath.dirname(normalize_path(path_b))
    if not a or not b:
        return False
    common = ntpath.commonpath([a, b])
    return common.count("\\") >= 2 and not _GENERIC_CONTAINERS.match(common)


def extension(path: str | None) -> str:
    return ntpath.splitext(normalize_path(path))[1]


def is_executable_or_script(path: str | None) -> bool:
    ext = extension(path)
    return ext in EXECUTABLE_EXTENSIONS or ext in SCRIPT_EXTENSIONS
