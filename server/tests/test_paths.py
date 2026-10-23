from __future__ import annotations

import pytest

from app.detection.paths import executable_from_command, is_startup_folder, is_user_writable, normalize_path


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Users\alice\AppData\Local\Temp\x.exe",
        r"c:\windows\temp\a\b.dll",
        r"C:\Users\Public\tool.exe",
        r"C:\ProgramData\evil.exe",
        r"C:\$Recycle.Bin\S-1-5\x.exe",
        r"C:\Users\alice\AppData\Roaming\svchost.exe",
        r'"C:\Users\alice\AppData\Local\Temp\x.exe" /quiet',
        r"\??\C:\Users\Public\x.exe",
    ],
)
def test_user_writable_paths(path: str) -> None:
    assert is_user_writable(path)


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Program Files\App\app.exe",
        r"C:\Windows\System32\svchost.exe",
        r"C:\Users\alice\AppData\Local\Discord\app-1.0\Discord.exe",  # per-user installs are normal
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",  # subfolders are normal
        r"C:\Users\alice\AppData\Roaming\Vendor\tool.exe",
        "",
    ],
)
def test_not_user_writable_paths(path: str) -> None:
    assert not is_user_writable(path)


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (r'"C:\Program Files\Example\svc.exe" -k', r"c:\program files\example\svc.exe"),
        (r"C:\Windows\system32\svchost.exe -k netsvcs", r"c:\windows\system32\svchost.exe"),
        (r"C:\Program Files\No Quotes\app.exe /run", r"c:\program files\no quotes\app.exe"),
        (r"\??\C:\Windows\system32\drivers\x.sys", r"c:\windows\system32\drivers\x.sys"),
        ("", ""),
    ],
)
def test_executable_from_command(command: str, expected: str) -> None:
    assert executable_from_command(command) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (r"C:\Program Files\Git\mingw64\bin\x.dll", r"C:\Program Files\Git\usr\bin\sh.exe", True),
        (r"C:\Users\a\AppData\Local\Vendor\hook.dll", r"C:\Users\a\AppData\Local\Vendor\app\v.exe", True),
        (r"C:\Users\a\AppData\Local\Temp\hook.dll", r"C:\Users\a\AppData\Local\Temp\updater.exe", False),  # Temp is generic
        (r"C:\Windows\System32\a.dll", r"C:\Windows\System32\b.exe", False),
        (r"C:\Program Files\Git\x.dll", r"C:\Program Files\Other\y.exe", False),
        (r"C:\Users\a\Downloads\x.dll", r"C:\Users\a\Downloads\y.exe", False),
        ("", r"C:\x.exe", False),
    ],
)
def test_same_installation(a: str, b: str, expected: bool) -> None:
    from app.detection.paths import same_installation

    assert same_installation(a, b) is expected


def test_startup_folder_and_normalize() -> None:
    assert is_startup_folder(r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk")
    assert not is_startup_folder(r"C:\Users\a\Desktop\x.lnk")
    assert normalize_path('"C:\\A B\\c.exe" arg') == "c:\\a b\\c.exe"
