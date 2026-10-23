"""Positive and negative cases for every detection rule, through the real pipeline."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session, sessionmaker

from tests.detection_harness import Harness, at
from tests.helpers import (
    GUID_A,
    GUID_B,
    GUID_C,
    TEMP_EXE,
    build_event,
    file_create,
    image_load,
    load_fixture,
    network,
    proc_create,
    process_access,
    registry_set,
    service_install,
)

PROGRAM_EXE = r"C:\Program Files\Vendor\app.exe"
RUN_KEY = r"HKU\S-1-5-21-1000\Software\Microsoft\Windows\CurrentVersion\Run\Updater"


@pytest.fixture
def h(session_factory: sessionmaker[Session]) -> Harness:
    return Harness(session_factory)


# ------------------------------------------------------------ KG-EXEC-001


def test_exec_001_fires_for_temp_image(h: Harness) -> None:
    h.run(proc_create())
    [alert] = h.alerts("KG-EXEC-001")
    assert alert.severity == "low" and alert.confidence == "low"
    assert alert.image == TEMP_EXE
    kinds = {o["kind"] for o in alert.observations}
    assert kinds == {"observed", "inferred"}
    assert any("code-signing" in u for u in alert.uncertainty)


def test_exec_001_ignores_program_files(h: Harness) -> None:
    h.run(proc_create(image=PROGRAM_EXE))
    assert h.alerts("KG-EXEC-001") == []


# ------------------------------------------------------------- KG-DRV-001


def test_drv_001_fires_for_unsigned_driver(h: Harness) -> None:
    xml = load_fixture("sysmon_6_driver_load.xml").replace(">true<", ">false<").replace(">Valid<", ">Unavailable<")
    h.run(xml)
    [alert] = h.alerts("KG-DRV-001")
    assert alert.severity == "high"
    assert any("BYOVD" in u for u in alert.uncertainty)


def test_drv_001_ignores_validly_signed_driver(h: Harness) -> None:
    h.run(load_fixture("sysmon_6_driver_load.xml"))
    assert h.alerts("KG-DRV-001") == []


# --------------------------------------------------------- KG-PERSIST-001


def test_persist_001_run_key_to_temp_is_high(h: Harness) -> None:
    h.run(registry_set(RUN_KEY, TEMP_EXE))
    [alert] = h.alerts("KG-PERSIST-001")
    assert (alert.severity, alert.confidence) == ("high", "medium")
    assert alert.mitre[0]["technique_id"] == "T1547.001" and alert.mitre[0]["relationship"] == "observed"
    assert any(f["factor"] == "adjustment" and "user-writable" in f["reason"] for f in alert.score_breakdown)


def test_persist_001_ordinary_run_key_stays_medium_low(h: Harness) -> None:
    h.run(registry_set(RUN_KEY.replace("Updater", "Vendor"), f'"{PROGRAM_EXE}" --minimized', image=PROGRAM_EXE))
    [alert] = h.alerts("KG-PERSIST-001")
    assert (alert.severity, alert.confidence) == ("medium", "low")
    assert not [f for f in alert.score_breakdown if f["factor"] == "adjustment"]


def test_persist_001_ignores_other_keys(h: Harness) -> None:
    h.run(registry_set(r"HKU\S-1-5-21-1000\Software\Vendor\Settings\Theme", "dark"))
    assert h.alerts("KG-PERSIST-001") == []


def test_persist_001_encoded_powershell_adjustment(h: Harness) -> None:
    h.run(registry_set(RUN_KEY, "powershell.exe -nop -enc SQBFAFgA"))
    [alert] = h.alerts("KG-PERSIST-001")
    reasons = [f["reason"] for f in alert.score_breakdown if f["factor"] == "adjustment"]
    assert any("powershell.exe" in r for r in reasons) and any("encoded" in r for r in reasons)


# --------------------------------------------------------- KG-PERSIST-002


def test_persist_002_startup_folder(h: Harness) -> None:
    h.run(load_fixture("sysmon_11_file_create.xml"))
    assert len(h.alerts("KG-PERSIST-002")) == 1


def test_persist_002_ignores_desktop_ini_and_other_paths(h: Harness) -> None:
    h.run(
        file_create(r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini"),
        file_create(r"C:\Users\a\Documents\report.lnk"),
    )
    assert h.alerts("KG-PERSIST-002") == []


# --------------------------------------------------------- KG-PERSIST-003


@pytest.mark.parametrize(
    ("image_path", "reason_fragment"),
    [
        (r"C:\Users\alice\AppData\Local\Temp\svc.exe", "user-writable"),
        (r"%COMSPEC% /c echo x > \\.\pipe\p", "%COMSPEC%"),
        (r"cmd.exe /c powershell -enc AAAA", "cmd.exe"),
        (r"\\fileserver\share\svc.exe", "UNC"),
    ],
)
def test_persist_003_suspicious_service(h: Harness, image_path: str, reason_fragment: str) -> None:
    h.run(service_install("BadSvc", image_path), channel="System")
    [alert] = h.alerts("KG-PERSIST-003")
    reasons = " ".join(f.get("reason", "") for f in alert.score_breakdown)
    assert reason_fragment in reasons
    assert any("7045 does not identify" in u for u in alert.uncertainty)


def test_persist_003_ignores_normal_service(h: Harness) -> None:
    h.run(load_fixture("system_7045_service_install.xml"), channel="System")
    assert h.alerts("KG-PERSIST-003") == []


# --------------------------------------------------------- KG-PERSIST-004


@pytest.mark.parametrize(
    ("target", "details", "technique"),
    [
        (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger",
         r"C:\Windows\System32\cmd.exe", "T1546.012"),
        (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", f"explorer.exe,{TEMP_EXE}", "T1547.004"),
        (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs", r"C:\Users\Public\x.dll", "T1546.010"),
    ],
)
def test_persist_004_hijack_points(h: Harness, target: str, details: str, technique: str) -> None:
    h.run(registry_set(target, details))
    [alert] = h.alerts("KG-PERSIST-004")
    assert alert.mitre[0]["technique_id"] == technique


def test_persist_004_ignores_default_winlogon_values(h: Harness) -> None:
    h.run(
        registry_set(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", "explorer.exe"),
        registry_set(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs", "(Empty)"),
    )
    assert h.alerts("KG-PERSIST-004") == []


def test_persist_004_com_hijack_is_consistent_with_and_low_confidence(h: Harness) -> None:
    h.run(registry_set(r"HKU\S-1-5-21-1000\Software\Classes\CLSID\{1234}\InprocServer32\(Default)", r"C:\Users\Public\x.dll"))
    [alert] = h.alerts("KG-PERSIST-004")
    assert alert.confidence == "low" and alert.mitre[0]["relationship"] == "consistent_with"


# --------------------------------------------------------- KG-PERSIST-005


def test_persist_005_command_line_consumer_is_high(h: Harness) -> None:
    h.run(build_event(20, {"EventType": "WmiConsumerEvent", "Operation": "Created", "User": "alice",
                           "Name": "Updater", "Type": "Command Line", "Destination": TEMP_EXE}))
    [alert] = h.alerts("KG-PERSIST-005")
    assert alert.severity == "high"


def test_persist_005_ignores_filter_only_events(h: Harness) -> None:
    h.run(build_event(19, {"EventType": "WmiFilterEvent", "Operation": "Created", "Name": "f", "Query": "SELECT 1"}))
    assert h.alerts("KG-PERSIST-005") == []


# ---------------------------------------------------- KG-INJ-001 / CRED / INJ-002


def test_inj_001_unbacked_remote_thread_is_high(h: Harness) -> None:
    h.run(load_fixture("sysmon_8_remote_thread.xml"))
    [alert] = h.alerts("KG-INJ-001")
    assert alert.severity == "high"
    assert alert.mitre[0]["relationship"] == "consistent_with"
    assert any(e.startswith("process:guid:host-1:{3f1b2c4d-0e11") for e in alert.entities)  # target process


def test_inj_001_ignores_system_sources(h: Harness) -> None:
    xml = load_fixture("sysmon_8_remote_thread.xml").replace(TEMP_EXE, r"C:\Windows\System32\csrss.exe")
    h.run(xml)
    assert h.alerts("KG-INJ-001") == []


def test_cred_001_lsass_read_with_unknown_calltrace_is_critical(h: Harness) -> None:
    h.run(load_fixture("sysmon_10_process_access.xml"))
    [alert] = h.alerts("KG-CRED-001")
    assert alert.severity == "critical"
    assert h.alerts("KG-INJ-002") == []  # lsass is covered by CRED-001 only


@pytest.mark.parametrize(
    "xml",
    [
        process_access(r"C:\Windows\system32\lsass.exe", "0x1000"),  # query-limited only
        process_access(r"C:\Windows\system32\lsass.exe", "0x1010",
                       image=r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"),
        process_access(r"C:\Windows\system32\lsass.exe", "zz"),  # malformed mask
    ],
    ids=["query-limited", "defender", "malformed-mask"],
)
def test_cred_001_negative(h: Harness, xml: str) -> None:
    h.run(xml)
    assert h.alerts("KG-CRED-001") == []


def test_inj_002_unbacked_access_to_other_process(h: Harness) -> None:
    h.run(process_access(r"C:\Windows\explorer.exe", "0x1fffff", call_trace=r"ntdll.dll+1|UNKNOWN(0000020000001000)"))
    assert len(h.alerts("KG-INJ-002")) == 1


def test_inj_002_ignores_backed_call_trace(h: Harness) -> None:
    h.run(process_access(r"C:\Windows\explorer.exe", "0x1fffff"))
    assert h.alerts("KG-INJ-002") == []


@pytest.mark.parametrize("mask", ["0x1000", "0x101401", "0x1410", "zz"],
                         ids=["query-limited", "query+sync+dup (VS Code)", "query+vm-read", "malformed"])
def test_inj_002_ignores_handles_that_cannot_inject(h: Harness, mask: str) -> None:
    """Regression (live 2026-10-24): 175 alerts in 9 min from JIT runtimes opening query-only handles."""
    h.run(process_access(r"C:\Windows\explorer.exe", mask, call_trace="ntdll.dll+1|UNKNOWN(1)"))
    assert h.alerts("KG-INJ-002") == []


@pytest.mark.parametrize("mask", ["0x0020", "0x0008", "0x0002", "0x1f3fff"], ids=["vm-write", "vm-operation", "create-thread", "all-ish"])
def test_inj_002_fires_for_injection_capable_rights(h: Harness, mask: str) -> None:
    h.run(process_access(r"C:\Windows\explorer.exe", mask, call_trace="ntdll.dll+1|UNKNOWN(1)"))
    assert len(h.alerts("KG-INJ-002")) == 1


def test_inj_002_ignores_sibling_instances_of_same_program(h: Harness) -> None:
    code = r"C:\Program Files\Microsoft VS Code\Code.exe"
    h.run(process_access(code, "0x1fffff", call_trace="UNKNOWN(1)", image=code))
    assert h.alerts("KG-INJ-002") == []


def test_inj_002_one_alert_per_program_pair(h: Harness) -> None:
    h.run(*[process_access(r"C:\Windows\explorer.exe", "0x1fffff", call_trace="UNKNOWN(1)",
                           guid=f"{{00000000-0000-0000-0000-{i:012d}}}") for i in range(5)])
    [alert] = h.alerts("KG-INJ-002")
    assert alert.occurrence_count == 5


def test_inj_002_ignores_parent_handle_to_its_own_child(h: Harness) -> None:
    """Regression (live 2026-10-24): JIT parents holding the full handle CreateProcess returns."""
    child = build_event(1, {"ProcessGuid": "{cccccccc-0000-0000-0000-000000000003}", "ProcessId": "720",
                            "Image": r"C:\Windows\explorer.exe", "ParentProcessGuid": GUID_A, "ParentProcessId": "7432",
                            "ParentImage": TEMP_EXE})
    h.run((child, at(0)), (process_access(r"C:\Windows\explorer.exe", "0x1fffff", call_trace="UNKNOWN(1)"), at(1)))
    assert h.alerts("KG-INJ-002") == []


def test_spy_001_ignores_dotnet_native_images(h: Harness) -> None:
    dll = r"C:\Windows\assembly\NativeImages_v4.0.30319_64\System\b0b1\System.ni.dll"
    h.run(*[image_load(dll, f"{{00000000-0000-0000-0000-{i:012d}}}", rf"C:\Program Files\App{i}\a.exe") for i in range(5)])
    assert h.alerts("KG-SPY-001") == []


def test_inj_001_ignores_winlogon_to_csrss(h: Harness) -> None:
    h.run(load_fixture("sysmon_8_remote_thread.xml").replace(TEMP_EXE, r"C:\Windows\System32\winlogon.exe"))
    assert h.alerts("KG-INJ-001") == []


def test_inj_001_ignores_backed_thread_into_same_program(h: Harness) -> None:
    code = r"C:\Program Files\Microsoft VS Code\Code.exe"
    xml = (load_fixture("sysmon_8_remote_thread.xml").replace(TEMP_EXE, code).replace(r"C:\Windows\explorer.exe", code)
           .replace("<Data Name='StartModule'>-</Data>", f"<Data Name='StartModule'>{code}</Data>"))
    h.run(xml)
    assert h.alerts("KG-INJ-001") == []


def test_inj_001_keeps_unbacked_thread_into_same_program(h: Harness) -> None:
    code = r"C:\Program Files\Microsoft VS Code\Code.exe"
    h.run(load_fixture("sysmon_8_remote_thread.xml").replace(TEMP_EXE, code).replace(r"C:\Windows\explorer.exe", code))
    assert len(h.alerts("KG-INJ-001")) == 1


# ------------------------------------------------------- KG-NET-001 / 002


def test_net_001_public_connection_from_temp(h: Harness) -> None:
    h.run(network())
    assert len(h.alerts("KG-NET-001")) == 1


@pytest.mark.parametrize(
    "xml",
    [
        network(ip="192.168.1.5"),  # private
        network(ip="203.0.113.50"),  # documentation range is not global
        network(initiated="false"),  # inbound
        network(image=PROGRAM_EXE),
    ],
    ids=["private-ip", "documentation-range", "inbound", "program-files"],
)
def test_net_001_negative(h: Harness, xml: str) -> None:
    h.run(xml)
    assert h.alerts("KG-NET-001") == []


def test_net_002_powershell_to_internet(h: Harness) -> None:
    h.run(network(guid=GUID_B, image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"))
    [alert] = h.alerts("KG-NET-002")
    assert alert.mitre[0]["technique_id"] == "T1059.001"


@pytest.mark.parametrize("image", [r"C:\Windows\System32\curl.exe", r"C:\Windows\System32\msiexec.exe"])
def test_net_002_excludes_curl_and_msiexec(h: Harness, image: str) -> None:
    h.run(network(guid=GUID_B, image=image))
    assert h.alerts("KG-NET-002") == []


# ------------------------------------------------------ KG-FILE-001 / 002


def test_file_001_executable_in_temp_is_informational(h: Harness) -> None:
    h.run(file_create(r"C:\Users\alice\AppData\Local\Temp\payload.exe"))
    [alert] = h.alerts("KG-FILE-001")
    assert alert.severity == "informational"


def test_file_001_ignores_powershell_policy_test_artifact(h: Harness) -> None:
    """Regression (live 2026-10-24): 10 alerts in 9 min, one per PowerShell start."""
    pwsh = r"C:\Program Files\PowerShell\7\pwsh.exe"
    h.run(file_create(r"C:\Users\kolhe\AppData\Local\Temp\__PSScriptPolicyTest_ouiccgxb.5c2.ps1", image=pwsh),
          file_create(r"C:\Users\kolhe\AppData\Local\Temp\__PSScriptPolicyTest_vektwqr0.jq1.psm1", image=pwsh))
    assert h.alerts("KG-FILE-001") == []


def test_file_001_policy_test_name_from_other_process_still_alerts(h: Harness) -> None:
    h.run(file_create(r"C:\Users\kolhe\AppData\Local\Temp\__PSScriptPolicyTest_ouiccgxb.5c2.ps1"))  # written by updater.exe
    assert len(h.alerts("KG-FILE-001")) == 1


def test_file_001_ignores_non_executables(h: Harness) -> None:
    h.run(file_create(r"C:\Users\alice\AppData\Local\Temp\notes.txt"))
    assert h.alerts("KG-FILE-001") == []


def test_file_002_drop_then_execute(h: Harness) -> None:
    dropped = r"C:\Users\alice\AppData\Local\Temp\payload.exe"
    h.run((file_create(dropped, guid=GUID_B, image=r"C:\Windows\explorer.exe"), at(10)),
          (proc_create(guid=GUID_C, image=dropped), at(40)))
    [alert] = h.alerts("KG-FILE-002")
    assert alert.occurrence_count == 1
    assert "30s later" in " ".join(o["text"] for o in alert.observations)


def test_file_002_out_of_order_delivery(h: Harness) -> None:
    """Execution event stored before the file-creation event that precedes it in time."""
    dropped = r"C:\Users\alice\AppData\Local\Temp\late.exe"
    h.run((proc_create(guid=GUID_C, image=dropped), at(40)))
    assert h.alerts("KG-FILE-002") == []
    h.run((file_create(dropped, guid=GUID_B, image=r"C:\Windows\explorer.exe"), at(10)))
    assert len(h.alerts("KG-FILE-002")) == 1


def test_file_002_different_path_no_match(h: Harness) -> None:
    h.run((file_create(r"C:\Users\alice\AppData\Local\Temp\a.exe"), at(10)),
          (proc_create(guid=GUID_C, image=r"C:\Users\alice\AppData\Local\Temp\b.exe"), at(20)))
    assert h.alerts("KG-FILE-002") == []


# -------------------------------------------------------- KG-SPY-001 / 002

HOOK_DLL = r"C:\Users\alice\AppData\Local\Temp\kbhook.dll"


def test_spy_001_same_unsigned_dll_in_three_processes(h: Harness) -> None:
    h.run(*[(image_load(HOOK_DLL, guid, rf"C:\Windows\app{i}.exe"), at(i)) for i, guid in enumerate([GUID_A, GUID_B, GUID_C])])
    [alert] = h.alerts("KG-SPY-001")
    assert alert.confidence == "low"
    assert {m["relationship"] for m in alert.mitre} == {"consistent_with"}
    assert any("SetWindowsHookEx" in u for u in alert.uncertainty)


def test_spy_001_joins_incident_of_a_loading_process(h: Harness) -> None:
    """Regression: the hook-DLL alert must correlate with alerts on the processes
    that loaded it (found during UI testing: it formed a separate incident)."""
    h.run(
        (proc_create(guid=GUID_A), at(0)),  # KG-EXEC-001 on updater.exe
        *[(image_load(HOOK_DLL, guid, rf"C:\Windows\app{i}.exe"), at(5 + i)) for i, guid in enumerate([GUID_A, GUID_B, GUID_C])],
    )
    [spy] = h.alerts("KG-SPY-001")
    [exec_alert] = h.alerts("KG-EXEC-001")
    assert spy.incident_id == exec_alert.incident_id
    assert len(h.incidents()) == 1


def test_spy_001_below_threshold(h: Harness) -> None:
    h.run(*[image_load(HOOK_DLL, guid, "x.exe") for guid in (GUID_A, GUID_B)])
    assert h.alerts("KG-SPY-001") == []


def test_spy_001_ignores_signed_system_dll(h: Harness) -> None:
    dll = r"C:\Windows\System32\msctf.dll"
    h.run(*[image_load(dll, guid, "x.exe", signed="true") for guid in (GUID_A, GUID_B, GUID_C)])
    assert h.alerts("KG-SPY-001") == []


def test_spy_001_respects_threshold_override(session_factory: sessionmaker[Session]) -> None:
    from app.detection.config import DetectionConfig, RuleOverride

    config = DetectionConfig(rules={"KG-SPY-001": RuleOverride(thresholds={"min_programs": 2})})
    h = Harness(session_factory, config=config)
    h.run(*[image_load(HOOK_DLL, guid, rf"C:\Windows\app{i}.exe") for i, guid in enumerate((GUID_A, GUID_B))])
    assert len(h.alerts("KG-SPY-001")) == 1


# ---- Tuning regressions from live measurement (2026-10-24) -----------------

GIT_DLL = r"C:\Program Files\Git\mingw64\bin\libiconv-2.dll"


def test_spy_001_ignores_many_instances_of_one_program(h: Harness) -> None:
    guids = [f"{{00000000-0000-0000-0000-{i:012d}}}" for i in range(10)]
    h.run(*[image_load(HOOK_DLL, g, r"C:\Program Files\Git\mingw64\bin\git.exe") for g in guids])
    assert h.alerts("KG-SPY-001") == []


def test_spy_001_ignores_programs_from_the_dlls_own_installation(h: Harness) -> None:
    images = [
        r"C:\Program Files\Git\mingw64\bin\git.exe",
        r"C:\Program Files\Git\mingw64\libexec\git-core\git-remote-https.exe",
        r"C:\Program Files\Git\usr\bin\sh.exe",
        r"C:\Program Files\Git\mingw64\bin\gpg.exe",
    ]
    h.run(*[image_load(GIT_DLL, f"{{00000000-0000-0000-0000-{i:012d}}}", img) for i, img in enumerate(images)])
    assert h.alerts("KG-SPY-001") == []


def test_spy_001_counts_foreign_programs_and_reports_excluded_own_loads(h: Harness) -> None:
    dll = r"C:\Users\alice\AppData\Local\Vendor\hook.dll"
    loaders = [
        r"C:\Users\alice\AppData\Local\Vendor\vendor.exe",  # own installation: not counted
        r"C:\Windows\notepad.exe",
        r"C:\Windows\explorer.exe",
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
    ]
    h.run(*[image_load(dll, f"{{00000000-0000-0000-0000-{i:012d}}}", img, signed="false") for i, img in enumerate(loaders)])
    [alert] = h.alerts("KG-SPY-001")
    assert "3 unrelated programs" in alert.title
    assert "1 load(s) by programs in the DLL's own folder were not counted" in alert.observations[0]["text"]


def test_spy_002_correlated_cluster(h: Harness) -> None:
    h.run(
        (proc_create(), at(0)),                     # executable (user-writable)
        (registry_set(RUN_KEY, TEMP_EXE), at(5)),   # persistence
        (network(), at(10)),                        # network
    )
    [alert] = h.alerts("KG-SPY-002")
    [incident] = h.incidents()
    assert alert.incident_id == incident.id
    assert alert.severity == "high"
    assert any("not proof of malware" in u for u in alert.uncertainty)


def test_spy_002_requires_persistence(h: Harness) -> None:
    h.run((proc_create(), at(0)), (network(), at(10)),
          (process_access(r"C:\Windows\explorer.exe", "0x1fffff", call_trace="UNKNOWN(1)"), at(20)))
    assert h.alerts("KG-SPY-002") == []


def test_spy_002_requires_three_categories(h: Harness) -> None:
    h.run((proc_create(), at(0)), (registry_set(RUN_KEY, TEMP_EXE), at(5)))
    assert h.alerts("KG-SPY-002") == []


def test_disabled_rule_does_not_fire(session_factory: sessionmaker[Session]) -> None:
    from app.detection.config import DetectionConfig, RuleOverride

    h = Harness(session_factory, config=DetectionConfig(rules={"KG-EXEC-001": RuleOverride(enabled=False)}))
    h.run(proc_create())
    assert h.alerts("KG-EXEC-001") == []


def test_every_rule_has_metadata() -> None:
    from app.detection.rules import RULES_BY_ID

    for rule in RULES_BY_ID.values():
        meta = rule.meta
        assert meta.rationale and meta.required_evidence and meta.false_positives, meta.rule_id
        assert meta.category in {"executable", "persistence", "injection", "network", "file", "spyware"}
