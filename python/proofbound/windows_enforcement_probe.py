"""Qualify the native Windows host for EXP-0023 without running workloads."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import platform
import sys
import uuid
from typing import Any

from proofbound.windows_enforcement_execute import canonical_json, domain_hash


PROBE_SCHEMA = "proofbound-research-windows-host-probe/1"
PROCESSOR_ARCHITECTURE_ARM64 = 12
TOKEN_ALL_ACCESS = 0x000F01FF
DISABLE_MAX_PRIVILEGE = 0x1
TOKEN_INTEGRITY_LEVEL = 25
SE_GROUP_INTEGRITY = 0x20
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000


class SidAndAttributes(ctypes.Structure):
    """Windows SID_AND_ATTRIBUTES."""

    _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]


class TokenMandatoryLabel(ctypes.Structure):
    """Windows TOKEN_MANDATORY_LABEL."""

    _fields_ = [("label", SidAndAttributes)]


class IoCounters(ctypes.Structure):
    """Windows IO_COUNTERS."""

    _fields_ = [
        ("read_operation_count", ctypes.c_uint64),
        ("write_operation_count", ctypes.c_uint64),
        ("other_operation_count", ctypes.c_uint64),
        ("read_transfer_count", ctypes.c_uint64),
        ("write_transfer_count", ctypes.c_uint64),
        ("other_transfer_count", ctypes.c_uint64),
    ]


class JobBasicLimitInformation(ctypes.Structure):
    """Windows JOBOBJECT_BASIC_LIMIT_INFORMATION."""

    _fields_ = [
        ("per_process_user_time_limit", ctypes.c_int64),
        ("per_job_user_time_limit", ctypes.c_int64),
        ("limit_flags", wintypes.DWORD),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority_class", wintypes.DWORD),
        ("scheduling_class", wintypes.DWORD),
    ]


class JobExtendedLimitInformation(ctypes.Structure):
    """Windows JOBOBJECT_EXTENDED_LIMIT_INFORMATION."""

    _fields_ = [
        ("basic_limit_information", JobBasicLimitInformation),
        ("io_info", IoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    ]


def _windows_error(operation: str) -> OSError:
    return ctypes.WinError(ctypes.get_last_error(), operation)


def _require(result: object, operation: str) -> None:
    if not result:
        raise _windows_error(operation)


def _hresult(result: int, operation: str) -> None:
    if result != 0:
        raise OSError(result & 0xFFFFFFFF, operation)


def _native_probe() -> dict[str, Any]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.CreateRestrictedToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.CreateRestrictedToken.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.GetLengthSid.argtypes = [wintypes.LPVOID]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    advapi32.SetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    advapi32.SetTokenInformation.restype = wintypes.BOOL
    advapi32.FreeSid.argtypes = [wintypes.LPVOID]
    advapi32.FreeSid.restype = wintypes.LPVOID

    userenv.CreateAppContainerProfile.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    userenv.CreateAppContainerProfile.restype = ctypes.c_long
    userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
    userenv.DeleteAppContainerProfile.restype = ctypes.c_long

    profile = f"proofbound.exp0023.{uuid.uuid4().hex}"
    appcontainer_sid = wintypes.LPVOID()
    token = wintypes.HANDLE()
    restricted = wintypes.HANDLE()
    integrity_sid = wintypes.LPVOID()
    job = wintypes.HANDLE()
    profile_created = False
    try:
        _hresult(
            userenv.CreateAppContainerProfile(
                profile,
                profile,
                "Proofbound EXP-0023 qualification",
                None,
                0,
                ctypes.byref(appcontainer_sid),
            ),
            "CreateAppContainerProfile",
        )
        profile_created = True
        _require(
            advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(), TOKEN_ALL_ACCESS, ctypes.byref(token)
            ),
            "OpenProcessToken",
        )
        _require(
            advapi32.CreateRestrictedToken(
                token,
                DISABLE_MAX_PRIVILEGE,
                0,
                None,
                0,
                None,
                0,
                None,
                ctypes.byref(restricted),
            ),
            "CreateRestrictedToken",
        )
        _require(
            advapi32.ConvertStringSidToSidW("S-1-16-4096", ctypes.byref(integrity_sid)),
            "ConvertStringSidToSidW",
        )
        label = TokenMandatoryLabel(
            label=SidAndAttributes(integrity_sid, SE_GROUP_INTEGRITY)
        )
        length = ctypes.sizeof(TokenMandatoryLabel) + advapi32.GetLengthSid(
            integrity_sid
        )
        _require(
            advapi32.SetTokenInformation(
                restricted,
                TOKEN_INTEGRITY_LEVEL,
                ctypes.byref(label),
                length,
            ),
            "SetTokenInformation(TokenIntegrityLevel)",
        )

        kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        job = kernel32.CreateJobObjectW(None, None)
        _require(job, "CreateJobObjectW")
        limits = JobExtendedLimitInformation()
        limits.basic_limit_information.limit_flags = (
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        limits.basic_limit_information.active_process_limit = 1
        _require(
            kernel32.SetInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
            ),
            "SetInformationJobObject",
        )
        required_exports = {
            "CreateProcessAsUserW": hasattr(advapi32, "CreateProcessAsUserW"),
            "SetNamedSecurityInfoW": hasattr(advapi32, "SetNamedSecurityInfoW"),
            "InitializeProcThreadAttributeList": hasattr(
                kernel32, "InitializeProcThreadAttributeList"
            ),
            "UpdateProcThreadAttribute": hasattr(kernel32, "UpdateProcThreadAttribute"),
            "AssignProcessToJobObject": hasattr(kernel32, "AssignProcessToJobObject"),
            "ResumeThread": hasattr(kernel32, "ResumeThread"),
        }
        if not all(required_exports.values()):
            raise OSError("one or more required process-boundary APIs are absent")
        return {
            "appcontainer_profile_lifecycle": True,
            "restricted_token": True,
            "low_integrity": True,
            "one_process_job": True,
            "required_exports": required_exports,
        }
    finally:
        if job:
            kernel32.CloseHandle(job)
        if integrity_sid:
            kernel32.LocalFree(integrity_sid)
        if restricted:
            kernel32.CloseHandle(restricted)
        if token:
            kernel32.CloseHandle(token)
        if appcontainer_sid:
            advapi32.FreeSid(appcontainer_sid)
        if profile_created:
            _hresult(
                userenv.DeleteAppContainerProfile(profile),
                "DeleteAppContainerProfile",
            )


def capture() -> dict[str, Any]:
    """Run the fail-closed Windows host qualification."""

    host = {
        "os": platform.system().lower(),
        "architecture": {
            "arm64": "aarch64",
            "amd64": "x86_64",
        }.get(platform.machine().lower(), platform.machine().lower()),
        "release": platform.release(),
        "version": platform.version(),
    }
    eligible = host["os"] == "windows" and host["architecture"] == "aarch64"
    mechanism: dict[str, Any] | None = None
    failure: str | None = None
    if eligible:
        try:
            mechanism = _native_probe()
        except OSError as issue:
            failure = f"{type(issue).__name__}:{issue.errno}:{issue.strerror or issue}"
    else:
        failure = "host-os-or-architecture-not-native-windows-arm64"
    value = {
        "schema": PROBE_SCHEMA,
        "experiment": "EXP-0023",
        "programme_experiment": "EXP-LANG-016",
        "host": host,
        "eligible": eligible,
        "mechanism": mechanism,
        "failure": failure,
        "supported": eligible and mechanism is not None,
        "fallback_used": False,
        "workload_slots": [],
        "process_id": os.getpid(),
    }
    value["identity"] = domain_hash("proofbound-research-windows-host-probe/1", value)
    return value


def main(argv: list[str] | None = None) -> int:
    """Write one canonical host-qualification record."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: windows_enforcement_probe CAPTURE", file=sys.stderr)
        return 2
    try:
        Path(arguments[0]).write_bytes(canonical_json(capture()))
    except OSError as issue:
        print(issue, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
