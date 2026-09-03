"""Minimal native Windows AppContainer process boundary for EXP-0023."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
import os
import subprocess
import tempfile
import uuid
from typing import Any

from proofbound.windows_enforcement_probe import (
    DISABLE_MAX_PRIVILEGE,
    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    SE_GROUP_INTEGRITY,
    TOKEN_ALL_ACCESS,
    TOKEN_INTEGRITY_LEVEL,
    JobExtendedLimitInformation,
    SidAndAttributes,
    TokenMandatoryLabel,
)


CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_NO_WINDOW = 0x08000000
STARTF_USESTDHANDLES = 0x00000100
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102
INFINITE = 0xFFFFFFFF


class StartupInfoW(ctypes.Structure):
    """Windows STARTUPINFOW."""

    _fields_ = [
        ("cb", wintypes.DWORD),
        ("reserved", wintypes.LPWSTR),
        ("desktop", wintypes.LPWSTR),
        ("title", wintypes.LPWSTR),
        ("x", wintypes.DWORD),
        ("y", wintypes.DWORD),
        ("x_size", wintypes.DWORD),
        ("y_size", wintypes.DWORD),
        ("x_count_chars", wintypes.DWORD),
        ("y_count_chars", wintypes.DWORD),
        ("fill_attribute", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("show_window", wintypes.WORD),
        ("reserved_size", wintypes.WORD),
        ("reserved2", ctypes.POINTER(wintypes.BYTE)),
        ("stdin", wintypes.HANDLE),
        ("stdout", wintypes.HANDLE),
        ("stderr", wintypes.HANDLE),
    ]


class StartupInfoExW(ctypes.Structure):
    """Windows STARTUPINFOEXW."""

    _fields_ = [("startup_info", StartupInfoW), ("attribute_list", wintypes.LPVOID)]


class ProcessInformation(ctypes.Structure):
    """Windows PROCESS_INFORMATION."""

    _fields_ = [
        ("process", wintypes.HANDLE),
        ("thread", wintypes.HANDLE),
        ("process_id", wintypes.DWORD),
        ("thread_id", wintypes.DWORD),
    ]


class SecurityCapabilities(ctypes.Structure):
    """Windows SECURITY_CAPABILITIES."""

    _fields_ = [
        ("appcontainer_sid", wintypes.LPVOID),
        ("capabilities", ctypes.POINTER(SidAndAttributes)),
        ("capability_count", wintypes.DWORD),
        ("reserved", wintypes.DWORD),
    ]


def _windows_error(operation: str) -> OSError:
    return ctypes.WinError(ctypes.get_last_error(), operation)


def _require(result: object, operation: str) -> None:
    if not result:
        raise _windows_error(operation)


def _hresult(result: int, operation: str) -> None:
    if result != 0:
        raise OSError(result & 0xFFFFFFFF, operation)


def _environment_block(environment: dict[str, str]) -> ctypes.Array[ctypes.c_wchar]:
    entries = [f"{name}={environment[name]}" for name in sorted(environment)]
    return ctypes.create_unicode_buffer("\0".join(entries) + "\0\0")


def _sid_text(advapi32: Any, kernel32: Any, sid: wintypes.LPVOID) -> str:
    text = wintypes.LPWSTR()
    _require(
        advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)),
        "ConvertSidToStringSidW",
    )
    try:
        return text.value
    finally:
        kernel32.LocalFree(ctypes.cast(text, wintypes.HLOCAL))


def run_appcontainer_process(
    command: list[str],
    cwd: Path,
    environment: dict[str, str],
    timeout_ms: int = 30_000,
) -> dict[str, Any]:
    """Run one command after all registered Windows boundary layers exist."""

    if os.name != "nt":
        raise OSError("native Windows boundary requested on a non-Windows host")
    if not command or not Path(command[0]).is_absolute():
        raise ValueError("the application path must be absolute")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.InitializeProcThreadAttributeList.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    kernel32.UpdateProcThreadAttribute.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.c_size_t,
        wintypes.LPVOID,
        ctypes.c_size_t,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
    kernel32.DeleteProcThreadAttributeList.argtypes = [wintypes.LPVOID]

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
    advapi32.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.GetLengthSid.argtypes = [wintypes.LPVOID]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    advapi32.SetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    advapi32.SetTokenInformation.restype = wintypes.BOOL
    advapi32.CreateProcessAsUserW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(StartupInfoW),
        ctypes.POINTER(ProcessInformation),
    ]
    advapi32.CreateProcessAsUserW.restype = wintypes.BOOL
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
    process = ProcessInformation()
    attribute_buffer: ctypes.Array[ctypes.c_char] | None = None
    attribute_initialized = False
    profile_created = False
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    try:
        _hresult(
            userenv.CreateAppContainerProfile(
                profile,
                profile,
                "Proofbound EXP-0023 execution",
                None,
                0,
                ctypes.byref(appcontainer_sid),
            ),
            "CreateAppContainerProfile",
        )
        profile_created = True
        sid = _sid_text(advapi32, kernel32, appcontainer_sid)
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
        label = TokenMandatoryLabel(SidAndAttributes(integrity_sid, SE_GROUP_INTEGRITY))
        _require(
            advapi32.SetTokenInformation(
                restricted,
                TOKEN_INTEGRITY_LEVEL,
                ctypes.byref(label),
                ctypes.sizeof(label) + advapi32.GetLengthSid(integrity_sid),
            ),
            "SetTokenInformation(TokenIntegrityLevel)",
        )

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

        attribute_size = ctypes.c_size_t()
        kernel32.InitializeProcThreadAttributeList(
            None, 1, 0, ctypes.byref(attribute_size)
        )
        attribute_buffer = ctypes.create_string_buffer(attribute_size.value)
        _require(
            kernel32.InitializeProcThreadAttributeList(
                attribute_buffer, 1, 0, ctypes.byref(attribute_size)
            ),
            "InitializeProcThreadAttributeList",
        )
        attribute_initialized = True
        capabilities = SecurityCapabilities(appcontainer_sid, None, 0, 0)
        _require(
            kernel32.UpdateProcThreadAttribute(
                attribute_buffer,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                ctypes.byref(capabilities),
                ctypes.sizeof(capabilities),
                None,
                None,
            ),
            "UpdateProcThreadAttribute(SecurityCapabilities)",
        )

        with (
            tempfile.NamedTemporaryFile(delete=False) as stdout_file,
            tempfile.NamedTemporaryFile(delete=False) as stderr_file,
        ):
            import msvcrt

            stdout_path = Path(stdout_file.name)
            stderr_path = Path(stderr_file.name)
            stdout_handle = msvcrt.get_osfhandle(stdout_file.fileno())
            stderr_handle = msvcrt.get_osfhandle(stderr_file.fileno())
            os.set_handle_inheritable(stdout_handle, True)
            os.set_handle_inheritable(stderr_handle, True)

            startup = StartupInfoExW()
            startup.startup_info.cb = ctypes.sizeof(startup)
            startup.startup_info.flags = STARTF_USESTDHANDLES
            startup.startup_info.stdin = wintypes.HANDLE(-1)
            startup.startup_info.stdout = wintypes.HANDLE(stdout_handle)
            startup.startup_info.stderr = wintypes.HANDLE(stderr_handle)
            startup.attribute_list = ctypes.cast(attribute_buffer, wintypes.LPVOID)
            command_line = ctypes.create_unicode_buffer(
                subprocess.list2cmdline(command)
            )
            environment_block = _environment_block(environment)
            _require(
                advapi32.CreateProcessAsUserW(
                    restricted,
                    command[0],
                    command_line,
                    None,
                    None,
                    True,
                    CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_NO_WINDOW,
                    environment_block,
                    str(cwd),
                    ctypes.byref(startup.startup_info),
                    ctypes.byref(process),
                ),
                "CreateProcessAsUserW",
            )
            _require(
                kernel32.AssignProcessToJobObject(job, process.process),
                "AssignProcessToJobObject",
            )
            if kernel32.ResumeThread(process.thread) == INFINITE:
                raise _windows_error("ResumeThread")
            wait = kernel32.WaitForSingleObject(process.process, timeout_ms)
            if wait == WAIT_TIMEOUT:
                kernel32.TerminateJobObject(job, 124)
                raise TimeoutError("AppContainer process exceeded its deadline")
            if wait != WAIT_OBJECT_0:
                raise _windows_error("WaitForSingleObject")
            exit_code = wintypes.DWORD()
            _require(
                kernel32.GetExitCodeProcess(process.process, ctypes.byref(exit_code)),
                "GetExitCodeProcess",
            )
        return {
            "profile": profile,
            "appcontainer_sid": sid,
            "restricted_token": True,
            "integrity_level": "low",
            "job": {
                "active_process_limit": 1,
                "kill_on_close": True,
                "assigned_before_resume": True,
            },
            "exit_code": exit_code.value,
            "stdout": stdout_path.read_text(encoding="utf-8", errors="strict"),
            "stderr": stderr_path.read_text(encoding="utf-8", errors="strict"),
        }
    finally:
        if process.thread:
            kernel32.CloseHandle(process.thread)
        if process.process:
            kernel32.CloseHandle(process.process)
        if attribute_initialized and attribute_buffer is not None:
            kernel32.DeleteProcThreadAttributeList(attribute_buffer)
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
                userenv.DeleteAppContainerProfile(profile), "DeleteAppContainerProfile"
            )
        if stdout_path is not None:
            stdout_path.unlink(missing_ok=True)
        if stderr_path is not None:
            stderr_path.unlink(missing_ok=True)
