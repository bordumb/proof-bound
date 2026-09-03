"""Minimal native Windows AppContainer process boundary for EXP-0023."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
import os
import shutil
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
TOKEN_QUERY = 0x0008
TOKEN_GROUPS = 2
TOKEN_IS_APPCONTAINER = 29
TOKEN_APPCONTAINER_SID = 31
SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010
LUA_TOKEN = 0x00000004
SE_WINDOW_OBJECT = 7
DACL_SECURITY_INFORMATION = 0x00000004
GRANT_ACCESS = 1
NO_INHERITANCE = 0
TRUSTEE_IS_SID = 0
TRUSTEE_IS_UNKNOWN = 0
WINSTA_ALL_ACCESS = 0x000F037F
DESKTOP_ALL_ACCESS = 0x000F01FF


@dataclass(frozen=True)
class WindowsBoundaryOptions:
    """Discovery-selectable process-boundary controls.

    Defaults preserve the preregistered EXP-0023 boundary. Non-default values
    are permitted only for EXP-0025's non-reusable discovery matrix.
    """

    active_process_limit: int | None = 1
    private_desktop: bool = True
    create_no_window: bool = True

    def __post_init__(self) -> None:
        if self.active_process_limit is not None and self.active_process_limit < 1:
            raise ValueError("active_process_limit must be positive or None")


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


class TokenGroups(ctypes.Structure):
    """Variable-length TOKEN_GROUPS prefix."""

    _fields_ = [
        ("group_count", wintypes.DWORD),
        ("groups", SidAndAttributes * 1),
    ]


class TokenAppContainerInformation(ctypes.Structure):
    """TOKEN_APPCONTAINER_INFORMATION."""

    _fields_ = [("appcontainer_sid", wintypes.LPVOID)]


class TrusteeW(ctypes.Structure):
    """Windows TRUSTEE_W."""

    _fields_ = [
        ("multiple_trustee", wintypes.LPVOID),
        ("multiple_trustee_operation", ctypes.c_int),
        ("trustee_form", ctypes.c_int),
        ("trustee_type", ctypes.c_int),
        ("name", wintypes.LPWSTR),
    ]


class ExplicitAccessW(ctypes.Structure):
    """Windows EXPLICIT_ACCESS_W."""

    _fields_ = [
        ("access_permissions", wintypes.DWORD),
        ("access_mode", ctypes.c_int),
        ("inheritance", wintypes.DWORD),
        ("trustee", TrusteeW),
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


def _appcontainer_folder(userenv: Any, ole32: Any, sid: str) -> Path:
    """Resolve the profile-owned storage root for one AppContainer SID."""

    value = wintypes.LPWSTR()
    _hresult(
        userenv.GetAppContainerFolderPath(sid, ctypes.byref(value)),
        "GetAppContainerFolderPath",
    )
    try:
        return Path(value.value)
    finally:
        ole32.CoTaskMemFree(ctypes.cast(value, wintypes.LPVOID))


def _grant_window_object(
    advapi32: Any,
    kernel32: Any,
    handle: wintypes.HANDLE,
    sid: wintypes.LPVOID,
    access: int,
) -> None:
    """Add one AppContainer allow entry to a private window object."""

    old_dacl = wintypes.LPVOID()
    security_descriptor = wintypes.LPVOID()
    result = advapi32.GetSecurityInfo(
        handle,
        SE_WINDOW_OBJECT,
        DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(old_dacl),
        None,
        ctypes.byref(security_descriptor),
    )
    if result != 0:
        raise OSError(result, "GetSecurityInfo")
    new_dacl = wintypes.LPVOID()
    entry = ExplicitAccessW(
        access,
        GRANT_ACCESS,
        NO_INHERITANCE,
        TrusteeW(
            None,
            0,
            TRUSTEE_IS_SID,
            TRUSTEE_IS_UNKNOWN,
            ctypes.cast(sid, wintypes.LPWSTR),
        ),
    )
    try:
        result = advapi32.SetEntriesInAclW(
            1, ctypes.byref(entry), old_dacl, ctypes.byref(new_dacl)
        )
        if result != 0:
            raise OSError(result, "SetEntriesInAclW")
        result = advapi32.SetSecurityInfo(
            handle,
            SE_WINDOW_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            new_dacl,
            None,
        )
        if result != 0:
            raise OSError(result, "SetSecurityInfo")
    finally:
        if new_dacl:
            kernel32.LocalFree(new_dacl)
        if security_descriptor:
            kernel32.LocalFree(security_descriptor)


def _token_information(advapi32: Any, token: wintypes.HANDLE, kind: int) -> Any:
    """Return a stable ctypes buffer for one token information class."""

    size = wintypes.DWORD()
    advapi32.GetTokenInformation(token, kind, None, 0, ctypes.byref(size))
    if size.value == 0:
        raise _windows_error(f"GetTokenInformation({kind}) size")
    buffer = ctypes.create_string_buffer(size.value)
    _require(
        advapi32.GetTokenInformation(
            token, kind, buffer, size.value, ctypes.byref(size)
        ),
        f"GetTokenInformation({kind})",
    )
    return buffer


def _inspect_child_token(
    advapi32: Any,
    kernel32: Any,
    process: wintypes.HANDLE,
    expected_appcontainer_sid: str,
) -> dict[str, Any]:
    """Inspect the actual suspended child token before workload entry."""

    child_token = wintypes.HANDLE()
    _require(
        advapi32.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(child_token)),
        "OpenProcessToken(child)",
    )
    try:
        is_appcontainer_buffer = _token_information(
            advapi32, child_token, TOKEN_IS_APPCONTAINER
        )
        is_appcontainer = bool(
            ctypes.cast(
                is_appcontainer_buffer, ctypes.POINTER(wintypes.DWORD)
            ).contents.value
        )
        appcontainer_buffer = _token_information(
            advapi32, child_token, TOKEN_APPCONTAINER_SID
        )
        appcontainer = TokenAppContainerInformation.from_buffer(appcontainer_buffer)
        appcontainer_sid = (
            _sid_text(advapi32, kernel32, appcontainer.appcontainer_sid)
            if appcontainer.appcontainer_sid
            else None
        )
        integrity_buffer = _token_information(
            advapi32, child_token, TOKEN_INTEGRITY_LEVEL
        )
        integrity = TokenMandatoryLabel.from_buffer(integrity_buffer)
        integrity_sid = _sid_text(advapi32, kernel32, integrity.label.sid)
        groups_buffer = _token_information(advapi32, child_token, TOKEN_GROUPS)
        groups = TokenGroups.from_buffer(groups_buffer)
        group_pointer = ctypes.cast(
            ctypes.addressof(groups_buffer) + TokenGroups.groups.offset,
            ctypes.POINTER(SidAndAttributes),
        )
        administrator_attributes = None
        for index in range(groups.group_count):
            group = group_pointer[index]
            if _sid_text(advapi32, kernel32, group.sid) == "S-1-5-32-544":
                administrator_attributes = group.attributes
                break
        administrator_deny_only = administrator_attributes is not None and bool(
            administrator_attributes & SE_GROUP_USE_FOR_DENY_ONLY
        )
        verified = (
            is_appcontainer
            and appcontainer_sid == expected_appcontainer_sid
            and integrity_sid == "S-1-16-4096"
            and administrator_deny_only
        )
        return {
            "appcontainer": is_appcontainer,
            "appcontainer_sid": appcontainer_sid,
            "integrity_sid": integrity_sid,
            "administrator_sid": "S-1-5-32-544",
            "administrator_attributes": administrator_attributes,
            "administrator_deny_only": administrator_deny_only,
            "verified_before_resume": verified,
        }
    finally:
        kernel32.CloseHandle(child_token)


def run_appcontainer_process(
    command: list[str],
    cwd: Path,
    environment: dict[str, str],
    timeout_ms: int = 30_000,
    *,
    stage_application: bool = False,
    options: WindowsBoundaryOptions | None = None,
) -> dict[str, Any]:
    """Run one command after all registered Windows boundary layers exist."""

    boundary = options or WindowsBoundaryOptions()
    if os.name != "nt":
        raise OSError("native Windows boundary requested on a non-Windows host")
    if not command or not Path(command[0]).is_absolute():
        raise ValueError("the application path must be absolute")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)

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
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
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
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.SetEntriesInAclW.argtypes = [
        wintypes.ULONG,
        ctypes.POINTER(ExplicitAccessW),
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.SetEntriesInAclW.restype = wintypes.DWORD
    advapi32.SetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    advapi32.SetSecurityInfo.restype = wintypes.DWORD

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
    userenv.GetAppContainerFolderPath.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    userenv.GetAppContainerFolderPath.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = [wintypes.LPVOID]
    user32.GetProcessWindowStation.restype = wintypes.HANDLE
    user32.SetProcessWindowStation.argtypes = [wintypes.HANDLE]
    user32.SetProcessWindowStation.restype = wintypes.BOOL
    user32.CreateWindowStationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    user32.CreateWindowStationW.restype = wintypes.HANDLE
    user32.CloseWindowStation.argtypes = [wintypes.HANDLE]
    user32.CloseWindowStation.restype = wintypes.BOOL
    user32.CreateDesktopW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    user32.CreateDesktopW.restype = wintypes.HANDLE
    user32.CloseDesktop.argtypes = [wintypes.HANDLE]
    user32.CloseDesktop.restype = wintypes.BOOL

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
    parent_station = wintypes.HANDLE()
    private_station = wintypes.HANDLE()
    private_desktop = wintypes.HANDLE()
    station_name = f"proofbound-{uuid.uuid4().hex}"
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
        profile_storage = _appcontainer_folder(userenv, ole32, sid)
        profile_temp = profile_storage / "Temp"
        profile_temp.mkdir(parents=True, exist_ok=True)
        child_command = list(command)
        child_cwd = cwd
        if stage_application:
            application_root = profile_storage / "Application"
            application_root.mkdir(parents=True, exist_ok=False)
            application = application_root / Path(command[0]).name
            shutil.copy2(command[0], application)
            child_command[0] = str(application)
            child_cwd = application_root
        child_environment = dict(environment)
        child_environment.update(
            {
                "LOCALAPPDATA": str(profile_storage),
                "TEMP": str(profile_temp),
                "TMP": str(profile_temp),
            }
        )
        if boundary.private_desktop:
            parent_station = user32.GetProcessWindowStation()
            _require(parent_station, "GetProcessWindowStation")
            private_station = user32.CreateWindowStationW(
                station_name, 0, WINSTA_ALL_ACCESS, None
            )
            _require(private_station, "CreateWindowStationW")
            _grant_window_object(
                advapi32,
                kernel32,
                private_station,
                appcontainer_sid,
                WINSTA_ALL_ACCESS,
            )
            _require(
                user32.SetProcessWindowStation(private_station),
                "SetProcessWindowStation(private)",
            )
            try:
                private_desktop = user32.CreateDesktopW(
                    "default", None, None, 0, DESKTOP_ALL_ACCESS, None
                )
                _require(private_desktop, "CreateDesktopW")
            finally:
                _require(
                    user32.SetProcessWindowStation(parent_station),
                    "SetProcessWindowStation(parent)",
                )
            _grant_window_object(
                advapi32,
                kernel32,
                private_desktop,
                appcontainer_sid,
                DESKTOP_ALL_ACCESS,
            )
        _require(
            advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(), TOKEN_ALL_ACCESS, ctypes.byref(token)
            ),
            "OpenProcessToken",
        )
        _require(
            advapi32.CreateRestrictedToken(
                token,
                DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
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
        limits.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if boundary.active_process_limit is not None:
            limits.basic_limit_information.limit_flags |= (
                JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            )
            limits.basic_limit_information.active_process_limit = (
                boundary.active_process_limit
            )
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
            if boundary.private_desktop:
                startup.startup_info.desktop = f"{station_name}\\default"
            startup.attribute_list = ctypes.cast(attribute_buffer, wintypes.LPVOID)
            command_line = ctypes.create_unicode_buffer(
                subprocess.list2cmdline(child_command)
            )
            environment_block = _environment_block(child_environment)
            _require(
                advapi32.CreateProcessAsUserW(
                    restricted,
                    child_command[0],
                    command_line,
                    None,
                    None,
                    True,
                    CREATE_SUSPENDED
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT
                    | (CREATE_NO_WINDOW if boundary.create_no_window else 0),
                    environment_block,
                    str(child_cwd),
                    ctypes.byref(startup.startup_info),
                    ctypes.byref(process),
                ),
                "CreateProcessAsUserW",
            )
            _require(
                kernel32.AssignProcessToJobObject(job, process.process),
                "AssignProcessToJobObject",
            )
            child_token = _inspect_child_token(advapi32, kernel32, process.process, sid)
            if not child_token["verified_before_resume"]:
                kernel32.TerminateJobObject(job, 125)
                raise ValueError("suspended child token does not match the boundary")
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
            "profile_storage": str(profile_storage),
            "window_station": {
                "name": station_name if boundary.private_desktop else None,
                "desktop": "default" if boundary.private_desktop else None,
                "private": boundary.private_desktop,
                "appcontainer_acl": boundary.private_desktop,
            },
            "requested_command": command,
            "executed_command": child_command,
            "application_staged": stage_application,
            "appcontainer_sid": sid,
            "restricted_token": True,
            "administrator_sids": "deny-only",
            "integrity_level": "low",
            "child_token": child_token,
            "job": {
                "active_process_limit": boundary.active_process_limit,
                "kill_on_close": True,
                "assigned_before_resume": True,
            },
            "create_no_window": boundary.create_no_window,
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
        if private_desktop:
            user32.CloseDesktop(private_desktop)
        if private_station:
            user32.CloseWindowStation(private_station)
        if profile_created:
            _hresult(
                userenv.DeleteAppContainerProfile(profile), "DeleteAppContainerProfile"
            )
        if stdout_path is not None:
            stdout_path.unlink(missing_ok=True)
        if stderr_path is not None:
            stderr_path.unlink(missing_ok=True)
