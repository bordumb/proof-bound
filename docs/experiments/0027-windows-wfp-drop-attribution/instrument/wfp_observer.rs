#![cfg(target_os = "windows")]

use std::ffi::{c_void, OsStr};
use std::fs;
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

type Handle = *mut c_void;

const ERROR_SUCCESS: u32 = 0;
const RPC_C_AUTHN_WINNT: u32 = 10;
const FWP_UINT32: u32 = 3;
const FWPM_ENGINE_COLLECT_NET_EVENTS: u32 = 0;
const FWPM_NET_EVENT_TYPE_CAPABILITY_DROP: u32 = 7;
const FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW: u32 = 8;
const OBSERVER_LIMIT: usize = 1024;
const OBSERVER_TIMEOUT: Duration = Duration::from_secs(70);

#[repr(C)]
#[derive(Clone, Copy)]
struct FileTime {
    low: u32,
    high: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
struct ByteBlob {
    size: u32,
    data: *mut u8,
}

#[repr(C)]
union ValueData {
    uint32: u32,
    pointer: *mut c_void,
}

#[repr(C)]
struct Value {
    kind: u32,
    data: ValueData,
}

#[repr(C)]
#[derive(Clone, Copy)]
union IpAddress {
    v4: u32,
    v6: [u8; 16],
}

#[repr(C)]
struct EventHeader {
    timestamp: FileTime,
    flags: u32,
    ip_version: u32,
    ip_protocol: u8,
    local_address: IpAddress,
    remote_address: IpAddress,
    local_port: u16,
    remote_port: u16,
    scope_id: u32,
    app_id: ByteBlob,
    user_id: *mut c_void,
    address_family: u32,
    package_sid: *mut c_void,
}

#[repr(C)]
struct CapabilityEvent {
    capability_id: u32,
    filter_id: u64,
    is_loopback: i32,
}

#[repr(C)]
union EventData {
    pointer: *const c_void,
    capability: *const CapabilityEvent,
}

#[repr(C)]
struct NetEvent {
    header: EventHeader,
    event_type: u32,
    data: EventData,
}

#[repr(C)]
struct Subscription {
    template: *const c_void,
    flags: u32,
    session_key: Guid,
}

#[derive(Clone)]
struct Record {
    timestamp: u64,
    flags: u32,
    event_type: u32,
    ip_version: u32,
    ip_protocol: u8,
    local_address: u32,
    remote_address: u32,
    local_port: u16,
    remote_port: u16,
    app_id: String,
    package_sid: String,
    capability_id: u32,
    filter_id: u64,
    is_loopback: bool,
}

struct State {
    records: Mutex<Vec<Record>>,
}

#[link(name = "Fwpuclnt")]
unsafe extern "system" {
    fn FwpmEngineOpen0(
        server_name: *const u16,
        authentication_service: u32,
        authentication_identity: *const c_void,
        session: *const c_void,
        engine_handle: *mut Handle,
    ) -> u32;
    fn FwpmEngineClose0(engine_handle: Handle) -> u32;
    fn FwpmEngineGetOption0(engine_handle: Handle, option: u32, value: *mut *mut Value) -> u32;
    fn FwpmNetEventSubscribe1(
        engine_handle: Handle,
        subscription: *const Subscription,
        callback: unsafe extern "system" fn(*mut c_void, *const NetEvent),
        context: *mut c_void,
        events_handle: *mut Handle,
    ) -> u32;
    fn FwpmNetEventUnsubscribe0(engine_handle: Handle, events_handle: Handle) -> u32;
    fn FwpmGetAppIdFromFileName0(file_name: *const u16, app_id: *mut *mut ByteBlob) -> u32;
    fn FwpmFreeMemory0(memory: *mut *mut c_void);
}

#[link(name = "Advapi32")]
unsafe extern "system" {
    fn ConvertSidToStringSidW(sid: *const c_void, string_sid: *mut *mut u16) -> i32;
}

#[link(name = "Kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

fn check(result: u32, operation: &str) -> Result<(), String> {
    if result == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!("{operation} failed with {result}"))
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn bytes_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

unsafe fn blob_hex(blob: &ByteBlob) -> String {
    if blob.data.is_null() || blob.size == 0 {
        return String::new();
    }
    // SAFETY: WFP owns a readable blob for the duration of the callback.
    let bytes = unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) };
    bytes_hex(bytes)
}

unsafe fn sid_text(sid: *const c_void) -> String {
    if sid.is_null() {
        return String::new();
    }
    let mut value = ptr::null_mut();
    // SAFETY: WFP supplies a valid SID and LocalFree owns the converted string.
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 || value.is_null() {
        return String::new();
    }
    let mut length = 0;
    // SAFETY: ConvertSidToStringSidW returns a terminated UTF-16 allocation.
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: The allocation remains valid until LocalFree below.
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, length) });
    // SAFETY: value was allocated by ConvertSidToStringSidW.
    unsafe { LocalFree(value.cast()) };
    text
}

unsafe extern "system" fn observe(context: *mut c_void, event: *const NetEvent) {
    if context.is_null() || event.is_null() {
        return;
    }
    // SAFETY: WFP invokes the callback with the registered State and event.
    let state = unsafe { &*(context.cast::<State>()) };
    // SAFETY: event is valid throughout this callback.
    let event = unsafe { &*event };
    if !matches!(
        event.event_type,
        FWPM_NET_EVENT_TYPE_CAPABILITY_DROP | FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW
    ) {
        return;
    }
    let mut records = match state.records.lock() {
        Ok(value) => value,
        Err(_) => return,
    };
    if records.len() >= OBSERVER_LIMIT {
        return;
    }
    // SAFETY: capability is the active union member for capability events.
    let capability = unsafe { event.data.capability.as_ref() };
    let Some(capability) = capability else {
        return;
    };
    records.push(Record {
        timestamp: ((event.header.timestamp.high as u64) << 32) | event.header.timestamp.low as u64,
        flags: event.header.flags,
        event_type: event.event_type,
        ip_version: event.header.ip_version,
        ip_protocol: event.header.ip_protocol,
        // SAFETY: Copying both raw IPv4 union values does not dereference memory.
        local_address: unsafe { event.header.local_address.v4 },
        remote_address: unsafe { event.header.remote_address.v4 },
        local_port: event.header.local_port,
        remote_port: event.header.remote_port,
        // SAFETY: Both values are owned by WFP during this callback and copied.
        app_id: unsafe { blob_hex(&event.header.app_id) },
        package_sid: unsafe { sid_text(event.header.package_sid) },
        capability_id: capability.capability_id,
        filter_id: capability.filter_id,
        is_loopback: capability.is_loopback != 0,
    });
}

struct Engine(Handle);

impl Engine {
    fn open() -> Result<Self, String> {
        let mut handle = ptr::null_mut();
        // SAFETY: Null optional arguments request the local default WFP session.
        check(
            unsafe {
                FwpmEngineOpen0(
                    ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    ptr::null(),
                    ptr::null(),
                    &mut handle,
                )
            },
            "FwpmEngineOpen0",
        )?;
        Ok(Self(handle))
    }

    fn collection_enabled(&self) -> Result<bool, String> {
        let mut value = ptr::null_mut();
        // SAFETY: value receives a WFP allocation released below.
        check(
            unsafe { FwpmEngineGetOption0(self.0, FWPM_ENGINE_COLLECT_NET_EVENTS, &mut value) },
            "FwpmEngineGetOption0",
        )?;
        if value.is_null() {
            return Err("FwpmEngineGetOption0 returned no value".to_owned());
        }
        // SAFETY: A successful query returned a readable Value.
        let option = unsafe { &*value };
        let kind = option.kind;
        let enabled = if kind == FWP_UINT32 {
            // SAFETY: FWP_UINT32 selects the uint32 union member.
            unsafe { option.data.uint32 == 1 }
        } else {
            let mut memory = value.cast::<c_void>();
            // SAFETY: value is a WFP allocation.
            unsafe { FwpmFreeMemory0(&mut memory) };
            return Err(format!("collection option type differs: {kind}"));
        };
        let mut memory = value.cast::<c_void>();
        // SAFETY: value is a WFP allocation.
        unsafe { FwpmFreeMemory0(&mut memory) };
        Ok(enabled)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self owns the engine handle.
            unsafe { FwpmEngineClose0(self.0) };
        }
    }
}

fn application_id(path: &Path) -> Result<String, String> {
    let input = wide(path.as_os_str());
    let mut blob = ptr::null_mut();
    // SAFETY: input is terminated and blob receives a WFP allocation.
    check(
        unsafe { FwpmGetAppIdFromFileName0(input.as_ptr(), &mut blob) },
        "FwpmGetAppIdFromFileName0",
    )?;
    if blob.is_null() {
        return Err("FwpmGetAppIdFromFileName0 returned no blob".to_owned());
    }
    // SAFETY: A successful call returned a readable blob.
    let result = unsafe { blob_hex(&*blob) };
    let mut memory = blob.cast::<c_void>();
    // SAFETY: blob is a WFP allocation.
    unsafe { FwpmFreeMemory0(&mut memory) };
    Ok(result)
}

fn write_records(path: &Path, records: &[Record]) -> Result<(), String> {
    let mut output = fs::File::create(path).map_err(|error| error.to_string())?;
    writeln!(output, "proofbound-wfp-events/1").map_err(|error| error.to_string())?;
    for value in records {
        writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            value.timestamp,
            value.flags,
            value.event_type,
            value.ip_version,
            value.ip_protocol,
            value.local_address,
            value.remote_address,
            value.local_port,
            value.remote_port,
            value.app_id,
            value.package_sid,
            value.capability_id,
            value.filter_id,
            u8::from(value.is_loopback),
        )
        .map_err(|error| error.to_string())?;
    }
    output.flush().map_err(|error| error.to_string())
}

fn run_observer(stop: &Path, output: &Path) -> Result<(), String> {
    let engine = Engine::open()?;
    if !engine.collection_enabled()? {
        return Err("WFP network event collection is disabled".to_owned());
    }
    let state = Box::new(State {
        records: Mutex::new(Vec::new()),
    });
    let context = (&*state as *const State).cast_mut().cast::<c_void>();
    let subscription = Subscription {
        template: ptr::null(),
        flags: 0,
        session_key: Guid {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        },
    };
    let mut events_handle = ptr::null_mut();
    // SAFETY: state outlives the subscription and the callback copies event data.
    check(
        unsafe {
            FwpmNetEventSubscribe1(
                engine.0,
                &subscription,
                observe,
                context,
                &mut events_handle,
            )
        },
        "FwpmNetEventSubscribe1",
    )?;
    println!("READY\tproofbound-wfp-events/1");
    io::stdout().flush().map_err(|error| error.to_string())?;
    let started = Instant::now();
    while !stop.exists() && started.elapsed() < OBSERVER_TIMEOUT {
        thread::sleep(Duration::from_millis(10));
    }
    // SAFETY: events_handle belongs to this engine and no callback may follow.
    check(
        unsafe { FwpmNetEventUnsubscribe0(engine.0, events_handle) },
        "FwpmNetEventUnsubscribe0",
    )?;
    let records = state
        .records
        .lock()
        .map_err(|_| "observer record lock poisoned".to_owned())?
        .clone();
    if records.len() >= OBSERVER_LIMIT {
        return Err("WFP observer event ceiling reached".to_owned());
    }
    write_records(output, &records)
}

fn run(arguments: &[String]) -> Result<(), String> {
    match arguments {
        [command] if command == "probe" => {
            let engine = Engine::open()?;
            println!(
                "PROBE\t{}\tFwpmNetEventSubscribe1\tFWPM_NET_EVENT2",
                u8::from(engine.collection_enabled()?)
            );
            Ok(())
        }
        [command, path] if command == "appid" => {
            println!("APPID\t{}", application_id(Path::new(path))?);
            Ok(())
        }
        [command, stop, output] if command == "observe" => {
            run_observer(Path::new(stop), Path::new(output))
        }
        _ => Err("usage: wfp_observer probe | appid PATH | observe STOP OUTPUT".to_owned()),
    }
}

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if let Err(error) = run(&arguments) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
