use rand::{RngCore, rngs::OsRng};
use std::{sync::Mutex, thread, time::Duration};
use tauri::{Manager, WebviewWindow, async_runtime::JoinHandle};
use windows::{
    Win32::{
        Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND},
        System::{
            DataExchange::{
                CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardOwner,
                IsClipboardFormatAvailable, OpenClipboard, RegisterClipboardFormatW,
                SetClipboardData,
            },
            Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock},
        },
    },
    core::w,
};
use zeroize::Zeroizing;

const CF_UNICODETEXT: u32 = 13;
const COPY_FAILED: &str = "Could not copy to the Windows clipboard. Try again.";

#[derive(Default)]
pub struct Clipboard(Mutex<Option<Copy>>);

struct Copy {
    marker: [u8; 16],
    format: u32,
    owner: isize,
    timer: JoinHandle<()>,
}

struct Open;

impl Open {
    fn acquire(owner: Option<HWND>) -> windows::core::Result<Self> {
        for _ in 0..5 {
            if unsafe { OpenClipboard(owner) }.is_ok() {
                return Ok(Self);
            }
            thread::sleep(Duration::from_millis(15));
        }
        unsafe { OpenClipboard(owner) }?;
        Ok(Self)
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        let _ = unsafe { CloseClipboard() };
    }
}

struct ClipboardMemory(Option<HGLOBAL>);

impl ClipboardMemory {
    fn new(bytes: &[u8]) -> windows::core::Result<Self> {
        let allocation = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len()) }?;
        let memory = Self(Some(allocation));
        let address = unsafe { GlobalLock(allocation) };
        if address.is_null() {
            return Err(windows::core::Error::from_thread());
        }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), address.cast(), bytes.len()) };
        // Releasing the final lock returns zero with a success last-error code.
        let _ = unsafe { GlobalUnlock(allocation) };
        Ok(memory)
    }

    fn publish(mut self, format: u32) -> windows::core::Result<()> {
        let allocation = self.0.expect("clipboard allocation exists");
        unsafe { SetClipboardData(format, Some(HANDLE(allocation.0))) }?;
        self.0 = None; // Windows owns the allocation from this point.
        Ok(())
    }
}

impl Drop for ClipboardMemory {
    fn drop(&mut self) {
        if let Some(allocation) = self.0.take() {
            let _ = unsafe { GlobalFree(Some(allocation)) };
        }
    }
}

fn write(owner: HWND, value: &str, marker: &[u8; 16]) -> windows::core::Result<u32> {
    let text = Zeroizing::new(
        value
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    let text_memory = ClipboardMemory::new(&text)?;
    let private = ClipboardMemory::new(marker)?;
    let private_format =
        unsafe { RegisterClipboardFormatW(w!("ExcludeClipboardContentFromMonitorProcessing")) };
    if private_format == 0 {
        return Err(windows::core::Error::from_thread());
    }
    let _clipboard = Open::acquire(Some(owner))?;
    unsafe { EmptyClipboard() }?;
    // Publish the privacy marker first so a failure cannot expose the text to history.
    private.publish(private_format)?;
    text_memory.publish(CF_UNICODETEXT)?;
    Ok(private_format)
}

fn clear(copy: &Copy) -> windows::core::Result<()> {
    let _clipboard = Open::acquire(None)?;
    if !unsafe { GetClipboardOwner() }.is_ok_and(|owner| owner.0 as isize == copy.owner)
        || unsafe { IsClipboardFormatAvailable(copy.format) }.is_err()
    {
        return Ok(());
    }
    // Read only our random marker. Windows can synthesize text formats and
    // change the sequence without replacing the copied value.
    let data = HGLOBAL(unsafe { GetClipboardData(copy.format) }?.0);
    if unsafe { GlobalSize(data) } < copy.marker.len() {
        return Ok(());
    }
    let address = unsafe { GlobalLock(data) };
    if address.is_null() {
        return Err(windows::core::Error::from_thread());
    }
    let matches = unsafe { std::slice::from_raw_parts(address.cast::<u8>(), copy.marker.len()) }
        == copy.marker;
    let _ = unsafe { GlobalUnlock(data) };
    if matches {
        unsafe { EmptyClipboard() }?;
    }
    Ok(())
}

impl Clipboard {
    pub fn copy(&self, window: &WebviewWindow, value: String, seconds: u64) -> Result<(), String> {
        let value = Zeroizing::new(value);
        if !matches!(seconds, 15 | 30 | 60 | 120)
            || value.len() > 1_000_000
            || value.as_bytes().contains(&0)
        {
            return Err("This value cannot be copied to the Windows clipboard.".into());
        }
        let owner = window.hwnd().map_err(|_| COPY_FAILED)?;
        let mut pending = self.0.lock().map_err(|_| COPY_FAILED)?;
        let mut marker = [0; 16];
        OsRng.try_fill_bytes(&mut marker).map_err(|_| COPY_FAILED)?;
        let format = write(owner, &value, &marker).map_err(|_| COPY_FAILED)?;
        if let Some(old) = pending.take() {
            old.timer.abort();
        }
        let app = window.app_handle().clone();
        let timer = tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_secs(seconds)).await;
            let clipboard = app.state::<Clipboard>();
            let mut delay = Duration::from_millis(250);
            loop {
                if clipboard.expire(Some(marker)) {
                    return;
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(5));
            }
        });
        *pending = Some(Copy {
            marker,
            format,
            owner: owner.0 as isize,
            timer,
        });
        Ok(())
    }

    pub fn expire(&self, marker: Option<[u8; 16]>) -> bool {
        let Ok(mut pending) = self.0.lock() else {
            return false;
        };
        let Some(copy) = pending.as_ref() else {
            return true;
        };
        if marker.is_some_and(|marker| marker != copy.marker) {
            return true;
        }
        if clear(copy).is_err() {
            return false;
        }
        if let Some(copy) = pending.take() {
            if marker.is_none() {
                copy.timer.abort();
            }
        }
        true
    }
}
