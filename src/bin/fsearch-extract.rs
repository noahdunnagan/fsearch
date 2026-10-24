// Bounded parser process. Allocator adapted from joshwhiteley/fsearch's
// pdf_process.rs (MIT, Copyright 2026 Josh Whiteley; see DOCUMENT-LICENSE).
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

const HEAP_BYTES: usize = 256 * 1024 * 1024;

/// Account for allocations in the document parser process. Accounting starts at process
/// startup, but the finite limit is enabled only in the isolated helper.
pub struct DocumentAllocator {
    live: AtomicUsize,
    limit: AtomicUsize,
}

impl Default for DocumentAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl DocumentAllocator {
    pub const fn new() -> Self {
        Self { live: AtomicUsize::new(0), limit: AtomicUsize::new(usize::MAX) }
    }

    fn charge(layout: Layout) -> Option<usize> {
        // Include alignment slack and conservative per-allocation overhead.
        layout.size().checked_add(layout.align())?.checked_add(64)
    }

    fn reserve(&self, bytes: usize) -> bool {
        self.live
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |live| live.checked_add(bytes).filter(|next| *next <= self.limit.load(Ordering::SeqCst)))
            .is_ok()
    }

    fn enable(&self) -> Result<(), &'static str> {
        self.limit.store(HEAP_BYTES, Ordering::SeqCst);
        if self.live.load(Ordering::SeqCst) > HEAP_BYTES { Err("Document helper startup exceeds heap budget") } else { Ok(()) }
    }
}

// SAFETY: allocation and deallocation are paired through System with their
// original layouts. Accounting failure returns null without touching memory.
unsafe impl GlobalAlloc for DocumentAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some(charge) = Self::charge(layout) else {
            return std::ptr::null_mut();
        };
        if !self.reserve(charge) {
            return std::ptr::null_mut();
        }
        let ptr = unsafe { System.alloc(layout) };
        if ptr.is_null() {
            self.live.fetch_sub(charge, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            System.dealloc(ptr, layout);
        }
        self.live.fetch_sub(Self::charge(layout).unwrap(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let Ok(next) = Layout::from_size_align(size, layout.align()) else {
            return std::ptr::null_mut();
        };
        let Some(charge) = Self::charge(next) else {
            return std::ptr::null_mut();
        };
        // Reserve the full new allocation, not just growth: System may briefly
        // retain both buffers. A failed realloc leaves the old charge intact.
        if !self.reserve(charge) {
            return std::ptr::null_mut();
        }
        let result = unsafe { System.realloc(ptr, layout, size) };
        self.live.fetch_sub(if result.is_null() { charge } else { Self::charge(layout).unwrap() }, Ordering::SeqCst);
        result
    }
}

#[global_allocator]
static ALLOCATOR: DocumentAllocator = DocumentAllocator::new();

fn main() {
    use std::io::{Read, Write};
    std::panic::set_hook(Box::new(|_| {}));
    if ALLOCATOR.enable().is_err() {
        std::process::exit(1);
    }
    unsafe {
        let cpu = libc::rlimit { rlim_cur: 8, rlim_max: 8 };
        let core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::setrlimit(libc::RLIMIT_CPU, &cpu) != 0 || libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
            std::process::exit(1);
        }
    }
    let result = std::panic::catch_unwind(|| -> Option<String> {
        let kind = std::env::args().nth(1)?;
        let mut bytes = Vec::new();
        std::io::stdin().take(fsearch::document::MAX_SOURCE + 1).read_to_end(&mut bytes).ok()?;
        if bytes.len() as u64 > fsearch::document::MAX_SOURCE {
            return None;
        }
        let text = match kind.as_str() {
            "pdf" => objc2::rc::autoreleasepool(|_| unsafe {
                use objc2::AnyThread;
                let data = objc2_foundation::NSData::with_bytes(&bytes);
                let pdf = objc2_pdf_kit::PDFDocument::initWithData(objc2_pdf_kit::PDFDocument::alloc(), &data)?;
                if pdf.isLocked() {
                    return None;
                }
                let mut text = String::new();
                for index in 0..pdf.pageCount() {
                    let page = pdf.pageAtIndex(index)?;
                    if let Some(value) = page.string() {
                        let value = value.to_string();
                        if text.len().saturating_add(value.len() + 1) > fsearch::document::MAX_TEXT {
                            return None;
                        }
                        text.push_str(&value);
                    }
                    text.push('\n');
                }
                Some(text)
            })?,
            "xls" | "xlsx" => {
                use calamine::Reader;
                let mut book = calamine::open_workbook_auto_from_rs(std::io::Cursor::new(bytes)).ok()?;
                let mut text = String::new();
                for name in book.sheet_names().to_vec() {
                    text.push_str(&name);
                    text.push('\n');
                    let sheet = book.worksheet_range(&name).ok()?;
                    for row in sheet.rows() {
                        for cell in row {
                            let value = cell.to_string();
                            if text.len().saturating_add(value.len() + 1) > fsearch::document::MAX_TEXT {
                                return None;
                            }
                            text.push_str(&value);
                            text.push('\t');
                        }
                        text.push('\n');
                    }
                }
                text
            }
            _ => return None,
        };
        (text.len() <= fsearch::document::MAX_TEXT).then_some(text)
    });
    let Ok(Some(text)) = result else {
        std::process::exit(1);
    };
    if std::io::stdout().write_all(text.as_bytes()).is_err() {
        std::process::exit(1);
    }
}
