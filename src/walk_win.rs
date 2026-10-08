#[cfg(windows)]
pub mod win {
    use crate::walk::{Listing, Ctx, RawEnt, KIND_DIR, KIND_FILE, KIND_OTHER, FLAG_MOUNT, FLAG_HIDDEN, NONE, blocked, SKIP};
    use std::os::windows::ffi::OsStrExt;
    use std::ffi::OsStr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;
    use windows_sys::Win32::Storage::FileSystem::{
        FindFirstFileExW, FindNextFileW, FindClose,
        FindExInfoBasic, FindExSearchNameMatch, FIND_FIRST_EX_LARGE_FETCH,
        WIN32_FIND_DATAW,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_REPARSE_POINT,
    };
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;

    pub fn scan(root: &[u8], threads: usize) -> Vec<Listing> {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
        let ctx = Ctx { next_id: AtomicU32::new(1), out: (0..threads + 1).map(|_| Mutex::new(Vec::new())).collect() };
        
        let path = SKIP.get().is_some_and(|v| !v.is_empty()).then(|| root.to_vec());
        let root_str = std::str::from_utf8(root).unwrap_or("");
        
        pool.scope(|s| finish_dir(s, root_str.to_string(), path, 0, &ctx));
        
        ctx.out.into_iter().flat_map(|m| m.into_inner().unwrap()).collect()
    }

    pub fn list_one(path: &[u8]) -> Option<Listing> {
        if blocked(path) {
            return None;
        }
        let path_str = std::str::from_utf8(path).ok()?;
        let mut l = Listing { id: 0, names: Vec::new(), ents: Vec::new() };
        list_into(path_str, &mut l).then_some(l)
    }

    fn finish_dir<'s>(s: &rayon::Scope<'s>, dir_path: String, path_vec: Option<Vec<u8>>, id: u32, ctx: &'s Ctx) {
        let mut l = Listing { id, names: Vec::new(), ents: Vec::new() };
        
        if !list_into(&dir_path, &mut l) {
            push(l, ctx);
            return;
        }

        let mut kids = Vec::new();
        for e in l.ents.iter_mut() {
            if e.kind & 3 == KIND_DIR && e.kind & FLAG_MOUNT == 0 {
                let name = &l.names[e.name_off as usize..e.name_off as usize + e.name_len as usize];
                let child_path_vec = path_vec.as_ref().map(|p| crate::live::join(p, name));
                if child_path_vec.as_deref().is_some_and(blocked) {
                    continue;
                }
                
                e.child = ctx.next_id.fetch_add(1, Ordering::Relaxed);
                
                let name_str = std::str::from_utf8(name).unwrap_or("");
                let next_dir = if dir_path.ends_with('/') || dir_path.ends_with('\\') {
                    format!("{}{}", dir_path, name_str)
                } else {
                    format!("{}/{}", dir_path, name_str)
                };
                
                kids.push((next_dir, e.child, child_path_vec));
            }
        }
        
        push(l, ctx);
        
        for (next_dir, cid, child_path_vec) in kids {
            s.spawn(move |s| {
                finish_dir(s, next_dir, child_path_vec, cid, ctx);
            });
        }
    }

    fn push(l: Listing, ctx: &Ctx) {
        let slot = rayon::current_thread_index().unwrap_or(ctx.out.len() - 1);
        ctx.out[slot].lock().unwrap().push(l);
    }

    fn list_into(dir_path: &str, l: &mut Listing) -> bool {
        let query = if dir_path.ends_with('/') || dir_path.ends_with('\\') {
            format!("{}*", dir_path)
        } else {
            format!("{}/*", dir_path)
        };
        
        let mut query_w: Vec<u16> = OsStr::new(&query).encode_wide().collect();
        query_w.push(0);

        let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
        
        let handle = unsafe {
            FindFirstFileExW(
                query_w.as_ptr(),
                FindExInfoBasic,
                &mut data as *mut _ as *mut _,
                FindExSearchNameMatch,
                std::ptr::null_mut(),
                FIND_FIRST_EX_LARGE_FETCH,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return false;
        }

        loop {
            let name_len = data.cFileName.iter().take_while(|&&c| c != 0).count();
            if name_len > 0 {
                let is_dot = name_len == 1 && data.cFileName[0] == b'.' as u16;
                let is_dotdot = name_len == 2 && data.cFileName[0] == b'.' as u16 && data.cFileName[1] == b'.' as u16;
                
                if !is_dot && !is_dotdot {
                    if let Ok(name_str) = String::from_utf16(&data.cFileName[..name_len]) {
                        let name_bytes = name_str.as_bytes();
                        
                        if !name_bytes.is_empty() && name_bytes.len() <= u16::MAX as usize {
                            let mut kind = KIND_OTHER;
                            if data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                                kind = KIND_DIR;
                            } else {
                                kind = KIND_FILE;
                            }
                            if data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                                kind |= FLAG_MOUNT; // Treat symlinks/junctions as mounts to avoid crossing
                            }
                            if data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN != 0 {
                                kind |= FLAG_HIDDEN;
                            }

                            let size = ((data.nFileSizeHigh as u64) << 32) | (data.nFileSizeLow as u64);
                            
                            // Convert FILETIME to unix timestamp
                            let ft = ((data.ftLastWriteTime.dwHighDateTime as u64) << 32) | (data.ftLastWriteTime.dwLowDateTime as u64);
                            let mtime = if ft >= 116444736000000000 {
                                ((ft - 116444736000000000) / 10000000) as u32
                            } else {
                                0
                            };

                            l.ents.push(RawEnt {
                                name_off: l.names.len() as u32,
                                name_len: name_bytes.len() as u16,
                                kind,
                                size,
                                mtime,
                                child: NONE,
                            });
                            l.names.extend_from_slice(name_bytes);
                        }
                    }
                }
            }

            let next = unsafe { FindNextFileW(handle, &mut data) };
            if next == 0 {
                break;
            }
        }

        unsafe { FindClose(handle) };
        true
    }
}
