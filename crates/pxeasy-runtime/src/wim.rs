use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int, c_uint},
    path::Path,
    ptr,
    sync::OnceLock,
};

const WIMLIB_OPEN_FLAG_WRITE_ACCESS: c_int = 0x00000004;
const WIMLIB_WRITE_FLAG_REBUILD: c_int = 0x00000040;
const WIMLIB_COMPRESSION_TYPE_XPRESS: c_int = 1;
const WIMLIB_EXPORT_FLAG_BOOT: c_int = 0x00000001;
const WIMLIB_ALL_IMAGES: c_int = -1;

#[cfg(not(unix))]
compile_error!("pxeasy-runtime wim wrapper currently supports Unix-like hosts only");

#[repr(C)]
struct WIMStruct {
    _private: [u8; 0],
}

#[link(name = "wim")]
unsafe extern "C" {
    fn wimlib_create_new_wim(ctype: c_int, wim_ret: *mut *mut WIMStruct) -> c_int;
    fn wimlib_open_wim(
        wim_file: *const c_char,
        open_flags: c_int,
        wim_ret: *mut *mut WIMStruct,
    ) -> c_int;
    fn wimlib_export_image(
        src_wim: *mut WIMStruct,
        src_image: c_int,
        dest_wim: *mut WIMStruct,
        dest_name: *const c_char,
        dest_description: *const c_char,
        export_flags: c_int,
    ) -> c_int;
    fn wimlib_add_tree(
        wim: *mut WIMStruct,
        image: c_int,
        fs_source_path: *const c_char,
        wim_target_path: *const c_char,
        add_flags: c_int,
    ) -> c_int;
    fn wimlib_write(
        wim: *mut WIMStruct,
        path: *const c_char,
        image: c_int,
        write_flags: c_int,
        num_threads: c_uint,
    ) -> c_int;
    fn wimlib_overwrite(wim: *mut WIMStruct, write_flags: c_int, num_threads: c_uint) -> c_int;
    fn wimlib_free(wim: *mut WIMStruct);
    fn wimlib_get_error_string(code: c_int) -> *const c_char;
    fn wimlib_global_init(init_flags: c_int) -> c_int;
    fn wimlib_set_print_errors(show_messages: bool);
}

static INIT: OnceLock<Result<(), String>> = OnceLock::new();

pub struct Wim {
    raw: *mut WIMStruct,
}

impl Wim {
    pub fn export_image_to_new_wim(
        source_path: &Path,
        source_image: i32,
        dest_path: &Path,
    ) -> Result<(), String> {
        init_wimlib()?;

        let source = Self::open(source_path, 0)?;
        let dest = Self::create_new()?;
        let code = unsafe {
            wimlib_export_image(
                source.raw,
                source_image,
                dest.raw,
                ptr::null(),
                ptr::null(),
                WIMLIB_EXPORT_FLAG_BOOT,
            )
        };
        if code != 0 {
            return Err(error_message("failed to export WIM image", code));
        }
        dest.write(dest_path)
    }

    pub fn open_for_update(path: &Path) -> Result<Self, String> {
        Self::open(path, WIMLIB_OPEN_FLAG_WRITE_ACCESS)
    }

    fn create_new() -> Result<Self, String> {
        init_wimlib()?;

        let mut raw = ptr::null_mut();
        let code = unsafe { wimlib_create_new_wim(WIMLIB_COMPRESSION_TYPE_XPRESS, &mut raw) };
        if code != 0 {
            return Err(error_message("failed to create WIM", code));
        }
        if raw.is_null() {
            return Err("error: failed to create WIM: libwim returned a null handle".to_string());
        }
        Ok(Self { raw })
    }

    fn open(path: &Path, flags: c_int) -> Result<Self, String> {
        init_wimlib()?;

        let path = path_to_cstring(path)?;
        let mut raw = ptr::null_mut();
        let code = unsafe { wimlib_open_wim(path.as_ptr(), flags, &mut raw) };
        if code != 0 {
            return Err(error_message("failed to open WIM", code));
        }
        if raw.is_null() {
            return Err("error: failed to open WIM: libwim returned a null handle".to_string());
        }
        Ok(Self { raw })
    }

    pub fn replace_file(
        &mut self,
        image: i32,
        host_path: &Path,
        wim_target_path: &str,
    ) -> Result<(), String> {
        self.add_tree(image, host_path, wim_target_path)
    }

    pub fn add_tree(
        &mut self,
        image: i32,
        host_path: &Path,
        wim_target_path: &str,
    ) -> Result<(), String> {
        let host_path = path_to_cstring(host_path)?;
        let wim_target_path = CString::new(wim_target_path)
            .map_err(|_| format!("error: invalid WIM path: {wim_target_path}"))?;
        let code = unsafe {
            wimlib_add_tree(
                self.raw,
                image,
                host_path.as_ptr(),
                wim_target_path.as_ptr(),
                0,
            )
        };
        if code != 0 {
            return Err(error_message("failed to update WIM image", code));
        }
        Ok(())
    }

    pub fn overwrite(self) -> Result<(), String> {
        let raw = self.raw;
        std::mem::forget(self);

        let code = unsafe { wimlib_overwrite(raw, WIMLIB_WRITE_FLAG_REBUILD, 0) };
        unsafe { wimlib_free(raw) };

        if code != 0 {
            return Err(error_message("failed to write WIM", code));
        }
        Ok(())
    }

    fn write(self, path: &Path) -> Result<(), String> {
        let path = path_to_cstring(path)?;
        let raw = self.raw;
        std::mem::forget(self);

        let code = unsafe { wimlib_write(raw, path.as_ptr(), WIMLIB_ALL_IMAGES, 0, 0) };
        unsafe { wimlib_free(raw) };

        if code != 0 {
            return Err(error_message("failed to write WIM", code));
        }
        Ok(())
    }
}

impl Drop for Wim {
    fn drop(&mut self) {
        unsafe { wimlib_free(self.raw) };
    }
}

fn init_wimlib() -> Result<(), String> {
    INIT.get_or_init(|| {
        let code = unsafe { wimlib_global_init(0) };
        if code != 0 {
            return Err(error_message("failed to initialize libwim", code));
        }
        unsafe { wimlib_set_print_errors(false) };
        Ok(())
    })
    .clone()
}

fn error_message(context: &str, code: c_int) -> String {
    let detail = unsafe {
        let ptr = wimlib_get_error_string(code);
        if ptr.is_null() {
            "unknown libwim error".to_string()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    };
    format!("error: {context}: {detail} (code {code})")
}

fn path_to_cstring(path: &Path) -> Result<CString, String> {
    let raw = path.to_str().ok_or_else(|| {
        format!(
            "error: path contains non-UTF-8 characters: {}",
            path.display()
        )
    })?;
    CString::new(raw).map_err(|_| {
        format!(
            "error: path contains interior NUL bytes: {}",
            path.display()
        )
    })
}
