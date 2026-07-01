use std::os::raw::{c_char, c_uchar};

// Exposed nyx agent functions.
//
// See docs in `fuzzamoto-nyx-sys/src/nyx-agent.c`
unsafe extern "C" {
    pub fn nyx_init() -> usize;
    pub fn nyx_dump_file_to_host(
        file_name: *const c_char,
        file_name_len: usize,
        data: *const c_uchar,
        len: usize,
    );
    pub fn nyx_get_fuzz_input(data: *const c_uchar, max_size: usize) -> usize;
    pub fn nyx_create_incremental_and_next(
        data: *mut c_uchar,
        resume_position: *mut usize,
    ) -> usize;
    pub fn nyx_skip();
    pub fn nyx_release();
    pub fn nyx_fail(message: *const c_char);
    pub fn nyx_println(message: *const c_char, size: usize);
}
