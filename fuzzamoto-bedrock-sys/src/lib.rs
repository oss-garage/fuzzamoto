use std::os::raw::{c_char, c_uchar};

// Exposed bedrock agent functions.
//
// See docs in `fuzzamoto-bedrock-sys/src/bedrock-agent.c`
unsafe extern "C" {
    pub fn bedrock_init() -> usize;
    pub fn bedrock_get_fuzz_input(data: *mut c_uchar, max_size: usize) -> usize;
    pub fn bedrock_skip();
    pub fn bedrock_release();
    pub fn bedrock_fail(message: *const c_char);
    pub fn bedrock_println(message: *const c_char, size: usize);
    pub fn bedrock_dump_file_to_host(
        name: *const c_char,
        name_len: usize,
        data: *const c_uchar,
        len: usize,
    );
}
