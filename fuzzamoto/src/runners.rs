#[cfg(feature = "nyx")]
use fuzzamoto_nyx_sys::*;

/// `Runner` provides an abstraction for a fuzzamoto test case runner (e.g. run under nyx,
/// libafl-qemu, local system, etc.)
pub trait Runner {
    // Initialize the runner
    fn new() -> Self
    where
        Self: Sized;
    // Get the next fuzz input
    fn get_fuzz_input(&self) -> Vec<u8>;
    // Create an incremental snapshot, return the payload, and save the snapshot prefix
    fn create_incremental_and_next(&self, prefix_index: usize) -> (Vec<u8>, usize);
    // Fail the last test case
    fn fail(&self, message: &str);
    // Skip the last test case
    fn skip(&self);
}

/// `LocalRunner` is a runner that reads the fuzz input from the environment variable `FUZZAMOTO_INPUT`
/// or from stdin if the environment variable is not set.
///
/// This runner is used for reproducing test cases locally without using nyx.
pub struct LocalRunner;
impl Runner for LocalRunner {
    fn new() -> Self {
        Self
    }

    fn get_fuzz_input(&self) -> Vec<u8> {
        use std::io::Read;
        if let Ok(path) = std::env::var("FUZZAMOTO_INPUT") {
            log::info!("Reading input from {:?}", std::env::var("FUZZAMOTO_INPUT"));
            std::fs::read(&path).unwrap_or_else(|_| vec![])
        } else {
            log::info!("Reading input from /dev/stdin");
            let mut buffer = Vec::new();
            std::io::stdin().read_to_end(&mut buffer).unwrap_or(0);
            buffer
        }
    }

    fn create_incremental_and_next(&self, _prefix_index: usize) -> (Vec<u8>, usize) {
        (vec![], 0)
    }

    fn fail(&self, message: &str) {
        log::error!("{message}");
    }

    fn skip(&self) {
        log::warn!("Skipping test case");
    }
}

#[cfg(feature = "nyx")]
pub struct NyxRunner {
    max_input_size: usize,
}
#[cfg(feature = "nyx")]
impl Runner for NyxRunner {
    fn new() -> Self {
        unsafe {
            let max_input_size = nyx_init();
            Self { max_input_size }
        }
    }

    fn get_fuzz_input(&self) -> Vec<u8> {
        let mut data = vec![0u8; self.max_input_size];
        let len = unsafe { nyx_get_fuzz_input(data.as_mut_ptr(), data.len()) };
        data.truncate(len);
        data
    }

    fn create_incremental_and_next(&self, prefix_index: usize) -> (Vec<u8>, usize) {
        let mut data = vec![0u8; self.max_input_size];
        let mut pos = prefix_index;
        let len = unsafe { nyx_create_incremental_and_next(data.as_mut_ptr(), &mut pos) };
        data.truncate(len);
        (data, pos)
    }

    fn fail(&self, message: &str) {
        let c_message = std::ffi::CString::new(message).unwrap_or_default();
        unsafe {
            // this println is necessary as libafl doesn't have the ability to read the message if we print it through nyx_fail
            // therefore we can only use nyx_println to print the message and receive it through `stdout` buffer of `NyxExecutor`
            nyx_println(c_message.as_ptr(), c_message.count_bytes());
            nyx_fail(c_message.as_ptr());
        }
    }

    fn skip(&self) {
        unsafe {
            nyx_skip();
        }
    }
}
#[cfg(feature = "nyx")]
impl Drop for NyxRunner {
    fn drop(&mut self) {
        unsafe {
            nyx_release();
        }
    }
}

#[cfg(feature = "nyx")]
type DefaultRunner = NyxRunner;
#[cfg(not(feature = "nyx"))]
type DefaultRunner = LocalRunner;

pub struct StdRunner {
    runner: DefaultRunner,
}

impl Runner for StdRunner {
    fn new() -> Self {
        Self {
            runner: DefaultRunner::new(),
        }
    }

    fn get_fuzz_input(&self) -> Vec<u8> {
        self.runner.get_fuzz_input()
    }

    fn create_incremental_and_next(&self, prefix_index: usize) -> (Vec<u8>, usize) {
        self.runner.create_incremental_and_next(prefix_index)
    }

    fn fail(&self, message: &str) {
        self.runner.fail(message);
    }

    fn skip(&self) {
        self.runner.skip();
    }
}
