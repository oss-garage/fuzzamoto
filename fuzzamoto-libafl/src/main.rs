#[cfg(target_os = "linux")]
#[cfg(all(feature = "nyx", feature = "bedrock"))]
compile_error!("features `nyx` and `bedrock` are mutually exclusive");
#[cfg(not(any(feature = "nyx", feature = "bedrock")))]
compile_error!("one of the `nyx` or `bedrock` backend features must be enabled");

#[cfg(feature = "bedrock")]
mod bedrock;
mod client;
#[cfg(target_os = "linux")]
mod feedbacks;
#[cfg(target_os = "linux")]
mod fuzzer;
#[cfg(target_os = "linux")]
mod input;
#[cfg(target_os = "linux")]
mod instance;
#[cfg(target_os = "linux")]
mod monitor;
#[cfg(target_os = "linux")]
mod mutators;
#[cfg(target_os = "linux")]
mod options;
#[cfg(target_os = "linux")]
mod schedulers;
#[cfg(target_os = "linux")]
mod stages;

#[cfg(target_os = "linux")]
use crate::fuzzer::Fuzzer;

#[cfg(target_os = "linux")]
pub fn main() {
    env_logger::init();
    Fuzzer::new().fuzz().unwrap();
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("fuzzamoto-libafl is only supported on linux!");
}
