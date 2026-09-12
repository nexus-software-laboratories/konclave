#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod config;
mod runtime;

pub use runtime::{check_health, run_until};
