//! HyperCraft is a VMM crate.
//! 
//! Only For CPU Virtualization
//! Memory Virtualization is in `guest_page_table` crate.

#![no_std]
#![allow(
    clippy::upper_case_acronyms,
    clippy::single_component_path_imports,
    clippy::collapsible_match,
    clippy::default_constructed_unit_structs,
)]
#![deny(missing_docs, warnings)]
#![feature(naked_functions, asm_const, negative_impls, stdsimd)]

extern crate alloc;

#[macro_use]
extern crate log;

// Auto Compile
#[cfg(target_arch = "riscv64")]
#[path = "arch/riscv/mod.rs"]
mod arch;
#[cfg(target_arch = "x86_64")]
#[path = "arch/x86/mod.rs"]
mod arch;
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch/mod.rs"]
mod arch;

mod hal;
mod traits;
mod vcpus;

/// HyperCraft Result Define.
pub type HyperResult<T = ()> = Result<T, HyperError>;

pub use arch::{
    init_hv_runtime, GprIndex, HyperCallMsg, PerCpu, VCpu, VmExitInfo, VM, 
};

pub use traits::VmTrait;
pub use hal::HyperCraftHal;
pub use vcpus::VmCpus;

/// The error type for hypervisor operation failures.
#[derive(Debug, PartialEq)]
pub enum HyperError {
    /// Internal error.
    Internal,
    /// No supported error.
    NotSupported,
    /// No memory error.
    NoMemory,
    /// Invalid parameter error.
    InvalidParam,
    /// Invalid instruction error.
    InvalidInstruction,
    /// Memory out of range error.
    OutOfRange,
    /// Bad state error.
    BadState,
    /// Not found error.
    NotFound,
    /// Fetch instruction error.
    FetchFault,
    /// Page fault error.
    PageFault,
    /// Decode error.
    DecodeError,
}
