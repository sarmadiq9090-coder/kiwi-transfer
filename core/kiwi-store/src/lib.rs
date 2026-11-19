pub mod destination;
pub mod error;
pub mod fsops;
pub mod hash;
pub mod sanitize;
mod sys;
pub mod template;
pub struct Store;
impl Store { pub fn reset_corrupt_ledger() {} }
