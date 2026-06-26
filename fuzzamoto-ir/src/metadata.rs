use serde::{Deserialize, Serialize};

use crate::{BlockAnnouncement, CompactBlockAnnouncement, GetBlockTxn, RecentBlock};

/// The runtime data observed during the course of harness execution
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PerTestcaseMetadata {
    pub block_txn_request: Vec<GetBlockTxn>,
    pub recent_blocks: Vec<RecentBlock>,
    pub compact_block_announcements: Vec<CompactBlockAnnouncement>,
    pub block_announcements: Vec<BlockAnnouncement>,
}

impl PerTestcaseMetadata {
    #[must_use]
    pub fn new() -> Self {
        Self {
            block_txn_request: Vec::new(),
            recent_blocks: Vec::new(),
            compact_block_announcements: Vec::new(),
            block_announcements: Vec::new(),
        }
    }

    #[must_use]
    pub fn block_txn_request(&self) -> &[GetBlockTxn] {
        &self.block_txn_request
    }

    #[must_use]
    pub fn recent_blocks(&self) -> &[RecentBlock] {
        &self.recent_blocks
    }

    #[must_use]
    pub fn compact_block_announcements(&self) -> &[CompactBlockAnnouncement] {
        &self.compact_block_announcements
    }

    #[must_use]
    pub fn block_announcements(&self) -> &[BlockAnnouncement] {
        &self.block_announcements
    }

    pub fn add_block_tx_request(&mut self, req: GetBlockTxn) {
        self.block_txn_request.push(req);
    }

    pub fn add_compact_block_announcement(&mut self, announcement: CompactBlockAnnouncement) {
        self.compact_block_announcements.push(announcement);
    }

    pub fn add_block_announcement(&mut self, announcement: BlockAnnouncement) {
        self.block_announcements.push(announcement);
    }

    pub fn add_recent_blocks(&mut self, blocks: Vec<RecentBlock>) {
        self.recent_blocks = blocks;
        self.recent_blocks.sort();
    }
}
