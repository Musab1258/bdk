//! Compact block filters sync over RPC. For more details refer to [BIP157][0].
//!
//! This module is home to [`FilterIter`], a structure that returns bitcoin blocks by matching
//! a list of script pubkeys against a [BIP158][1] [`BlockFilter`].
//!
//! [0]: https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki
//! [1]: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki

use bdk_core::collections::BTreeMap;
use core::fmt;

use bdk_core::bitcoin;
use bdk_core::{BlockId, CheckPoint};
use bitcoin::{
    bip158::{self, BlockFilter},
    Block, BlockHash, ScriptBuf,
};
use bitcoincore_rpc;
use bitcoincore_rpc::RpcApi;

/// Block height
type Height = u32;

/// Type that generates block [`Event`]s by matching a list of script pubkeys against a
/// [`BlockFilter`].
#[derive(Debug)]
pub struct FilterIter<'c, C> {
    // RPC client
    client: &'c C,
    // SPK inventory
    spks: Vec<ScriptBuf>,
    // local cp
    cp: Option<CheckPoint>,
    // blocks map
    blocks: BTreeMap<Height, BlockHash>,
    // best height counter
    height: Height,
    // stop height
    stop: Height,
}

impl<'c, C: RpcApi> FilterIter<'c, C> {
    /// Construct [`FilterIter`] from a given `client` and start `height`.
    pub fn new_with_height(client: &'c C, height: u32) -> Self {
        Self {
            client,
            spks: vec![],
            cp: None,
            blocks: BTreeMap::new(),
            height,
            stop: 0,
        }
    }

    /// Construct [`FilterIter`] from a given `client` and [`CheckPoint`].
    pub fn new_with_checkpoint(client: &'c C, cp: CheckPoint) -> Self {
        let mut filter_iter = Self::new_with_height(client, cp.height());
        filter_iter.cp = Some(cp);
        filter_iter
    }

    /// Extends `self` with an iterator of spks.
    pub fn add_spks(&mut self, spks: impl IntoIterator<Item = ScriptBuf>) {
        self.spks.extend(spks)
    }

    /// Add spk to the list of spks to scan with.
    pub fn add_spk(&mut self, spk: ScriptBuf) {
        self.spks.push(spk);
    }

    /// Get the next filter and increment the current best height.
    ///
    /// Returns `Ok(None)` when the stop height is exceeded.
    fn next_filter(&mut self) -> Result<Option<NextFilter>, Error> {
        if self.height > self.stop {
            return Ok(None);
        }
        let height = self.height;
        let hash = match self.blocks.get(&height) {
            Some(h) => *h,
            None => self.client.get_block_hash(height as u64)?,
        };
        let filter_bytes = self.client.get_block_filter(&hash)?.filter;
        let filter = BlockFilter::new(&filter_bytes);
        self.height += 1;
        Ok(Some((BlockId { height, hash }, filter)))
    }

    /// Get the remote tip.
    ///
    /// Returns `None` if the remote height is not strictly greater than the height of this
    /// [`FilterIter`].
    pub fn get_tip(&mut self) -> Result<Option<BlockId>, Error> {
        let tip_hash = self.client.get_best_block_hash()?;
        let mut header = self.client.get_block_header_info(&tip_hash)?;
        let tip_height = header.height as u32;
        if self.height >= tip_height {
            // nothing to do
            return Ok(None);
        }
        self.blocks.insert(tip_height, tip_hash);

        // if we have a checkpoint we use a lookback of ten blocks
        // to ensure consistency of the local chain
        if let Some(cp) = self.cp.as_ref() {
            // adjust start height to point of agreement + 1
            let base = self.find_base_with(cp.clone())?;
            self.height = base.height + 1;

            for _ in 0..9 {
                let hash = match header.previous_block_hash {
                    Some(hash) => hash,
                    None => break,
                };
                header = self.client.get_block_header_info(&hash)?;
                let height = header.height as u32;
                if height < self.height {
                    break;
                }
                self.blocks.insert(height, hash);
            }
        }

        self.stop = tip_height;

        Ok(Some(BlockId {
            height: tip_height,
            hash: tip_hash,
        }))
    }
}

/// Alias for a compact filter and associated block id.
type NextFilter = (BlockId, BlockFilter);

/// Event inner type
#[derive(Debug, Clone)]
pub struct EventInner {
    /// Height
    pub height: Height,
    /// Block
    pub block: Block,
}

/// Kind of event produced by [`FilterIter`].
#[derive(Debug, Clone)]
pub enum Event {
    /// Block
    Block(EventInner),
    /// No match
    NoMatch(Height),
}

impl Event {
    /// Whether this event contains a matching block.
    pub fn is_match(&self) -> bool {
        matches!(self, Event::Block(_))
    }

    /// Get the height of this event.
    pub fn height(&self) -> Height {
        match self {
            Self::Block(EventInner { height, .. }) => *height,
            Self::NoMatch(h) => *h,
        }
    }
}

impl<C: RpcApi> Iterator for FilterIter<'_, C> {
    type Item = Result<Event, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        (|| -> Result<_, Error> {
            loop {
                let next_filter = self.next_filter()?;
                if let Some((block, filter)) = next_filter {
                    let height = block.height;
                    let hash = block.hash;

                    // Enhanced reorg detection logic
                    if height > 0 {
                        let prev_height = height - 1;

                        // Get previous block hash from cache or node
                        let prev_hash = match self.blocks.get(&prev_height).copied() {
                            Some(hash) => hash,
                            None => self.client.get_block_hash(prev_height as u64)?,
                        };

                        // Verify chain continuity
                        let current_header = self.client.get_block_header_info(&hash)?;
                        if current_header.previous_block_hash != Some(prev_hash) {
                            // Reorg detected: find fork point
                            let fork_height = self.find_fork_point(prev_height)?;

                            // Reset state to fork height
                            self.height = fork_height;
                            self.blocks.retain(|h, _| *h <= fork_height);

                            continue; // Restart processing from fork height
                        }
                    }

                    // Existing filter matching logic
                    if self.spks.is_empty() {
                        return Err(Error::NoScripts);
                    } else if filter
                        .match_any(&hash, self.spks.iter().map(|script| script.as_bytes()))
                        .map_err(Error::Bip158)?
                    {
                        let block = self.client.get_block(&hash)?;
                        self.blocks.insert(height, hash);
                        let inner = EventInner { height, block };
                        return Ok(Some(Event::Block(inner)));
                    } else {
                        return Ok(Some(Event::NoMatch(height)));
                    }
                } else {
                    return Ok(None);
                }
            }
        })()
        .transpose()
    }
}

impl<C: RpcApi> FilterIter<'_, C> {
    /// Returns the point of agreement between `self` and the given `cp`.
    fn find_base_with(&mut self, mut cp: CheckPoint) -> Result<BlockId, Error> {
        loop {
            let height = cp.height();
            let fetched_hash = match self.blocks.get(&height) {
                Some(hash) => *hash,
                None if height == 0 => cp.hash(),
                _ => self.client.get_block_hash(height as _)?,
            };
            if cp.hash() == fetched_hash {
                // ensure this block also exists in self
                self.blocks.insert(height, cp.hash());
                return Ok(cp.block_id());
            }
            // remember conflicts
            self.blocks.insert(height, fetched_hash);
            cp = cp.prev().expect("must break before genesis");
        }
    }

    fn find_fork_point(&self, current_height: u32) -> Result<u32, Error> {
        // Try a quick check of the immediate previous block first (common case)
        if current_height > 0 {
            let prev_height = current_height - 1;
            let prev_hash = self.client.get_block_hash(prev_height as u64)?;
            let prev_header = self.client.get_block_header_info(&prev_hash)?;

            // If previous block links properly to its parent, it's valid
            if prev_height == 0
                || prev_header.previous_block_hash.is_some()
                    && prev_header.previous_block_hash
                        == Some(self.client.get_block_hash((prev_height - 1) as u64)?)
            {
                return Ok(prev_height);
            }
        }

        // Binary search for fork point
        let max_lookback = 10; // Adjust based on security needs
        let min_height = current_height.saturating_sub(max_lookback);

        let mut low = min_height;
        let mut high = current_height.saturating_sub(1);

        while low <= high {
            let mid = low + (high - low) / 2;

            // Check if this block is valid in the chain
            let hash = self.client.get_block_hash(mid as u64)?;
            let header = self.client.get_block_header_info(&hash)?;

            let is_valid = if mid == 0 {
                true // Genesis is always valid
            } else {
                let prev_hash = self.client.get_block_hash((mid - 1) as u64)?;
                header.previous_block_hash == Some(prev_hash)
            };

            if is_valid {
                // Check if the next block is invalid, which would make this our fork point
                if mid == high || {
                    let next_hash = self.client.get_block_hash((mid + 1) as u64)?;
                    let next_header = self.client.get_block_header_info(&next_hash)?;
                    next_header.previous_block_hash != Some(hash)
                } {
                    return Ok(mid);
                }
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }

        // Fall back to lowest valid block or genesis
        Ok(low.saturating_sub(1))
    }

    /// Returns a chain update from the newly scanned blocks.
    ///
    /// Returns `None` if this [`FilterIter`] was not constructed using a [`CheckPoint`], or
    /// if no blocks have been fetched for example by using [`get_tip`](Self::get_tip).
    pub fn chain_update(&mut self) -> Option<CheckPoint> {
        if self.cp.is_none() || self.blocks.is_empty() {
            return None;
        }

        // note: to connect with the local chain we must guarantee that `self.blocks.first()`
        // is also the point of agreement with `self.cp`.
        Some(
            CheckPoint::from_block_ids(self.blocks.iter().map(BlockId::from))
                .expect("blocks must be in order"),
        )
    }
}

/// Errors that may occur during a compact filters sync.
#[derive(Debug)]
pub enum Error {
    /// bitcoin bip158 error
    Bip158(bip158::Error),
    /// attempted to scan blocks without any script pubkeys
    NoScripts,
    /// `bitcoincore_rpc` error
    Rpc(bitcoincore_rpc::Error),
}

impl From<bitcoincore_rpc::Error> for Error {
    fn from(e: bitcoincore_rpc::Error) -> Self {
        Self::Rpc(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bip158(e) => e.fmt(f),
            Self::NoScripts => write!(f, "no script pubkeys were provided to match with"),
            Self::Rpc(e) => e.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
