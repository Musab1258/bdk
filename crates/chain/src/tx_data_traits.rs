use bitcoin::{Block, BlockHash, OutPoint, Script, Transaction, TxOut};

use crate::BlockId;

/// Trait to do something with every txout contained in a structure.
///
/// We would prefer to just work with things that can give us an `Iterator<Item=(OutPoint, &TxOut)>`
/// here, but rust's type system makes it extremely hard to do this (without trait objects).
pub trait ForEachTxOut {
    /// The provided closure `f` will be called with each `outpoint/txout` pair.
    fn for_each_txout(&self, f: impl FnMut((OutPoint, &TxOut)));
}

impl ForEachTxOut for Block {
    fn for_each_txout(&self, mut f: impl FnMut((OutPoint, &TxOut))) {
        for tx in self.txdata.iter() {
            tx.for_each_txout(&mut f)
        }
    }
}

impl ForEachTxOut for Transaction {
    fn for_each_txout(&self, mut f: impl FnMut((OutPoint, &TxOut))) {
        let txid = self.txid();
        for (i, txout) in self.output.iter().enumerate() {
            f((
                OutPoint {
                    txid,
                    vout: i as u32,
                },
                txout,
            ))
        }
    }
}

/// Trait that "anchors" blockchain data in a specific block of height and hash.
///
/// This trait is typically associated with blockchain data such as transactions.
pub trait BlockAnchor:
    core::fmt::Debug + Clone + Eq + PartialOrd + Ord + core::hash::Hash + Send + Sync + 'static
{
    /// Returns the [`BlockId`] that the associated blockchain data is "anchored" in.
    fn anchor_block(&self) -> BlockId;
}

impl<A: BlockAnchor> BlockAnchor for &'static A {
    fn anchor_block(&self) -> BlockId {
        <A as BlockAnchor>::anchor_block(self)
    }
}

impl BlockAnchor for (u32, BlockHash) {
    fn anchor_block(&self) -> BlockId {
        (*self).into()
    }
}

/// Represents an index of transaction data.
pub trait TxIndex {
    /// The resultant "additions" when new transaction data is indexed.
    type Additions;

    /// Scan and index the given `outpoint` and `txout`.
    fn index_txout(&mut self, outpoint: OutPoint, txout: &TxOut) -> Self::Additions;

    /// Scan and index the given transaction.
    fn index_tx(&mut self, tx: &Transaction) -> Self::Additions;

    /// Apply additions to itself.
    fn apply_additions(&mut self, additions: Self::Additions);

    /// A transaction is relevant if it contains a txout with a script_pubkey that we own, or if it
    /// spends an already-indexed outpoint that we have previously indexed.
    fn is_tx_relevant(&self, tx: &Transaction) -> bool;

    /// Returns whether the script pubkey is owned by us.
    fn is_spk_owned(&self, spk: &Script) -> bool;
}
