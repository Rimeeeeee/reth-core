//! Compact implementation for [`TxEip8141`].

use crate::Compact;
use alloy_consensus::TxEip8141;
use alloy_eips::{eip2718::Encodable2718, eip8141::FRAME_TX_TYPE};
use alloy_rlp::Header;

impl Compact for TxEip8141 {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let len = self.encode_2718_len();
        self.encode_2718(buf);
        len
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let mut encoded =
            buf.get(..len).expect("EIP-8141 compact transaction length exceeds input");
        // Compact storage must roundtrip structurally representable transactions, including
        // old test vectors with overflowing aggregate gas. Network admission validates budgets
        // independently; applying that validation here breaks the existing database encoding.
        let (&tx_type, payload) =
            encoded.split_first().expect("empty EIP-8141 compact transaction");
        assert_eq!(tx_type, FRAME_TX_TYPE, "invalid EIP-8141 compact transaction type");
        encoded = payload;
        let mut fields = Header::decode_bytes(&mut encoded, true)
            .expect("invalid EIP-8141 compact transaction list");
        let tx = Self::rlp_decode_fields(&mut fields)
            .expect("invalid EIP-8141 transaction in compact database encoding");
        assert!(fields.is_empty(), "trailing EIP-8141 compact transaction fields");
        let consumed = len - encoded.len();
        (tx, &buf[consumed..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::{
        eip2718::Decodable2718,
        eip8141::{Frame, FrameLimits, FrameMode},
    };
    use alloy_primitives::{Address, Bytes};

    #[test]
    fn frame_transaction_roundtrip() {
        let tx = TxEip8141 {
            chain_id: 1,
            nonce: 7,
            sender: Address::repeat_byte(0x11),
            frames: vec![Frame {
                mode: FrameMode::Sender,
                data: Bytes::copy_from_slice(&[0xaa, 0xbb]),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut compact = Vec::new();

        let len = tx.to_compact(&mut compact);
        let (decoded, remaining) = TxEip8141::from_compact(&compact, len);

        assert_eq!(decoded, tx);
        assert!(remaining.is_empty());
    }
    #[test]
    fn overflowing_frame_budgets_preserve_compact_encoding() {
        for limits in [
            vec![
                FrameLimits { execution: u64::MAX, state: 0 },
                FrameLimits { execution: 1, state: 0 },
            ],
            vec![
                FrameLimits { execution: 0, state: u64::MAX },
                FrameLimits { execution: 0, state: 1 },
            ],
            vec![FrameLimits { execution: u64::MAX, state: 1 }],
        ] {
            let tx = TxEip8141 {
                frames: limits
                    .into_iter()
                    .map(|limits| Frame { limits, ..Default::default() })
                    .collect(),
                ..Default::default()
            };
            let mut compact = Vec::new();
            let len = tx.to_compact(&mut compact);
            assert!(TxEip8141::decode_2718_exact(&compact).is_err());
            compact.extend_from_slice(&[0xaa, 0xbb]);
            let (decoded, remaining) = TxEip8141::from_compact(&compact, len);
            assert_eq!(decoded, tx);
            assert_eq!(remaining, &[0xaa, 0xbb]);
            let mut reencoded = Vec::new();
            decoded.to_compact(&mut reencoded);
            assert_eq!(reencoded, compact[..len]);
        }
    }
}
