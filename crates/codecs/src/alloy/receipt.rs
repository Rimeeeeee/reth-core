//! Compact implementations for Alloy receipt types.

use crate::Compact;
use alloc::vec::Vec;
use alloy_consensus::{
    EthereumReceipt as AlloyEthereumReceipt, FrameReceiptEnvelope,
    ReceiptEnvelope as AlloyReceiptEnvelope, TxType,
};
use alloy_eips::eip8141::FRAME_TX_TYPE;
use alloy_primitives::Log;
use alloy_rlp::{Decodable, Encodable};
use bytes::{Buf, BufMut};
use modular_bitfield::prelude::*;

/// Discriminator for the EIP-8141 receipt envelope compact encoding.
///
/// `0xff` is not a valid [`ReceiptFlags`] value: it would require a three-byte transaction type
/// and a fifteen-byte `u64`. Existing receipt encodings can therefore continue using their
/// unchanged compact representation.
const EIP8141_COMPACT_IDENTIFIER: u8 = u8::MAX;

#[allow(non_snake_case)]
mod flags {
    use super::*;

    /// Bitflag fieldset for receipt compact encoding.
    ///
    /// Used bytes: 1 | Unused bits: 0
    #[bitfield]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct ReceiptFlags {
        pub tx_type_len: B2,
        pub success_len: B1,
        pub cumulative_gas_used_len: B4,
        pub __zstd: B1,
    }

    impl ReceiptFlags {
        /// Deserializes this fieldset and returns it, alongside the original slice in an advanced
        /// position.
        pub fn from(mut buf: &[u8]) -> (Self, &[u8]) {
            (Self::from_bytes([buf.get_u8()]), buf)
        }
    }
}

pub(crate) use flags::ReceiptFlags;

impl<T: Compact> Compact for AlloyEthereumReceipt<T> {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let mut flags = ReceiptFlags::default();
        let mut buffer = bytes::BytesMut::new();

        let tx_type_len = self.tx_type.to_compact(&mut buffer);
        flags.set_tx_type_len(tx_type_len as u8);
        let success_len = self.success.to_compact(&mut buffer);
        flags.set_success_len(success_len as u8);
        let cumulative_gas_used_len = self.cumulative_gas_used.to_compact(&mut buffer);
        flags.set_cumulative_gas_used_len(cumulative_gas_used_len as u8);
        self.logs.to_compact(&mut buffer);

        let zstd = buffer.len() > 7;
        if zstd {
            flags.set___zstd(1);
        }

        let flags = flags.into_bytes();
        buf.put_slice(&flags);
        if zstd {
            reth_zstd_compressors::with_receipt_compressor(|compressor| {
                let compressed = compressor.compress(&buffer).expect("Failed to compress.");
                buf.put(compressed.as_slice());
                flags.len() + compressed.len()
            })
        } else {
            let len = flags.len() + buffer.len();
            buf.put(buffer);
            len
        }
    }

    fn from_compact(buf: &[u8], _len: usize) -> (Self, &[u8]) {
        fn fields<T: Compact>(flags: ReceiptFlags, buf: &[u8]) -> (AlloyEthereumReceipt<T>, &[u8]) {
            let (tx_type, buf) = T::from_compact(buf, flags.tx_type_len() as usize);
            let (success, buf) = bool::from_compact(buf, flags.success_len() as usize);
            let (cumulative_gas_used, buf) =
                u64::from_compact(buf, flags.cumulative_gas_used_len() as usize);
            let (logs, buf) = Vec::<Log>::from_compact(buf, buf.len());
            (AlloyEthereumReceipt { tx_type, success, cumulative_gas_used, logs }, buf)
        }

        let (flags, body) = ReceiptFlags::from(buf);
        if flags.__zstd() == 0 {
            // Uncompressed receipts end after their count-prefixed logs, so `len` is not needed.
            return fields(flags, body)
        }
        // Older encoders wrote the uncompressed size as the `Vec`/`Option` length prefix, which
        // can be larger or smaller than the zstd frame, so take the zstd boundary from the frame.
        let (frame, rest) = body.split_at(reth_zstd_compressors::frame_compressed_size(body));
        let receipt = reth_zstd_compressors::with_receipt_decompressor(|d| {
            fields(flags, d.decompress(frame)).0
        });
        (receipt, rest)
    }
}

impl Compact for AlloyReceiptEnvelope {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: BufMut + AsMut<[u8]>,
    {
        match self {
            AlloyReceiptEnvelope::Legacy(receipt) => {
                standard(TxType::Legacy, &receipt.receipt).to_compact(buf)
            }
            AlloyReceiptEnvelope::Eip2930(receipt) => {
                standard(TxType::Eip2930, &receipt.receipt).to_compact(buf)
            }
            AlloyReceiptEnvelope::Eip1559(receipt) => {
                standard(TxType::Eip1559, &receipt.receipt).to_compact(buf)
            }
            AlloyReceiptEnvelope::Eip4844(receipt) => {
                standard(TxType::Eip4844, &receipt.receipt).to_compact(buf)
            }
            AlloyReceiptEnvelope::Eip7702(receipt) => {
                standard(TxType::Eip7702, &receipt.receipt).to_compact(buf)
            }
            AlloyReceiptEnvelope::Eip8141(receipt) => receipt.to_compact(buf),
        }
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        if buf.first() == Some(&EIP8141_COMPACT_IDENTIFIER) {
            let (receipt, buf) = FrameReceiptEnvelope::from_compact(buf, len);
            return (Self::Eip8141(receipt), buf)
        }

        let (receipt, buf) = AlloyEthereumReceipt::<TxType>::from_compact(buf, len);
        (
            AlloyReceiptEnvelope::try_from(receipt)
                .expect("standard receipt conversion cannot fail"),
            buf,
        )
    }
}

impl Compact for FrameReceiptEnvelope {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: BufMut + AsMut<[u8]>,
    {
        buf.put_u8(EIP8141_COMPACT_IDENTIFIER);
        buf.put_u8(FRAME_TX_TYPE);
        self.encode(buf);
        self.length() + 2
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let encoded = buf.get(..len).expect("EIP-8141 compact receipt length exceeds input");
        let (prefix, mut encoded) = encoded
            .split_first_chunk::<2>()
            .expect("EIP-8141 compact receipt is missing its discriminator");
        assert_eq!(
            *prefix,
            [EIP8141_COMPACT_IDENTIFIER, FRAME_TX_TYPE],
            "invalid EIP-8141 compact receipt discriminator"
        );
        let receipt = Self::decode(&mut encoded)
            .expect("invalid EIP-8141 receipt in compact database encoding");
        assert!(encoded.is_empty(), "trailing bytes in EIP-8141 compact receipt");
        (receipt, &buf[len..])
    }
}

fn standard(tx_type: TxType, receipt: &alloy_consensus::Receipt) -> AlloyEthereumReceipt {
    AlloyEthereumReceipt {
        tx_type,
        success: receipt.status.coerce_status(),
        cumulative_gas_used: receipt.cumulative_gas_used,
        logs: receipt.logs.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip8141::{FrameGasUsed, FrameReceipt, FrameReceiptPayload, FrameStatus};
    use alloy_primitives::Address;
    use proptest::proptest;
    use proptest_arbitrary_interop::arb;

    proptest! {
        #[test]
        fn roundtrip_receipt(receipt in arb::<AlloyEthereumReceipt<TxType>>()) {
            let mut compacted_receipt = Vec::<u8>::new();
            let len = receipt.to_compact(&mut compacted_receipt);
            let (decoded, _) = AlloyEthereumReceipt::<TxType>::from_compact(&compacted_receipt, len);
            assert_eq!(receipt, decoded)
        }
    }

    fn receipt(with_log: bool) -> AlloyEthereumReceipt<TxType> {
        let logs = if with_log {
            vec![Log::new_unchecked(
                alloy_primitives::Address::repeat_byte(0x22),
                vec![alloy_primitives::B256::repeat_byte(0x33)],
                alloy_primitives::Bytes::from_static(b"reth"),
            )]
        } else {
            vec![]
        };
        AlloyEthereumReceipt {
            tx_type: TxType::Eip1559,
            success: true,
            cumulative_gas_used: 21_000,
            logs,
        }
    }

    // Encodings produced by the codec before the `len`/remainder fix. Decoding them proves the
    // on-disk format is unchanged.
    const UNCOMPRESSED: &str = "16520800";
    const COMPRESSED: &str = "9628b52ffd23fc4269613da5000058520801392201337265746802cc80d1c200102c";

    #[test]
    fn receipt_fixtures_and_remainder() {
        for (with_log, fixture) in [(false, UNCOMPRESSED), (true, COMPRESSED)] {
            let receipt = receipt(with_log);
            let fixture = alloy_primitives::hex::decode(fixture).unwrap();
            assert_eq!(fixture[0] >> 7, with_log as u8, "zstd flag");

            let mut buf = Vec::new();
            let len = receipt.to_compact(&mut buf);
            assert_eq!(buf, fixture, "encoding changed");
            assert_eq!(len, buf.len(), "to_compact must return bytes written");

            let (decoded, rest) =
                AlloyEthereumReceipt::<TxType>::from_compact(&fixture, fixture.len());
            assert_eq!(decoded, receipt);
            assert!(rest.is_empty());

            // Followed by trailing bytes: consume only the receipt and return the rest, whether
            // `len` is the receipt's length or the remaining length a struct field passes.
            let mut trailing = fixture.clone();
            trailing.extend_from_slice(&[0xde, 0xad]);
            for len in [len, trailing.len()] {
                let (decoded, rest) = AlloyEthereumReceipt::<TxType>::from_compact(&trailing, len);
                assert_eq!(decoded, receipt);
                assert_eq!(rest, &[0xde, 0xad]);
            }

            // Nested in a Vec, whose element framing uses the returned length.
            let receipts = vec![receipt.clone(), receipt.clone()];
            let mut nested = Vec::new();
            receipts.to_compact(&mut nested);
            let (decoded, rest) =
                Vec::<AlloyEthereumReceipt<TxType>>::from_compact(&nested, nested.len());
            assert_eq!(decoded, receipts);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn decodes_legacy_option_with_oversized_prefix() {
        // `Some(receipt(true))` encoded before the fix: the prefix 0x3e (62) is the uncompressed
        // length, but only the 34-byte compressed body follows.
        let legacy = alloy_primitives::hex::decode(
            "3e9628b52ffd23fc4269613da5000058520801392201337265746802cc80d1c200102c",
        )
        .unwrap();
        let (decoded, _) = Option::<AlloyEthereumReceipt<TxType>>::from_compact(&legacy, 1);
        assert_eq!(decoded, Some(receipt(true)));
    }

    #[test]
    fn decodes_legacy_option_with_undersized_prefix() {
        // `Some(receipt)` encoded before the fix, where zstd grew the body: the prefix 0x38 (56)
        // is the uncompressed length, but a 57-byte receipt follows.
        let legacy = alloy_primitives::hex::decode(
            "388028b52ffd23fc426961375d0100440201352201976eb7813b278b773bcb9c225603ed69d1d4d80ea9adb030c8471b7100238ec30100091802",
        )
        .unwrap();
        let expected = AlloyEthereumReceipt {
            tx_type: TxType::Legacy,
            success: false,
            cumulative_gas_used: 0,
            logs: vec![Log::new_unchecked(
                alloy_primitives::Address::repeat_byte(0x22),
                vec![alloy_primitives::keccak256(b"reth")],
                alloy_primitives::Bytes::new(),
            )],
        };
        let (decoded, rest) = Option::<AlloyEthereumReceipt<TxType>>::from_compact(&legacy, 1);
        assert_eq!(decoded, Some(expected));
        assert!(rest.is_empty());
    }

    #[test]
    fn non_frame_envelope_preserves_existing_compact_encoding() {
        let receipt = AlloyEthereumReceipt {
            tx_type: TxType::Eip1559,
            success: true,
            cumulative_gas_used: 21_000,
            logs: vec![Log::default()],
        };
        let envelope = AlloyReceiptEnvelope::try_from(receipt.clone()).unwrap();
        let mut receipt_buf = Vec::new();
        let mut envelope_buf = Vec::new();

        let receipt_len = receipt.to_compact(&mut receipt_buf);
        let envelope_len = envelope.to_compact(&mut envelope_buf);
        let (decoded, _) = AlloyReceiptEnvelope::from_compact(&envelope_buf, envelope_len);

        assert_eq!(envelope_buf, receipt_buf);
        assert_eq!(envelope_len, receipt_len);
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn frame_receipt_envelope_roundtrip() {
        let envelope = AlloyReceiptEnvelope::Eip8141(
            FrameReceiptPayload {
                cumulative_gas_used: 42_000,
                payer: Address::repeat_byte(0x11),
                frame_receipts: vec![
                    FrameReceipt {
                        status: FrameStatus::Success,
                        gas_used: FrameGasUsed { execution: 21_000, state: 0 },
                        logs: vec![Log::default()],
                    },
                    FrameReceipt {
                        status: FrameStatus::SkippedAtomicBatch,
                        gas_used: FrameGasUsed::default(),
                        logs: Vec::new(),
                    },
                ],
            }
            .into(),
        );
        let mut compact = Vec::new();

        let len = envelope.to_compact(&mut compact);
        let (decoded, remaining) = AlloyReceiptEnvelope::from_compact(&compact, len);

        assert_eq!(compact.first(), Some(&EIP8141_COMPACT_IDENTIFIER));
        assert_eq!(decoded, envelope);
        assert!(remaining.is_empty());

        let AlloyReceiptEnvelope::Eip8141(frame) = &envelope else { unreachable!() };
        let mut expected = vec![0xff, 0x06];
        expected.extend(alloy_rlp::encode(frame.payload()));
        assert_eq!(compact, expected);
        let mut direct = Vec::new();
        assert_eq!(frame.to_compact(&mut direct), len);
        assert_eq!(direct, compact);
        direct.extend_from_slice(&[0xaa, 0xbb]);
        let (decoded, remaining) = FrameReceiptEnvelope::from_compact(&direct, len);
        assert_eq!(&decoded, frame);
        assert_eq!(remaining, &[0xaa, 0xbb]);
    }
}
