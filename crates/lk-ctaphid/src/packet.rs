//! Packet layout (CTAP 2.1 §11.2.4): parsing host reports and fragmenting device
//! messages into zero-padded 64-byte reports.

use crate::protocol::{CONT_DATA_LEN, INIT_DATA_LEN, MAX_PAYLOAD, MAX_SEQ, REPORT_LEN, cmd, err};

/// Bit 7 of byte 4 marks an initialization packet (CTAP 2.1 §11.2.4).
const INIT_FLAG: u8 = 0x80;

/// One received report, split into its header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Packet<'a> {
    /// `CID(4) CMD(1, bit 7 set) BCNTH BCNTL DATA(57)`.
    Init {
        cid: u32,
        /// The command code with bit 7 cleared.
        cmd: u8,
        /// Total message length announced by the host.
        bcnt: u16,
        /// All 57 data bytes, including any padding beyond `bcnt`.
        data: &'a [u8],
    },
    /// `CID(4) SEQ(1, bit 7 clear) DATA(59)`.
    Cont {
        cid: u32,
        seq: u8,
        /// All 59 data bytes, including any padding beyond the message end.
        data: &'a [u8],
    },
}

/// Splits a report into its packet fields.
pub(crate) fn parse(report: &[u8; REPORT_LEN]) -> Packet<'_> {
    let [c0, c1, c2, c3, tag, rest @ ..] = report;
    let cid = u32::from_be_bytes([*c0, *c1, *c2, *c3]);
    if tag & INIT_FLAG == 0 {
        return Packet::Cont {
            cid,
            seq: *tag,
            data: rest,
        };
    }
    let [bcnt_hi, bcnt_lo, data @ ..] = rest;
    Packet::Init {
        cid,
        cmd: tag & !INIT_FLAG,
        bcnt: u16::from_be_bytes([*bcnt_hi, *bcnt_lo]),
        data,
    }
}

/// Builds the initialization packet header and copies as much of `payload` as fits.
fn init_packet(cid: u32, command: u8, bcnt: u16, first: &[u8]) -> [u8; REPORT_LEN] {
    let mut report = [0u8; REPORT_LEN];
    let (head, body) = report.split_at_mut(7);
    head[..4].copy_from_slice(&cid.to_be_bytes());
    head[4] = INIT_FLAG | (command & !INIT_FLAG);
    head[5..].copy_from_slice(&bcnt.to_be_bytes());
    body[..first.len()].copy_from_slice(first);
    report
}

/// Builds one continuation packet.
fn cont_packet(cid: u32, seq: u8, chunk: &[u8]) -> [u8; REPORT_LEN] {
    let mut report = [0u8; REPORT_LEN];
    let (head, body) = report.split_at_mut(5);
    head[..4].copy_from_slice(&cid.to_be_bytes());
    head[4] = seq;
    body[..chunk.len()].copy_from_slice(chunk);
    report
}

/// Frames a message that fits in one initialization packet (at most 57 bytes).
///
/// Longer data is cut to 57 bytes; callers only pass the fixed short payloads of
/// `CTAPHID_ERROR`, `CTAPHID_KEEPALIVE`, `CTAPHID_INIT`, `CTAPHID_WINK` and `CTAPHID_LOCK`.
pub(crate) fn single(cid: u32, command: u8, data: &[u8]) -> [u8; REPORT_LEN] {
    let data = data.get(..INIT_DATA_LEN).unwrap_or(data);
    // `data.len() <= 57`, so the conversion cannot fail.
    let bcnt = u16::try_from(data.len()).unwrap_or(0);
    init_packet(cid, command, bcnt, data)
}

/// A `CTAPHID_ERROR` report (CTAP 2.1 §11.2.9.1.6).
pub(crate) fn error(cid: u32, code: u8) -> [u8; REPORT_LEN] {
    single(cid, cmd::ERROR, &[code])
}

/// Fragments a device message into one initialization packet followed by continuation
/// packets with SEQ 0, 1, … (CTAP 2.1 §11.2.4). Unused bytes are zero.
///
/// A payload longer than [`MAX_PAYLOAD`] cannot be framed; the channel then receives
/// `ERR_OTHER` instead (model policy: no application response is that long).
pub(crate) fn fragment(cid: u32, command: u8, payload: &[u8]) -> Vec<[u8; REPORT_LEN]> {
    let bcnt = match u16::try_from(payload.len()) {
        Ok(bcnt) if payload.len() <= MAX_PAYLOAD => bcnt,
        _ => return vec![error(cid, err::OTHER)],
    };
    let (first, rest) = payload.split_at(payload.len().min(INIT_DATA_LEN));
    let mut reports = Vec::with_capacity(1 + rest.len().div_ceil(CONT_DATA_LEN));
    reports.push(init_packet(cid, command, bcnt, first));
    reports.extend(
        (0..=MAX_SEQ)
            .zip(rest.chunks(CONT_DATA_LEN))
            .map(|(seq, chunk)| cont_packet(cid, seq, chunk)),
    );
    reports
}

#[cfg(test)]
mod tests {
    use super::*;

    // Layouts from CTAP 2.1 §11.2.4 (initialization and continuation packets).

    #[test]
    fn parses_initialization_packet() {
        let mut report = [0u8; REPORT_LEN];
        report[..7].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x90, 0x01, 0x02]);
        report[7] = 0xAA;
        report[63] = 0xBB;
        match parse(&report) {
            Packet::Init {
                cid,
                cmd,
                bcnt,
                data,
            } => {
                assert_eq!(cid, 0x1234_5678);
                assert_eq!(cmd, 0x10);
                assert_eq!(bcnt, 0x0102);
                assert_eq!(data.len(), INIT_DATA_LEN);
                assert_eq!(data[0], 0xAA);
                assert_eq!(data[56], 0xBB);
            }
            other => panic!("expected an initialization packet, got {other:?}"),
        }
    }

    #[test]
    fn parses_continuation_packet() {
        let mut report = [0u8; REPORT_LEN];
        report[..5].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x7F]);
        report[5] = 0xCC;
        match parse(&report) {
            Packet::Cont { cid, seq, data } => {
                assert_eq!(cid, 0xFFFF_FFFF);
                assert_eq!(seq, 0x7F);
                assert_eq!(data.len(), CONT_DATA_LEN);
                assert_eq!(data[0], 0xCC);
            }
            other => panic!("expected a continuation packet, got {other:?}"),
        }
    }

    #[test]
    fn fragments_at_packet_boundaries() {
        // 57 bytes fill the initialization packet; 58 and 116 need one continuation
        // packet; 117 needs two (57 + 59 = 116).
        for (len, packets) in [(0, 1), (57, 1), (58, 2), (116, 2), (117, 3), (7609, 129)] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let reports = fragment(7, cmd::PING, &payload);
            assert_eq!(reports.len(), packets, "length {len}");
            assert_eq!(reports[0][4], 0x81);
            assert_eq!(
                usize::from(u16::from_be_bytes([reports[0][5], reports[0][6]])),
                len
            );
            for (seq, report) in reports.iter().skip(1).enumerate() {
                assert_eq!(usize::from(report[4]), seq);
            }
            let mut joined = reports[0][7..].to_vec();
            for report in &reports[1..] {
                joined.extend_from_slice(&report[5..]);
            }
            assert!(
                joined[len..].iter().all(|&b| b == 0),
                "zero padding, length {len}"
            );
            joined.truncate(len);
            assert_eq!(joined, payload);
        }
    }

    #[test]
    fn oversized_payload_becomes_err_other() {
        let reports = fragment(9, cmd::CBOR, &[0u8; MAX_PAYLOAD + 1]);
        assert_eq!(reports, vec![error(9, err::OTHER)]);
    }

    #[test]
    fn error_report_layout() {
        let report = error(0x0102_0304, err::CHANNEL_BUSY);
        let mut expected = [0u8; REPORT_LEN];
        expected[..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0xBF, 0x00, 0x01, 0x06]);
        assert_eq!(report, expected);
    }
}
