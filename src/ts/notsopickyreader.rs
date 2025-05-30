use crate::ts::payload::{Bytes, Null, Pat, Pes, Pmt};
use crate::ts::{AdaptationField, Pid, TsHeader, TsPacket, TsPayload, PidKind};
use crate::{ErrorKind, Result};
use std::collections::HashMap;
use std::io::Read;

/// TS packet reader.
#[derive(Debug)]
pub struct TsPacketNotSoPickyReader {
    pids: HashMap<Pid, PidKind>,
}

impl TsPacketNotSoPickyReader {
    /// Makes a new `TsPacketNotSoPickyReader` instance.
    pub fn new() -> Self {
        TsPacketNotSoPickyReader {
            pids: HashMap::new(),
        }
    }

    /// Read and parses ts packet from provided buffer
    pub fn read_ts_packet(&mut self, buf: &[u8]) -> Result<Option<TsPacket>> {
        let mut reader = buf.take(TsPacket::SIZE as u64);
        let mut peek = [0; 1];
        let eos = track_io!(reader.read(&mut peek))? == 0;
        if eos {
            return Ok(None);
        }

        let (header, adaptation_field_control, payload_unit_start_indicator) =
            track!(TsHeader::read_from(peek.chain(&mut reader)))?;

        let adaptation_field = if adaptation_field_control.has_adaptation_field() {
            track!(AdaptationField::read_from(&mut reader))?
        } else {
            None
        };

        let payload = if adaptation_field_control.has_payload() {
            let payload = match header.pid.as_u16() {
                Pid::PAT => {
                    let pat = track!(Pat::read_from(&mut reader))?;
                    for pa in &pat.table {
                        self.pids.insert(pa.program_map_pid, PidKind::Pmt);
                    }
                    TsPayload::Pat(pat)
                }
                Pid::NULL => {
                    let null = track!(Null::read_from(&mut reader))?;
                    TsPayload::Null(null)
                }
                0x01..=0x1F | 0x1FFB => {
                    // Unknown (unsupported) packets
                    let bytes = track!(Bytes::read_from(&mut reader))?;
                    TsPayload::Raw(bytes)
                }
                _ => {
                    if let Some(kind) = self.pids.get(&header.pid).cloned() {
                        match kind {
                            PidKind::Pmt => {
                                let pmt = track!(Pmt::read_from(&mut reader))?;
                                for es in &pmt.es_info {
                                    self.pids.insert(es.elementary_pid, PidKind::Pes);
                                }
                                TsPayload::Pmt(pmt)
                            }
                            PidKind::Pes => {
                                if payload_unit_start_indicator {
                                    let pes = track!(Pes::read_from(&mut reader))?;
                                    TsPayload::Pes(pes)
                                } else {
                                    let bytes = track!(Bytes::read_from(&mut reader))?;
                                    TsPayload::Raw(bytes)
                                }
                            }
                        }
                    } else {
                        let bytes = track!(Bytes::read_from(&mut reader))?;

                        TsPayload::Raw(bytes)
                    }
                }
            };
            Some(payload)
        } else {
            None
        };

        track_assert_eq!(reader.limit(), 0, ErrorKind::InvalidInput);
        Ok(Some(TsPacket {
            header,
            adaptation_field,
            payload,
        }))
    }
}
