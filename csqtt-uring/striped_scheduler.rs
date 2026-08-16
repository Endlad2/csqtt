// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

pub const SMALL_PACKET_LIMIT: usize = 384;
pub const DOOMSDAY_PACKET_LIMIT: usize = 133;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketClass {
    Doomsday,
    Small,
    Bulk,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StripedScheduler {
    doomsday_packet: u64,
    small_packet: u64,
    bulk_packet: u64,
}

impl StripedScheduler {
    #[inline(always)]
    pub fn select(&mut self, count: usize, packet_len: usize) -> Option<usize> {
        if count == 0 {
            return None;
        }
        let index = match packet_class(packet_len) {
            PacketClass::Doomsday => {
                let value = self.doomsday_packet;
                self.doomsday_packet = self.doomsday_packet.wrapping_add(1);
                value as usize % count
            }
            PacketClass::Small => {
                let value = self.small_packet;
                self.small_packet = self.small_packet.wrapping_add(1);
                (value / 2) as usize % count
            }
            PacketClass::Bulk => {
                let value = self.bulk_packet;
                self.bulk_packet = self.bulk_packet.wrapping_add(1);
                (value / 32) as usize % count
            }
        };
        Some(index)
    }
}

#[inline(always)]
pub fn packet_class(length: usize) -> PacketClass {
    if length <= DOOMSDAY_PACKET_LIMIT {
        PacketClass::Doomsday
    } else if length <= SMALL_PACKET_LIMIT {
        PacketClass::Small
    } else {
        PacketClass::Bulk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifications_match_legacy_boundaries() {
        assert_eq!(packet_class(0), PacketClass::Doomsday);
        assert_eq!(packet_class(133), PacketClass::Doomsday);
        assert_eq!(packet_class(134), PacketClass::Small);
        assert_eq!(packet_class(384), PacketClass::Small);
        assert_eq!(packet_class(385), PacketClass::Bulk);
    }

    #[test]
    fn selection_is_always_constant_time_single_index() {
        for count in [
            9, 18, 27, 36, 45, 54, 63, 72, 81, 90, 99, 108, 117, 126, 135, 144, 153, 162,
        ] {
            let mut scheduler = StripedScheduler::default();
            for length in [64, 200, 1200] {
                for _ in 0..100_000 {
                    assert!(
                        scheduler
                            .select(count, length)
                            .is_some_and(|index| index < count)
                    );
                }
            }
        }
    }

    #[test]
    fn stripe_weights_match_new_distribution() {
        let mut scheduler = StripedScheduler::default();
        for _ in 0..32 {
            assert_eq!(scheduler.select(2, 1200), Some(0));
        }
        assert_eq!(scheduler.select(2, 1200), Some(1));

        let mut scheduler = StripedScheduler::default();
        for _ in 0..2 {
            assert_eq!(scheduler.select(2, 200), Some(0));
        }
        assert_eq!(scheduler.select(2, 200), Some(1));

        let mut scheduler = StripedScheduler::default();
        assert_eq!(scheduler.select(2, 64), Some(0));
        assert_eq!(scheduler.select(2, 64), Some(1));
    }
}
