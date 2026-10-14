//! Random LSDAs, shared by the tests.
#![allow(dead_code)]

use lsda::write::{Action, ActionId, Address, CallSite, ExceptionSpec, Filter};
use lsda::write::{LpStart, Lsda, SpecId, TypeId};
use lsda::{Encoding, Format, RunTimeEndian, Unwinder};

use super::rng::Rng;

/// The section address that random addresses are near.
pub const SECTION: u64 = 0x10_0000;

pub fn random_format(rng: &mut Rng) -> Format {
    let unwinder = match rng.below(3) {
        0 => Unwinder::Dwarf,
        1 => Unwinder::ArmEhabi,
        _ => Unwinder::SjLj,
    };
    // The Arm EHABI is 32-bit only.
    let address_size = if unwinder == Unwinder::ArmEhabi || rng.chance(50) {
        4
    } else {
        8
    };
    Format {
        address_size,
        unwinder,
    }
}

pub fn random_endian(rng: &mut Rng) -> RunTimeEndian {
    if rng.chance(50) {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    }
}

/// Pick a valid encoding for pointers of the given kind.
pub fn random_encoding(rng: &mut Rng, fixed_size: bool) -> Encoding {
    let formats: &[u8] = if fixed_size {
        &[0x00, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c]
    } else {
        &[0x00, 0x01, 0x02, 0x03, 0x04, 0x09, 0x0a, 0x0b, 0x0c]
    };
    let format = formats[rng.below(formats.len() as u64) as usize];
    let application = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50][rng.below(6) as usize];
    if application == 0x50 {
        // DW_EH_PE_aligned is valid only on its own.
        return Encoding(0x50);
    }
    let indirect = if rng.chance(30) { 0x80 } else { 0 };
    Encoding(format | application | indirect)
}

/// An address near one of the bases, or null.
pub fn random_address(rng: &mut Rng) -> Address {
    let base = [SECTION, 0x1000, 0x20_0000, 0x2000][rng.below(4) as usize];
    Address::Constant(if rng.chance(10) {
        0
    } else {
        base + rng.below(0x400) * 4
    })
}

pub fn random_lsda(rng: &mut Rng, format: Format) -> Lsda {
    let mut lsda = Lsda::new();
    if rng.chance(20) {
        lsda.lpstart = Some(LpStart {
            encoding: random_encoding(rng, false),
            address: random_address(rng),
        });
    }
    lsda.call_site_encoding = match rng.below(4) {
        0 => Encoding::ULEB128,
        1 => Encoding::UDATA4,
        2 => Encoding::SDATA4,
        _ => Encoding::ABSPTR,
    };
    lsda.type_table_alignment = 1 << rng.below(5);

    let arm = format.unwinder == Unwinder::ArmEhabi;
    let type_count = rng.below(6) as usize;
    let spec_count = rng.below(3) as usize;
    if type_count > 0 || spec_count > 0 || rng.chance(20) {
        lsda.ttype_encoding = random_encoding(rng, true);
        // The Arm EHABI type table holds 4-byte words.
        while arm && (lsda.ttype_encoding.size(4) != Some(4) || lsda.ttype_encoding.0 == 0x50) {
            lsda.ttype_encoding = random_encoding(rng, true);
        }
    }
    for _ in 0..type_count {
        let address = if rng.chance(20) {
            None
        } else {
            Some(random_address(rng))
        };
        lsda.add_type(address);
    }
    for _ in 0..spec_count {
        let len = rng.below(3) as usize;
        let spec = if arm {
            ExceptionSpec::TypeInfos(
                (0..len)
                    .map(|_| Address::Constant(rng.below(0x1_0000) + 1))
                    .collect(),
            )
        } else if type_count == 0 {
            ExceptionSpec::Types(Vec::new())
        } else {
            ExceptionSpec::Types(
                (0..len)
                    .map(|_| TypeId(rng.below(type_count as u64) as usize))
                    .collect(),
            )
        };
        lsda.add_exception_spec(spec);
    }

    // Actions link only to later actions, so that chains end. Every action
    // is the head of a call site's chain, so that all are reachable, and
    // every exception specification is used by an action, as producers emit
    // only referenced specifications.
    let action_count = rng.below(8) as usize + spec_count;
    for i in 0..action_count {
        let filter = match rng.below(3) {
            _ if i < spec_count => Filter::ExceptionSpec(SpecId(i)),
            1 if type_count > 0 => Filter::Catch(TypeId(rng.below(type_count as u64) as usize)),
            2 if spec_count > 0 => {
                Filter::ExceptionSpec(SpecId(rng.below(spec_count as u64) as usize))
            }
            _ => Filter::Cleanup,
        };
        let next = (i + 1 < action_count && rng.chance(50))
            .then(|| ActionId(i + 1 + rng.below((action_count - i - 1) as u64) as usize));
        lsda.add_action(Action { filter, next });
    }
    let mut start = 0;
    for i in 0..action_count + rng.below(4) as usize {
        let length = rng.below(0x100) + 1;
        lsda.call_sites.push(CallSite {
            start,
            length,
            landing_pad: if rng.chance(20) { 0 } else { rng.below(0x400) },
            action: (i < action_count).then_some(ActionId(i)),
        });
        start += length + rng.below(0x10);
    }
    lsda
}
