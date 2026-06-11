//! Vector-clock helpers for `.tnpkg` manifests.
//!
//! The vector clock rides inside the signed manifest (see
//! [`VectorClock`](super::VectorClock)), so its JSON layout must stay
//! deterministic across implementations. This module owns the JSON
//! conversions [`Manifest`](super::Manifest) uses on the wire, plus the
//! pointwise comparison ([`clock_dominates`]) and merge ([`clock_merge`])
//! that [`crate::Runtime::absorb`] runs to decide whether a package carries
//! anything new and to advance the receiver's clock on accept.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::VectorClock;

pub(super) fn clock_to_json(clock: &VectorClock) -> Value {
    let mut out = Map::new();
    for (did, et_map) in clock {
        let mut inner = Map::new();
        for (et, seq) in et_map {
            inner.insert(et.clone(), Value::Number((*seq).into()));
        }
        out.insert(did.clone(), Value::Object(inner));
    }
    Value::Object(out)
}

pub(super) fn json_to_clock(v: Option<&Value>) -> VectorClock {
    let mut out: VectorClock = BTreeMap::new();
    let Some(Value::Object(m)) = v else {
        return out;
    };
    for (did, et_v) in m {
        let Value::Object(et_map) = et_v else {
            continue;
        };
        let mut inner = BTreeMap::new();
        for (et, seq_v) in et_map {
            if let Some(seq) = seq_v.as_u64() {
                inner.insert(et.clone(), seq);
            }
        }
        out.insert(did.clone(), inner);
    }
    out
}

/// Return `true` iff `a` is at or ahead of `b` on every `(did, event_type)`
/// coordinate.
///
/// A coordinate absent from `a` counts as sequence `0`. Absorb uses this to
/// short-circuit: if the receiver's local clock dominates an incoming
/// manifest's clock, the package carries nothing new and absorb is a no-op.
/// Pure; not symmetric — equal clocks dominate each other, but a clock that is
/// behind on any single coordinate does not dominate.
///
/// # Examples
///
/// ```
/// use std::collections::BTreeMap;
/// use tn_core::VectorClock;
/// use tn_core::tnpkg::clock_dominates;
///
/// let mut ahead: VectorClock = BTreeMap::new();
/// ahead.entry("did:key:zA".into()).or_default().insert("tn.recipient.added".into(), 5);
///
/// let mut behind: VectorClock = BTreeMap::new();
/// behind.entry("did:key:zA".into()).or_default().insert("tn.recipient.added".into(), 3);
///
/// assert!(clock_dominates(&ahead, &behind));   // 5 >= 3
/// assert!(!clock_dominates(&behind, &ahead));  // 3 <  5
/// ```
pub fn clock_dominates(a: &VectorClock, b: &VectorClock) -> bool {
    for (did, et_map) in b {
        let a_map = a.get(did);
        for (event_type, seq) in et_map {
            let a_seq = a_map.and_then(|m| m.get(event_type)).copied().unwrap_or(0);
            if a_seq < *seq {
                return false;
            }
        }
    }
    true
}

/// Merge two vector clocks by taking the pointwise maximum on every coordinate.
///
/// The least-upper-bound of `a` and `b`: the result holds, for each
/// `(did, event_type)`, the larger of the two sequences (or whichever clock has
/// the coordinate at all). This is how a receiver advances its clock after
/// accepting a package. Pure; neither input is mutated. Commutative and
/// idempotent.
pub fn clock_merge(a: &VectorClock, b: &VectorClock) -> VectorClock {
    let mut out = a.clone();
    for (did, et_map) in b {
        let slot = out.entry(did.clone()).or_default();
        for (et, seq) in et_map {
            let cur = slot.get(et).copied().unwrap_or(0);
            if *seq > cur {
                slot.insert(et.clone(), *seq);
            }
        }
    }
    out
}
