//! Minimal CBOR decoder (RFC 8949) for AXIOM wire format.
//!
//! Converts CBOR bytes → serde_json::Value so existing deserialization
//! code works unchanged. No external crate needed.
//!
//! Yellow Paper §16.8.5: "CBOR: Binary, self-describing, standard (RFC 8949)"
//!
//! Supports: unsigned int, negative int, byte string (→ int array),
//!           text string, array, map, true, false, null, float64.

use serde_json::Value;

/// Decode CBOR bytes into a serde_json::Value.
///
/// Byte strings (major type 2) are decoded as JSON arrays of integers
/// to match the existing serde deserialization for Vec<u8> and [u8; N].
/// Maximum CBOR nesting depth (DoS prevention).
const MAX_CBOR_DEPTH: usize = 32;
/// Maximum array/map element count.
const MAX_CBOR_ELEMENTS: u64 = 100_000;

pub fn cbor_to_json(data: &[u8]) -> Result<Value, String> {
    let (value, _) = decode_item(data, 0, 0)?;
    Ok(value)
}

fn decode_item(data: &[u8], mut pos: usize, depth: usize) -> Result<(Value, usize), String> {
    if depth > MAX_CBOR_DEPTH {
        return Err("CBOR nesting too deep (>32 levels)".into());
    }
    if pos >= data.len() {
        return Err("Unexpected end of CBOR data".into());
    }

    let initial = data[pos];
    let major = initial >> 5;
    let info = initial & 0x1f;
    pos += 1;

    // Decode argument
    let (arg, pos) = decode_arg(data, pos, info)?;

    match major {
        // Unsigned integer
        0 => Ok((Value::Number(arg.into()), pos)),

        // Negative integer
        1 => {
            let val = -1i64 - arg as i64;
            Ok((Value::Number(val.into()), pos))
        }

        // Byte string → JSON array of integers (for serde Vec<u8> compat)
        2 => {
            let end = pos + arg as usize;
            if end > data.len() {
                return Err(format!("Byte string length {} exceeds data at pos {}", arg, pos));
            }
            let bytes = &data[pos..end];
            let arr: Vec<Value> = bytes.iter().map(|&b| Value::Number(b.into())).collect();
            Ok((Value::Array(arr), end))
        }

        // Text string
        3 => {
            let end = pos + arg as usize;
            if end > data.len() {
                return Err(format!("Text string length {} exceeds data at pos {}", arg, pos));
            }
            let s = std::str::from_utf8(&data[pos..end])
                .map_err(|e| format!("Invalid UTF-8 in text string: {}", e))?;
            Ok((Value::String(s.to_string()), end))
        }

        // Array
        4 => {
            if arg > MAX_CBOR_ELEMENTS {
                return Err(format!("CBOR array too large: {} elements", arg));
            }
            let count = arg as usize;
            let mut items = Vec::with_capacity(count.min(1024));
            let mut p = pos;
            for _ in 0..count {
                let (item, next) = decode_item(data, p, depth + 1)?;
                items.push(item);
                p = next;
            }
            Ok((Value::Array(items), p))
        }

        // Map
        5 => {
            if arg > MAX_CBOR_ELEMENTS {
                return Err(format!("CBOR map too large: {} entries", arg));
            }
            let count = arg as usize;
            let mut map = serde_json::Map::with_capacity(count.min(1024));
            let mut p = pos;
            for _ in 0..count {
                let (key, next) = decode_item(data, p, depth + 1)?;
                p = next;
                let (value, next) = decode_item(data, p, depth + 1)?;
                p = next;

                // Map keys must be strings
                let key_str = match key {
                    Value::String(s) => s,
                    Value::Number(n) => n.to_string(),
                    _ => return Err(format!("Non-string map key: {:?}", key)),
                };
                map.insert(key_str, value);
            }
            Ok((Value::Object(map), p))
        }

        // Simple values and floats (major type 7)
        7 => {
            match initial {
                0xf4 => Ok((Value::Bool(false), pos)),
                0xf5 => Ok((Value::Bool(true), pos)),
                0xf6 | 0xf7 => Ok((Value::Null, pos)),
                0xfb => {
                    // Float64: decode_arg already read 8 bytes as u64 in `arg`
                    let val = f64::from_bits(arg);
                    let num = serde_json::Number::from_f64(val)
                        .ok_or_else(|| format!("Cannot represent float {} as JSON number", val))?;
                    Ok((Value::Number(num), pos))
                }
                _ => Err(format!("Unknown CBOR simple value: {:#x}", initial)),
            }
        }

        _ => Err(format!("Unknown CBOR major type: {}", major)),
    }
}

fn decode_arg(data: &[u8], pos: usize, info: u8) -> Result<(u64, usize), String> {
    match info {
        0..=23 => Ok((info as u64, pos)),
        24 => {
            if pos >= data.len() {
                return Err("Truncated 1-byte arg".into());
            }
            Ok((data[pos] as u64, pos + 1))
        }
        25 => {
            if pos + 2 > data.len() {
                return Err("Truncated 2-byte arg".into());
            }
            let val = u16::from_be_bytes(data[pos..pos+2].try_into()
                .map_err(|_| "Invalid 2-byte CBOR arg")?);
            Ok((val as u64, pos + 2))
        }
        26 => {
            if pos + 4 > data.len() {
                return Err("Truncated 4-byte arg".into());
            }
            let val = u32::from_be_bytes(data[pos..pos+4].try_into()
                .map_err(|_| "Invalid 4-byte CBOR arg")?);
            Ok((val as u64, pos + 4))
        }
        27 => {
            if pos + 8 > data.len() {
                return Err("Truncated 8-byte arg".into());
            }
            let val = u64::from_be_bytes(data[pos..pos+8].try_into()
                .map_err(|_| "Invalid 8-byte CBOR arg")?);
            Ok((val, pos + 8))
        }
        31 => Err("Indefinite-length CBOR not supported".into()),
        _ => Err(format!("Reserved CBOR additional info: {}", info)),
    }
}

/// Encode serde_json::Value to CBOR bytes.
///
/// Used for ANTIE → PMC responses.
/// JSON arrays of small integers (0-255) are encoded as CBOR byte strings
/// when they look like byte arrays (all elements 0-255).
pub fn json_to_cbor(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_value(value, &mut buf);
    buf
}

fn encode_value(value: &Value, buf: &mut Vec<u8>) {
    match value {
        Value::Null => buf.push(0xf6),
        Value::Bool(true) => buf.push(0xf5),
        Value::Bool(false) => buf.push(0xf4),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                encode_head(0, u, buf);
            } else if let Some(i) = n.as_i64() {
                if i < 0 {
                    encode_head(1, (-1 - i) as u64, buf);
                } else {
                    encode_head(0, i as u64, buf);
                }
            } else if let Some(f) = n.as_f64() {
                buf.push(0xfb);
                buf.extend_from_slice(&f.to_bits().to_be_bytes());
            }
        }
        Value::String(s) => {
            let bytes = s.as_bytes();
            encode_head(3, bytes.len() as u64, buf);
            buf.extend_from_slice(bytes);
        }
        Value::Array(arr) => {
            // Heuristic: if all elements are integers 0-255, encode as byte string
            if is_byte_array(arr) {
                let bytes: Vec<u8> = arr.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u8))
                    .collect();
                encode_head(2, bytes.len() as u64, buf);
                buf.extend_from_slice(&bytes);
            } else {
                encode_head(4, arr.len() as u64, buf);
                for item in arr {
                    encode_value(item, buf);
                }
            }
        }
        Value::Object(map) => {
            encode_head(5, map.len() as u64, buf);
            for (k, v) in map {
                // Keys as text strings
                let kb = k.as_bytes();
                encode_head(3, kb.len() as u64, buf);
                buf.extend_from_slice(kb);
                encode_value(v, buf);
            }
        }
    }
}

fn encode_head(major: u8, value: u64, buf: &mut Vec<u8>) {
    let mt = major << 5;
    if value < 24 {
        buf.push(mt | value as u8);
    } else if value < 0x100 {
        buf.push(mt | 24);
        buf.push(value as u8);
    } else if value < 0x10000 {
        buf.push(mt | 25);
        buf.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 0x100000000 {
        buf.push(mt | 26);
        buf.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        buf.push(mt | 27);
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

/// Check if a JSON array looks like a byte array (all integers 0-255).
fn is_byte_array(arr: &[Value]) -> bool {
    if arr.is_empty() {
        return false; // Empty arrays stay as arrays
    }
    arr.iter().all(|v| {
        matches!(v, Value::Number(n) if n.as_u64().is_some_and(|u| u <= 255))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_basic() {
        let json = serde_json::json!({
            "name": "test",
            "value": 42,
            "flag": true,
            "empty": null,
            "nested": {"a": 1}
        });
        let cbor = json_to_cbor(&json);
        let decoded = cbor_to_json(&cbor).unwrap();
        assert_eq!(json, decoded);
    }

    #[test]
    fn test_byte_arrays() {
        // Byte arrays should round-trip through CBOR byte strings
        let json = serde_json::json!({
            "data": [0, 1, 2, 255],
            "text": "hello"
        });
        let cbor = json_to_cbor(&json);
        let decoded = cbor_to_json(&cbor).unwrap();
        assert_eq!(json, decoded);
    }

    #[test]
    fn test_large_payload() {
        let sig: Vec<Value> = (0..7856).map(|i| Value::Number((i % 256).into())).collect();
        let json = serde_json::json!({
            "signature": sig,
            "amount": 1000000u64,
        });
        let cbor = json_to_cbor(&json);
        // CBOR should be much smaller than JSON
        let json_size = serde_json::to_string(&json).unwrap().len();
        assert!(cbor.len() < json_size / 3, "CBOR {} should be < JSON/3 {}", cbor.len(), json_size / 3);
        
        let decoded = cbor_to_json(&cbor).unwrap();
        assert_eq!(json, decoded);
    }

    #[test]
    fn test_empty_cbor_rejected() {
        assert!(cbor_to_json(&[]).is_err());
    }

    #[test]
    fn test_truncated_cbor_rejected() {
        // CBOR map header says 5 items but only 1 follows
        assert!(cbor_to_json(&[0xA5, 0x61, 0x61, 0x01]).is_err());
    }

    #[test]
    fn test_deeply_nested_cbor() {
        // Build deeply nested CBOR: {"a":{"a":{"a":...}}}
        let mut json = serde_json::json!(42);
        for _ in 0..30 {
            json = serde_json::json!({"a": json});
        }
        let cbor = json_to_cbor(&json);
        let decoded = cbor_to_json(&cbor).unwrap();
        assert_eq!(json, decoded);
    }

    #[test]
    fn test_negative_integers() {
        let json = serde_json::json!({"neg": -42, "zero": 0, "pos": 42});
        let cbor = json_to_cbor(&json);
        let decoded = cbor_to_json(&cbor).unwrap();
        assert_eq!(json, decoded);
    }

    #[test]
    fn test_unicode_text() {
        let json = serde_json::json!({"jp": "高市首相", "de": "Wir hätten", "emoji": "test"});
        let cbor = json_to_cbor(&json);
        let decoded = cbor_to_json(&cbor).unwrap();
        assert_eq!(json, decoded);
    }
}

#[cfg(test)]
mod proptest_fuzz {
    use super::*;
    use proptest::prelude::*;

    // Property: any valid JSON → CBOR → JSON roundtrip preserves value
    proptest! {
        #[test]
        fn cbor_roundtrip_integers(v in any::<i64>()) {
            let json = serde_json::json!({"v": v});
            let cbor = json_to_cbor(&json);
            let decoded = cbor_to_json(&cbor).unwrap();
            prop_assert_eq!(json, decoded);
        }

        #[test]
        fn cbor_roundtrip_strings(s in "[a-zA-Z0-9@._/]{0,200}") {
            let json = serde_json::json!({"s": s});
            let cbor = json_to_cbor(&json);
            let decoded = cbor_to_json(&cbor).unwrap();
            prop_assert_eq!(json, decoded);
        }

        #[test]
        fn cbor_roundtrip_byte_arrays(bytes in proptest::collection::vec(0u8..=255, 0..500)) {
            let arr: Vec<serde_json::Value> = bytes.iter().map(|&b| serde_json::json!(b)).collect();
            let json = serde_json::json!({"data": arr});
            let cbor = json_to_cbor(&json);
            let decoded = cbor_to_json(&cbor).unwrap();
            prop_assert_eq!(json, decoded);
        }

        #[test]
        fn cbor_roundtrip_nested(depth in 1usize..15, val in any::<i32>()) {
            let mut json = serde_json::json!(val);
            for _ in 0..depth {
                json = serde_json::json!({"n": json});
            }
            let cbor = json_to_cbor(&json);
            let decoded = cbor_to_json(&cbor).unwrap();
            prop_assert_eq!(json, decoded);
        }

        // Property: random bytes should NOT panic cbor_to_json (may return Err, never panic)
        #[test]
        fn cbor_decode_random_no_panic(data in proptest::collection::vec(any::<u8>(), 0..1000)) {
            let _ = cbor_to_json(&data); // Must not panic
        }

        // Property: random bytes should NOT panic json_to_cbor (via serde_json::Value)
        #[test]
        fn cbor_encode_random_json_no_panic(
            keys in proptest::collection::vec("[a-z]{1,10}", 1..10),
            vals in proptest::collection::vec(any::<i64>(), 1..10),
        ) {
            let mut map = serde_json::Map::new();
            for (k, v) in keys.into_iter().zip(vals.into_iter()) {
                map.insert(k, serde_json::json!(v));
            }
            let json = serde_json::Value::Object(map);
            let cbor = json_to_cbor(&json);
            let decoded = cbor_to_json(&cbor).unwrap();
            prop_assert_eq!(json, decoded);
        }
    }
}
