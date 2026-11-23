//! The part of JSON Schema 2020-12 a model's manifest uses for its inputs: type, properties, required, enum,
//! minimum, maximum, maxLength, items, additionalProperties. Anything a schema says beyond that is ignored.
use serde_json::Value;

/// Checks `v` against `schema`. The error names the first input that doesn't fit, e.g. `inputs.params.steps: at most 8`.
pub fn check(schema: &Value, v: &Value, at: &str) -> Result<(), String> {
    if let Some(t) = schema.get("type").and_then(|t| t.as_str()) {
        let ok = match t {
            "object" => v.is_object(),
            "array" => v.is_array(),
            "string" => v.is_string(),
            "boolean" => v.is_boolean(),
            "integer" => v.as_i64().is_some() || v.as_u64().is_some() || v.as_f64().map_or(false, |f| f.fract() == 0.0 && f.is_finite()),
            "number" => v.is_number(),
            "null" => v.is_null(),
            _ => true,
        };
        if !ok { return Err(format!("{at}: should be {}", if t == "integer" { "a whole number" } else { t })); }
    }
    if let Some(e) = schema.get("enum").and_then(|e| e.as_array()) {
        if !e.contains(v) {
            let list: Vec<String> = e.iter().take(12).map(|x| x.to_string()).collect();
            return Err(format!("{at}: one of {}{}", list.join(", "), if e.len() > 12 { ", …" } else { "" }));
        }
    }
    if let Some(n) = v.as_f64() {
        if let Some(min) = schema.get("minimum").and_then(|m| m.as_f64()) { if n < min { return Err(format!("{at}: at least {min}")); } }
        if let Some(max) = schema.get("maximum").and_then(|m| m.as_f64()) { if n > max { return Err(format!("{at}: at most {max}")); } }
    }
    if let (Some(s), Some(max)) = (v.as_str(), schema.get("maxLength").and_then(|m| m.as_u64())) {
        if s.chars().count() as u64 > max { return Err(format!("{at}: up to {max} characters")); }
    }
    if let Some(o) = v.as_object() {
        let props = schema.get("properties").and_then(|p| p.as_object());
        if let Some(req) = schema.get("required").and_then(|r| r.as_array()) {
            for k in req.iter().filter_map(|k| k.as_str()) { if !o.contains_key(k) { return Err(format!("{at}.{k}: required")); } }
        }
        for (k, x) in o {
            match props.and_then(|p| p.get(k)) {
                Some(s) => check(s, x, &format!("{at}.{k}"))?,
                None => match schema.get("additionalProperties") {
                    Some(Value::Bool(false)) => return Err(format!("{at}.{k}: this model doesn't take it")),
                    Some(s @ Value::Object(_)) => check(s, x, &format!("{at}.{k}"))?,
                    _ => {}
                },
            }
        }
    }
    if let (Some(a), Some(items)) = (v.as_array(), schema.get("items")) {
        for (i, x) in a.iter().enumerate() { check(items, x, &format!("{at}[{i}]"))?; }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn schema() -> Value {
        json!({ "type": "object", "additionalProperties": false, "required": ["prompt"], "properties": {
            "prompt": { "type": "string", "maxLength": 10 },
            "n": { "type": "integer", "minimum": 1, "maximum": 4 },
            "size": { "type": "string", "enum": ["512x512", "1024x1024"] },
            "references": { "type": "array", "items": { "type": "object" } },
            "params": { "type": "object", "additionalProperties": false, "properties": { "steps": { "type": "integer", "maximum": 8 }, "fast": { "type": "boolean" } } } } })
    }
    #[test]
    fn accepts_what_fits() {
        assert!(check(&schema(), &json!({ "prompt": "a cat", "n": 2, "size": "512x512", "params": { "steps": 4, "fast": true } }), "inputs").is_ok());
        assert!(check(&schema(), &json!({ "prompt": "a cat", "n": 2.0 }), "inputs").is_ok());
    }
    #[test]
    fn refuses_what_doesnt() {
        let s = schema();
        assert_eq!(check(&s, &json!({}), "inputs").unwrap_err(), "inputs.prompt: required");
        assert_eq!(check(&s, &json!({ "prompt": "x", "n": 9 }), "inputs").unwrap_err(), "inputs.n: at most 4");
        assert_eq!(check(&s, &json!({ "prompt": "x", "n": 1.5 }), "inputs").unwrap_err(), "inputs.n: should be a whole number");
        assert!(check(&s, &json!({ "prompt": "x", "size": "4096x4096" }), "inputs").unwrap_err().starts_with("inputs.size: one of"));
        assert_eq!(check(&s, &json!({ "prompt": "01234567890" }), "inputs").unwrap_err(), "inputs.prompt: up to 10 characters");
        assert_eq!(check(&s, &json!({ "prompt": "x", "fps": 30 }), "inputs").unwrap_err(), "inputs.fps: this model doesn't take it");
        assert_eq!(check(&s, &json!({ "prompt": "x", "params": { "steps": 99 } }), "inputs").unwrap_err(), "inputs.params.steps: at most 8");
        assert_eq!(check(&s, &json!({ "prompt": "x", "params": { "cfg": 1 } }), "inputs").unwrap_err(), "inputs.params.cfg: this model doesn't take it");
        assert_eq!(check(&s, &json!({ "prompt": "x", "references": ["ast_1"] }), "inputs").unwrap_err(), "inputs.references[0]: should be object");
    }
}
