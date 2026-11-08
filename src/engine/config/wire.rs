//! Codec views keep the public hash tables and flattened JSON layout stable.
use super::{default_bind_address, InboundConfig, InboundType, OutboundConfig, OutboundType};
use crate::common::json_map::MapRef;
use nextjson::{FormatEncoder, NsonDeserialize, NsonSchema, NsonSerialize, TypeSchema, Value};
use std::collections::BTreeMap;

#[derive(NsonSerialize, NsonDeserialize)]
pub(super) struct Inbound {
    #[serde(rename = "type")]
    inbound_type: InboundType,
    tag: String,
    #[serde(default = "default_bind_address")]
    listen: String,
    port: u16,
    #[serde(flatten)]
    options: BTreeMap<String, Value>,
}
#[derive(NsonSerialize, NsonDeserialize)]
pub(super) struct Outbound {
    #[serde(rename = "type")]
    outbound_type: OutboundType,
    tag: String,
    server: Option<String>,
    port: Option<u16>,
    #[serde(flatten)]
    options: BTreeMap<String, Value>,
}
impl From<Inbound> for InboundConfig {
    fn from(v: Inbound) -> Self {
        Self {
            inbound_type: v.inbound_type,
            tag: v.tag,
            listen: v.listen,
            port: v.port,
            options: v.options.into_iter().collect(),
        }
    }
}
impl From<Outbound> for OutboundConfig {
    fn from(v: Outbound) -> Self {
        Self {
            outbound_type: v.outbound_type,
            tag: v.tag,
            server: v.server,
            port: v.port,
            options: v.options.into_iter().collect(),
        }
    }
}
#[derive(NsonSerialize)]
struct InboundRef<'a> {
    #[serde(rename = "type")]
    inbound_type: &'a InboundType,
    tag: &'a str,
    listen: &'a str,
    port: u16,
    #[serde(flatten)]
    options: MapRef<'a, Value>,
}
#[derive(NsonSerialize)]
struct OutboundRef<'a> {
    #[serde(rename = "type")]
    outbound_type: &'a OutboundType,
    tag: &'a str,
    server: &'a Option<String>,
    port: Option<u16>,
    #[serde(flatten)]
    options: MapRef<'a, Value>,
}
impl NsonSchema for InboundConfig {
    const SCHEMA: TypeSchema = {
        // A named constant gives the reference a static lifetime on Rust 1.78.
        // Borrowing a struct built inside the match arm does not on that MSRV.
        const SCHEMA: nextjson::StructSchema = match Inbound::SCHEMA {
            TypeSchema::Struct(schema) => nextjson::StructSchema {
                name: "InboundConfig",
                ..*schema
            },
            _ => panic!("Inbound codec must have a struct schema"),
        };
        TypeSchema::Struct(&SCHEMA)
    };
}
impl NsonSerialize for InboundConfig {
    fn nextencode<E: FormatEncoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        if ["type", "tag", "listen", "port"]
            .iter()
            .any(|key| self.options.contains_key(*key))
        {
            return Err(nextjson::Error::custom("inbound options contain a reserved field").into());
        }
        InboundRef {
            inbound_type: &self.inbound_type,
            tag: &self.tag,
            listen: &self.listen,
            port: self.port,
            options: MapRef(&self.options),
        }
        .nextencode(encoder)
    }
}
impl NsonSchema for OutboundConfig {
    const SCHEMA: TypeSchema = {
        const SCHEMA: nextjson::StructSchema = match Outbound::SCHEMA {
            TypeSchema::Struct(schema) => nextjson::StructSchema {
                name: "OutboundConfig",
                ..*schema
            },
            _ => panic!("Outbound codec must have a struct schema"),
        };
        TypeSchema::Struct(&SCHEMA)
    };
}
impl NsonSerialize for OutboundConfig {
    fn nextencode<E: FormatEncoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        if ["type", "tag", "server", "port"]
            .iter()
            .any(|key| self.options.contains_key(*key))
        {
            return Err(
                nextjson::Error::custom("outbound options contain a reserved field").into(),
            );
        }
        OutboundRef {
            outbound_type: &self.outbound_type,
            tag: &self.tag,
            server: &self.server,
            port: self.port,
            options: MapRef(&self.options),
        }
        .nextencode(encoder)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_schemas_preserve_codec_metadata() {
        for (public, wire, name) in [
            (InboundConfig::SCHEMA, Inbound::SCHEMA, "InboundConfig"),
            (OutboundConfig::SCHEMA, Outbound::SCHEMA, "OutboundConfig"),
        ] {
            let (TypeSchema::Struct(public), TypeSchema::Struct(wire)) = (public, wire) else {
                panic!("config and codec schemas must describe structs");
            };
            assert_eq!(public.name, name);
            assert_eq!(public.fields, wire.fields);
            assert_eq!(public.transparent, wire.transparent);
            assert_eq!(public.max_depth, wire.max_depth);
            assert_eq!(public.deny_unknown_fields, wire.deny_unknown_fields);
            let options = public.fields.iter().find(|f| f.name == "options").unwrap();
            assert!(options.flattened);
            assert!(matches!(options.ty, TypeSchema::Map(_)));
        }
    }

    #[test]
    fn flattened_options_survive_roundtrip_without_changing_wire_keys() {
        let raw = r#"{"type":"socks5","tag":"node","server":"example.com","port":1080,"username":"u","password":"p","nested":{"list":[1,true,null]}}"#;
        let decoded: OutboundConfig = nextjson::from_str(raw).unwrap();
        assert_eq!(decoded.options["username"].as_str(), Some("u"));
        let encoded = nextjson::to_string(&decoded).unwrap();
        assert_eq!(
            nextjson::from_str::<BTreeMap<String, Value>>(raw).unwrap(),
            nextjson::from_str::<BTreeMap<String, Value>>(&encoded).unwrap()
        );
        let again: OutboundConfig = nextjson::from_str(&encoded).unwrap();
        assert_eq!(decoded.options, again.options);
        assert!(!again.options.contains_key("type"));
    }
    #[test]
    fn inbound_defaults_and_invalid_fields_match_existing_contract() {
        let decoded: InboundConfig =
            nextjson::from_str(r#"{"type":"mixed","tag":"local","port":7890,"sniff":true}"#)
                .unwrap();
        assert_eq!(decoded.listen, default_bind_address());
        assert_eq!(decoded.options["sniff"].as_bool(), Some(true));
        let encoded = nextjson::to_string(&decoded).unwrap();
        let again: InboundConfig = nextjson::from_str(&encoded).unwrap();
        assert_eq!(decoded.options, again.options);
        assert!(nextjson::from_str::<InboundConfig>(
            r#"{"type":"mixed","tag":"local","port":70000}"#
        )
        .is_err());
        assert!(nextjson::from_str::<InboundConfig>(r#"{"type":"mixed","tag":"local"}"#).is_err());
    }
    #[test]
    fn options_cannot_override_routing_identity_on_serialization() {
        let outbound: OutboundConfig =
            nextjson::from_str(r#"{"type":"direct","tag":"safe"}"#).unwrap();
        for key in ["type", "tag", "server", "port"] {
            let mut config = outbound.clone();
            config.options.insert(key.into(), Value::Null);
            assert!(nextjson::to_string(&config).is_err(), "reserved key: {key}");
        }
        let inbound: InboundConfig =
            nextjson::from_str(r#"{"type":"mixed","tag":"safe","port":7890}"#).unwrap();
        for key in ["type", "tag", "listen", "port"] {
            let mut config = inbound.clone();
            config.options.insert(key.into(), Value::Null);
            assert!(nextjson::to_string(&config).is_err(), "reserved key: {key}");
        }
    }
}
