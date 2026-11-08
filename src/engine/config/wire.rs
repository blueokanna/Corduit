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
    const SCHEMA: TypeSchema = match Inbound::SCHEMA {
        TypeSchema::Struct(schema) => TypeSchema::Struct(&nextjson::StructSchema {
            name: "InboundConfig",
            ..*schema
        }),
        schema => schema,
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
    const SCHEMA: TypeSchema = match Outbound::SCHEMA {
        TypeSchema::Struct(schema) => TypeSchema::Struct(&nextjson::StructSchema {
            name: "OutboundConfig",
            ..*schema
        }),
        schema => schema,
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
        assert_eq!(InboundConfig::SCHEMA.name(), "InboundConfig");
        assert_eq!(OutboundConfig::SCHEMA.name(), "OutboundConfig");
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
        let mut decoded: OutboundConfig =
            nextjson::from_str(r#"{"type":"direct","tag":"safe"}"#).unwrap();
        decoded
            .options
            .insert("tag".into(), Value::String("other".into()));
        assert!(nextjson::to_string(&decoded).is_err());
    }
}
