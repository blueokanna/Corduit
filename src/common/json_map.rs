//! Codec boundary for std maps. NextJson 0.1.5 intentionally only provides
//! no_std collections; packet-path maps remain hash based inside Corduit.
use nextjson::{
    FormatDecoder, FormatEncoder, NsonDeserialize, NsonSchema, NsonSerialize, TypeSchema,
};
use std::collections::{BTreeMap, HashMap};

pub(crate) struct MapRef<'a, V>(pub &'a HashMap<String, V>);

impl<V: NsonSerialize> NsonSchema for MapRef<'_, V> {
    const SCHEMA: TypeSchema = TypeSchema::Map(&V::SCHEMA);
}
impl<V: NsonSerialize> NsonSerialize for MapRef<'_, V> {
    fn nextencode<E: FormatEncoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        let mut entries: Vec<_> = self.0.iter().collect();
        entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
        encoder.begin_object_len(entries.len())?;
        for (key, value) in entries {
            encoder.map_key(key)?;
            value.nextencode(encoder)?;
        }
        encoder.end_object()
    }
}

pub(crate) fn serialize<V: NsonSerialize, E: FormatEncoder>(
    map: &HashMap<String, V>,
    encoder: &mut E,
) -> Result<(), E::Error> {
    MapRef(map).nextencode(encoder)
}

pub(crate) fn deserialize<'de, V: NsonDeserialize<'de>, D: FormatDecoder<'de>>(
    decoder: &mut D,
) -> Result<HashMap<String, V>, D::Error> {
    Ok(BTreeMap::<String, V>::nextdecode(decoder)?
        .into_iter()
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, NsonSerialize, NsonDeserialize)]
    struct Fixture {
        #[serde(default, with = "super")]
        values: HashMap<String, Vec<String>>,
    }

    #[test]
    fn map_roundtrip_defaults_and_stable_encoding() {
        let fixture = Fixture {
            values: HashMap::from([
                ("z".into(), vec!["quote\"".into(), "\n".into()]),
                ("a".into(), vec!["resolver".into()]),
            ]),
        };
        let encoded = nextjson::to_string(&fixture).unwrap();
        assert_eq!(
            encoded,
            r#"{"values":{"a":["resolver"],"z":["quote\"","\n"]}}"#
        );
        assert_eq!(nextjson::from_str::<Fixture>(&encoded).unwrap(), fixture);
        assert!(nextjson::from_str::<Fixture>("{}")
            .unwrap()
            .values
            .is_empty());
        assert!(nextjson::from_str::<Fixture>(r#"{"values":{"a":12}}"#).is_err());
    }
}
