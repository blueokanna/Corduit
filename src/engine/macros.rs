/// String-based codec for unit-variant enums in configuration files.
///
/// nextjson's derived enum codec uses externally-tagged objects
/// (`{"socks5": null}`); Corduit configuration spells such values as plain
/// strings (`"socks5"`). This macro implements a string codec: the first
/// literal is the canonical serialized name, the remaining literals are
/// accepted deserialization aliases. This keeps the config format stable and
/// human-friendly while staying 100% on `nextjson` (no serde anywhere).
#[macro_export]
macro_rules! impl_config_enum {
    ($ty:ident { $($variant:ident => $canonical:literal $(| $alias:literal)*),+ $(,)? }) => {
        impl ::nextjson::NsonSchema for $ty {
            const SCHEMA: ::nextjson::TypeSchema = ::nextjson::TypeSchema::Str;
        }
        impl ::nextjson::NsonSerialize for $ty {
            fn nextencode<E: ::nextjson::FormatEncoder>(
                &self,
                e: &mut E,
            ) -> ::core::result::Result<(), E::Error> {
                let name = match self {
                    $($ty::$variant => $canonical,)+
                };
                e.write_str(name)
            }
        }
        impl $ty {
            /// Canonical string name as used in configuration files.
            pub fn as_str(self) -> &'static str {
                match self {
                    $($ty::$variant => $canonical,)+
                }
            }
        }
        impl<'de> ::nextjson::NsonDeserialize<'de> for $ty {
            fn nextdecode_into<D: ::nextjson::FormatDecoder<'de>>(
                d: &mut D,
                out: &mut ::nextjson::DecodeSlot<Self>,
            ) -> ::core::result::Result<(), D::Error> {
                let s = d.string()?;
                let value = match s.as_ref() {
                    $($canonical $(| $alias)* => $ty::$variant,)+
                    other => {
                        return Err(::nextjson::Error::custom(
                            format!("invalid {} value: {other}", stringify!($ty)),
                        )
                        .into());
                    }
                };
                out.write(value);
                Ok(())
            }
        }
    };
}

#[macro_export]
macro_rules! bail_config {
    ($($arg:tt)*) => {
        return Err($crate::engine::error::Error::Config {
            message: format!($($arg)*),
            source: None,
        })
    };
}

#[macro_export]
macro_rules! bail_network {
    ($($arg:tt)*) => {
        return Err($crate::engine::error::Error::Network {
            message: format!($($arg)*),
            source: None,
        })
    };
}

#[macro_export]
macro_rules! bail_protocol {
    ($($arg:tt)*) => {
        return Err($crate::engine::error::Error::Protocol {
            message: format!($($arg)*),
            protocol: None,
            source: None,
        })
    };
}

#[macro_export]
macro_rules! bail_protocol_with_name {
    ($protocol:expr, $($arg:tt)*) => {
        return Err($crate::engine::error::Error::Protocol {
            message: format!($($arg)*),
            protocol: Some($protocol.to_string()),
            source: None,
        })
    };
}

#[macro_export]
macro_rules! bail_dns {
    ($($arg:tt)*) => {
        return Err($crate::engine::error::Error::Dns {
            message: format!($($arg)*),
            source: None,
        })
    };
}

#[macro_export]
macro_rules! try_network {
    ($expr:expr) => {
        $expr.map_err(|e| $crate::engine::error::Error::Network {
            message: e.to_string(),
            source: None,
        })?
    };
    ($expr:expr, $msg:expr) => {
        $expr.map_err(|e| $crate::engine::error::Error::Network {
            message: format!("{}: {}", $msg, e),
            source: None,
        })?
    };
}

#[macro_export]
macro_rules! try_protocol {
    ($expr:expr) => {
        $expr.map_err(|e| $crate::engine::error::Error::Protocol {
            message: e.to_string(),
            protocol: None,
            source: None,
        })?
    };
    ($expr:expr, $msg:expr) => {
        $expr.map_err(|e| $crate::engine::error::Error::Protocol {
            message: format!("{}: {}", $msg, e),
            protocol: None,
            source: None,
        })?
    };
    ($expr:expr, $msg:expr, $protocol:expr) => {
        $expr.map_err(|e| $crate::engine::error::Error::Protocol {
            message: format!("{}: {}", $msg, e),
            protocol: Some($protocol.to_string()),
            source: None,
        })?
    };
}

#[macro_export]
macro_rules! try_dns {
    ($expr:expr) => {
        $expr.map_err(|e| $crate::engine::error::Error::Dns {
            message: e.to_string(),
            source: None,
        })?
    };
    ($expr:expr, $msg:expr) => {
        $expr.map_err(|e| $crate::engine::error::Error::Dns {
            message: format!("{}: {}", $msg, e),
            source: None,
        })?
    };
}

#[macro_export]
macro_rules! try_config {
    ($expr:expr) => {
        $expr.map_err(|e| $crate::engine::error::Error::Config {
            message: e.to_string(),
            source: None,
        })?
    };
    ($expr:expr, $msg:expr) => {
        $expr.map_err(|e| $crate::engine::error::Error::Config {
            message: format!("{}: {}", $msg, e),
            source: None,
        })?
    };
}

#[macro_export]
macro_rules! get_option {
    ($options:expr, $key:expr, String) => {
        $options.get($key).and_then(|v| match v {
            nextjson::Value::String(s) => Some(s.clone()),
            nextjson::Value::Number(n) => Some(n.to_string()),
            nextjson::Value::Bool(b) => Some(b.to_string()),
            _ => None,
        })
    };
    ($options:expr, $key:expr, u16) => {
        $options.get($key).and_then(|v| match v {
            nextjson::Value::Number(n) => n.as_u64().map(|n| n as u16),
            nextjson::Value::String(s) => s.parse::<u16>().ok(),
            _ => None,
        })
    };
    ($options:expr, $key:expr, u32) => {
        $options.get($key).and_then(|v| match v {
            nextjson::Value::Number(n) => n.as_u64().map(|n| n as u32),
            nextjson::Value::String(s) => s.parse::<u32>().ok(),
            _ => None,
        })
    };
    ($options:expr, $key:expr, u64) => {
        $options.get($key).and_then(|v| match v {
            nextjson::Value::Number(n) => n.as_u64(),
            nextjson::Value::String(s) => s.parse::<u64>().ok(),
            _ => None,
        })
    };
    ($options:expr, $key:expr, i64) => {
        $options.get($key).and_then(|v| match v {
            nextjson::Value::Number(n) => n.as_i64(),
            nextjson::Value::String(s) => s.parse::<i64>().ok(),
            _ => None,
        })
    };
    ($options:expr, $key:expr, bool) => {
        $options.get($key).and_then(|v| match v {
            nextjson::Value::Bool(b) => Some(*b),
            nextjson::Value::String(s) => match s.to_lowercase().as_str() {
                "true" | "yes" | "1" | "on" => Some(true),
                "false" | "no" | "0" | "off" => Some(false),
                _ => None,
            },
            nextjson::Value::Number(n) => n.as_i64().map(|n| n != 0),
            _ => None,
        })
    };
    ($options:expr, $key:expr, Vec<String>) => {
        $options.get($key).and_then(|v| match v {
            nextjson::Value::Array(seq) => {
                let strings: Vec<String> = seq
                    .iter()
                    .filter_map(|item| match item {
                        nextjson::Value::String(s) => Some(s.clone()),
                        nextjson::Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    })
                    .collect();
                if strings.is_empty() {
                    None
                } else {
                    Some(strings)
                }
            }
            nextjson::Value::String(s) => Some(vec![s.clone()]),
            _ => None,
        })
    };
}

#[macro_export]
macro_rules! require_option {
    ($options:expr, $key:expr, String) => {
        $crate::get_option!($options, $key, String).ok_or_else(|| {
            $crate::engine::error::Error::Config {
                message: format!("Missing required option: {}", $key),
                source: None,
            }
        })?
    };
    ($options:expr, $key:expr, String, $error_msg:expr) => {
        $crate::get_option!($options, $key, String).ok_or_else(|| {
            $crate::engine::error::Error::Config {
                message: $error_msg.to_string(),
                source: None,
            }
        })?
    };
    ($options:expr, $key:expr, u16) => {
        $crate::get_option!($options, $key, u16).ok_or_else(|| {
            $crate::engine::error::Error::Config {
                message: format!("Missing required option: {}", $key),
                source: None,
            }
        })?
    };
    ($options:expr, $key:expr, u16, $error_msg:expr) => {
        $crate::get_option!($options, $key, u16).ok_or_else(|| {
            $crate::engine::error::Error::Config {
                message: $error_msg.to_string(),
                source: None,
            }
        })?
    };
    ($options:expr, $key:expr, u32) => {
        $crate::get_option!($options, $key, u32).ok_or_else(|| {
            $crate::engine::error::Error::Config {
                message: format!("Missing required option: {}", $key),
                source: None,
            }
        })?
    };
    ($options:expr, $key:expr, u32, $error_msg:expr) => {
        $crate::get_option!($options, $key, u32).ok_or_else(|| {
            $crate::engine::error::Error::Config {
                message: $error_msg.to_string(),
                source: None,
            }
        })?
    };
    ($options:expr, $key:expr, u64) => {
        $crate::get_option!($options, $key, u64).ok_or_else(|| {
            $crate::engine::error::Error::Config {
                message: format!("Missing required option: {}", $key),
                source: None,
            }
        })?
    };
    ($options:expr, $key:expr, u64, $error_msg:expr) => {
        $crate::get_option!($options, $key, u64).ok_or_else(|| {
            $crate::engine::error::Error::Config {
                message: $error_msg.to_string(),
                source: None,
            }
        })?
    };
    ($options:expr, $key:expr, bool) => {
        $crate::get_option!($options, $key, bool).ok_or_else(|| {
            $crate::engine::error::Error::Config {
                message: format!("Missing required option: {}", $key),
                source: None,
            }
        })?
    };
    ($options:expr, $key:expr, bool, $error_msg:expr) => {
        $crate::get_option!($options, $key, bool).ok_or_else(|| {
            $crate::engine::error::Error::Config {
                message: $error_msg.to_string(),
                source: None,
            }
        })?
    };
    ($options:expr, $key:expr, Vec<String>) => {
        $crate::get_option!($options, $key, Vec<String>).ok_or_else(|| {
            $crate::engine::error::Error::Config {
                message: format!("Missing required option: {}", $key),
                source: None,
            }
        })?
    };
    ($options:expr, $key:expr, Vec<String>, $error_msg:expr) => {
        $crate::get_option!($options, $key, Vec<String>).ok_or_else(|| {
            $crate::engine::error::Error::Config {
                message: $error_msg.to_string(),
                source: None,
            }
        })?
    };
}

#[macro_export]
macro_rules! get_option_or {
    ($options:expr, $key:expr, String, $default:expr) => {
        $crate::get_option!($options, $key, String).unwrap_or_else(|| $default.to_string())
    };
    ($options:expr, $key:expr, u16, $default:expr) => {
        $crate::get_option!($options, $key, u16).unwrap_or($default)
    };
    ($options:expr, $key:expr, u32, $default:expr) => {
        $crate::get_option!($options, $key, u32).unwrap_or($default)
    };
    ($options:expr, $key:expr, u64, $default:expr) => {
        $crate::get_option!($options, $key, u64).unwrap_or($default)
    };
    ($options:expr, $key:expr, bool, $default:expr) => {
        $crate::get_option!($options, $key, bool).unwrap_or($default)
    };
    ($options:expr, $key:expr, Vec<String>, $default:expr) => {
        $crate::get_option!($options, $key, Vec<String>).unwrap_or_else(|| $default)
    };
}

#[macro_export]
macro_rules! impl_outbound_proxy {
    ($name:ident, $tag_field:expr) => {
        impl $name {
            #[inline]
            pub fn proxy_tag(&self) -> &str {
                &$tag_field
            }
        }
    };
    ($name:ident, $tag_field:expr, server: $server_field:expr, port: $port_field:expr) => {
        impl $name {
            #[inline]
            pub fn proxy_tag(&self) -> &str {
                &$tag_field
            }

            #[inline]
            pub fn proxy_server_addr(&self) -> Option<(String, u16)> {
                Some(($server_field.clone(), $port_field))
            }
        }
    };
}

#[macro_export]
macro_rules! impl_outbound_proxy_trait {
    ($name:ident { tag: $tag:expr $(,)? }) => {
        #[async_trait::async_trait]
        impl $crate::engine::outbound::OutboundProxy for $name {
            fn tag(&self) -> &str {
                &$tag
            }

            fn server_addr(&self) -> Option<(String, u16)> {
                None
            }

            async fn connect(&self) -> $crate::engine::error::Result<()> {
                Ok(())
            }

            async fn disconnect(&self) -> $crate::engine::error::Result<()> {
                Ok(())
            }
        }
    };
    ($name:ident { tag: $tag:expr, server: $server:expr, port: $port:expr $(,)? }) => {
        #[async_trait::async_trait]
        impl $crate::engine::outbound::OutboundProxy for $name {
            fn tag(&self) -> &str {
                &$tag
            }

            fn server_addr(&self) -> Option<(String, u16)> {
                Some(($server.clone(), $port))
            }

            async fn connect(&self) -> $crate::engine::error::Result<()> {
                Ok(())
            }

            async fn disconnect(&self) -> $crate::engine::error::Result<()> {
                Ok(())
            }
        }
    };
}

#[macro_export]
macro_rules! impl_transport {
    ($name:ident { config: $config_type:ty $(,)? }) => {
        impl $name {
            pub fn new(config: $config_type) -> $crate::engine::error::Result<Self> {
                Ok(Self { config })
            }

            pub fn config(&self) -> &$config_type {
                &self.config
            }
        }
    };
    ($name:ident { config: $config_type:ty, inner: $inner_type:ty $(,)? }) => {
        impl $name {
            pub fn new(
                config: $config_type,
                inner: $inner_type,
            ) -> $crate::engine::error::Result<Self> {
                Ok(Self { config, inner })
            }

            pub fn config(&self) -> &$config_type {
                &self.config
            }

            pub fn inner(&self) -> &$inner_type {
                &self.inner
            }
        }
    };
}

#[macro_export]
macro_rules! impl_transport_wrap {
    ($self:expr, $stream:expr, $wrap_fn:expr, $transport_name:expr) => {
        $wrap_fn($self, $stream)
            .await
            .map_err(|e| $crate::engine::error::Error::Network {
                message: format!("{} transport error: {}", $transport_name, e),
                source: None,
            })
    };
}

#[macro_export]
macro_rules! connect_with_timeout {
    ($addr:expr, $timeout:expr) => {
        tokio::time::timeout($timeout, tokio::net::TcpStream::connect($addr))
            .await
            .map_err(|_| $crate::engine::error::Error::Timeout {
                message: format!("Connection to {} timed out", $addr),
                operation: Some("connect".to_string()),
            })?
            .map_err(|e| $crate::engine::error::Error::Network {
                message: format!("Failed to connect to {}: {}", $addr, e),
                source: None,
            })
    };
}

#[macro_export]
macro_rules! relay_streams {
    ($inbound:expr, $outbound:expr) => {
        $crate::engine::outbound::relay_bidirectional_with_connection(
            $inbound,
            $outbound,
            $crate::engine::connection_tracker::global_tracker(),
            None,
        )
        .await
    };
    ($inbound:expr, $outbound:expr, $connection:expr) => {
        $crate::engine::outbound::relay_bidirectional_with_connection(
            $inbound,
            $outbound,
            $crate::engine::connection_tracker::global_tracker(),
            $connection,
        )
        .await
    };
}

#[cfg(test)]
mod tests {
    use nextjson::Value;
    use std::collections::HashMap;

    fn create_test_map() -> HashMap<String, Value> {
        let mut map = HashMap::new();
        map.insert("string_val".to_string(), Value::String("hello".to_string()));
        map.insert(
            "number_val".to_string(),
            Value::Number(nextjson::Number::from(42)),
        );
        map.insert("bool_val".to_string(), Value::Bool(true));
        map.insert("string_bool".to_string(), Value::String("yes".to_string()));
        map.insert(
            "array_val".to_string(),
            Value::Array(vec![
                Value::String("a".to_string()),
                Value::String("b".to_string()),
            ]),
        );
        map
    }

    #[test]
    fn test_get_option_string() {
        let map = create_test_map();
        let result = get_option!(map, "string_val", String);
        assert_eq!(result, Some("hello".to_string()));

        let missing = get_option!(map, "missing", String);
        assert_eq!(missing, None);
    }

    #[test]
    fn test_get_option_u16() {
        let map = create_test_map();
        let result = get_option!(map, "number_val", u16);
        assert_eq!(result, Some(42u16));
    }

    #[test]
    fn test_get_option_bool() {
        let map = create_test_map();
        let result = get_option!(map, "bool_val", bool);
        assert_eq!(result, Some(true));

        let string_bool = get_option!(map, "string_bool", bool);
        assert_eq!(string_bool, Some(true));
    }

    #[test]
    fn test_get_option_vec_string() {
        let map = create_test_map();
        let result = get_option!(map, "array_val", Vec<String>);
        assert_eq!(result, Some(vec!["a".to_string(), "b".to_string()]));
    }

    #[test]
    fn test_get_option_or() {
        let map = create_test_map();
        let result = get_option_or!(map, "missing", String, "default");
        assert_eq!(result, "default".to_string());

        let existing = get_option_or!(map, "string_val", String, "default");
        assert_eq!(existing, "hello".to_string());
    }
}
