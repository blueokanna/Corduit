use nextjson::{NsonDeserialize, NsonSerialize};
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CipherKind {
    #[default]
    Aes256Gcm,
    Aes128Gcm,
    Chacha20Poly1305,
    Aead2022Aes256Gcm,
    Aead2022Aes128Gcm,
    Aead2022Chacha20Poly1305,
}

crate::impl_protocol_enum!(CipherKind {
    Aes256Gcm => "aes-256-gcm",
    Aes128Gcm => "aes-128-gcm",
    Chacha20Poly1305 => "chacha20-poly1305" | "chacha20-ietf-poly1305",
    Aead2022Aes256Gcm => "2022-blake3-aes-256-gcm",
    Aead2022Aes128Gcm => "2022-blake3-aes-128-gcm",
    Aead2022Chacha20Poly1305 => "2022-blake3-chacha20-poly1305" | "2022-blake3-chacha20-ietf-poly1305",
});

impl CipherKind {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "aes-128-gcm" => Some(Self::Aes128Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(Self::Chacha20Poly1305),
            "2022-blake3-aes-256-gcm" => Some(Self::Aead2022Aes256Gcm),
            "2022-blake3-aes-128-gcm" => Some(Self::Aead2022Aes128Gcm),
            "2022-blake3-chacha20-ietf-poly1305" | "2022-blake3-chacha20-poly1305" => {
                Some(Self::Aead2022Chacha20Poly1305)
            }
            _ => None,
        }
    }

    #[inline]
    pub const fn key_size(&self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aead2022Aes128Gcm => 16,
            _ => 32,
        }
    }

    #[inline]
    pub const fn nonce_size(&self) -> usize {
        12
    }

    #[inline]
    pub const fn tag_size(&self) -> usize {
        16
    }

    #[inline]
    pub const fn is_aead_2022(&self) -> bool {
        matches!(
            self,
            Self::Aead2022Aes256Gcm | Self::Aead2022Aes128Gcm | Self::Aead2022Chacha20Poly1305
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionControl {
    #[default]
    Cubic,
    NewReno,
    Bbr,
}

crate::impl_protocol_enum!(CongestionControl {
    Cubic => "cubic",
    NewReno => "new-reno" | "newreno",
    Bbr => "bbr",
});

#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct TransportConfig {
    #[serde(default = "defaults::idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,

    #[serde(default = "defaults::keep_alive", with = "option_duration")]
    pub keep_alive_interval: Option<Duration>,

    #[serde(default = "defaults::max_bi_streams")]
    pub max_concurrent_bi_streams: u32,

    #[serde(default = "defaults::max_uni_streams")]
    pub max_concurrent_uni_streams: u32,

    #[serde(default = "defaults::initial_rtt", with = "humantime_serde")]
    pub initial_rtt: Duration,

    #[serde(default = "defaults::zero_rtt")]
    pub zero_rtt: bool,

    #[serde(default)]
    pub congestion_control: CongestionControl,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            idle_timeout: defaults::idle_timeout(),
            keep_alive_interval: defaults::keep_alive(),
            max_concurrent_bi_streams: defaults::max_bi_streams(),
            max_concurrent_uni_streams: defaults::max_uni_streams(),
            initial_rtt: defaults::initial_rtt(),
            zero_rtt: defaults::zero_rtt(),
            congestion_control: CongestionControl::default(),
        }
    }
}

#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct ClientConfig {
    pub server_addr: SocketAddr,
    pub password: String,

    #[serde(default)]
    pub cipher: CipherKind,

    pub server_name: Option<String>,

    #[serde(default = "defaults::alpn")]
    pub alpn: Vec<String>,

    #[serde(default)]
    pub skip_cert_verify: bool,

    #[serde(default)]
    pub transport: TransportConfig,

    pub local_addr: Option<SocketAddr>,

    #[serde(default = "defaults::udp_relay")]
    pub udp_relay: bool,
}

#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub password: String,

    #[serde(default)]
    pub cipher: CipherKind,

    pub certificate: String,
    pub private_key: String,

    #[serde(default = "defaults::alpn")]
    pub alpn: Vec<String>,

    #[serde(default)]
    pub transport: TransportConfig,

    #[serde(default = "defaults::udp_relay")]
    pub udp_relay: bool,

    pub fallback: Option<SocketAddr>,
}

mod defaults {
    use std::time::Duration;

    pub fn idle_timeout() -> Duration {
        Duration::from_secs(30)
    }

    pub fn keep_alive() -> Option<Duration> {
        Some(Duration::from_secs(15))
    }

    pub fn max_bi_streams() -> u32 {
        100
    }

    pub fn max_uni_streams() -> u32 {
        100
    }

    pub fn initial_rtt() -> Duration {
        Duration::from_millis(100)
    }

    pub fn zero_rtt() -> bool {
        true
    }

    pub fn alpn() -> Vec<String> {
        vec!["h3".into(), "h3-29".into()]
    }

    pub fn udp_relay() -> bool {
        true
    }
}

mod humantime_serde {
    use nextjson::{FormatDecoder, FormatEncoder};
    use std::time::Duration;

    pub fn serialize<E: FormatEncoder>(
        duration: &Duration,
        encoder: &mut E,
    ) -> Result<(), E::Error> {
        encoder.write_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D: FormatDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Duration, D::Error> {
        let secs = decoder.u64()?;
        Ok(Duration::from_secs(secs))
    }
}

mod option_duration {
    use nextjson::{FormatDecoder, FormatEncoder, OptionTag};
    use std::time::Duration;

    pub fn serialize<E: FormatEncoder>(
        duration: &Option<Duration>,
        encoder: &mut E,
    ) -> Result<(), E::Error> {
        match duration {
            Some(d) => {
                encoder.write_some()?;
                encoder.write_u64(d.as_secs())
            }
            None => encoder.write_none(),
        }
    }

    pub fn deserialize<'de, D: FormatDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Option<Duration>, D::Error> {
        match decoder.option_tag()? {
            OptionTag::None => Ok(None),
            OptionTag::Some => {
                let secs = decoder.u64()?;
                Ok(Some(Duration::from_secs(secs)))
            }
        }
    }
}
