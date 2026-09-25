use crate::engine::config::*;
use crate::engine::error::{Error, Result};

/// Configuration validator
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validate the entire configuration
    pub fn validate(config: &Config) -> Result<()> {
        Self::validate_general(&config.general)?;
        Self::validate_dns(&config.dns)?;
        Self::validate_inbounds(&config.inbounds)?;
        Self::validate_outbounds(&config.outbounds)?;
        Self::validate_rules(&config.rules)?;
        Self::validate_cross_references(config)?;
        Ok(())
    }

    /// Validate general configuration
    fn validate_general(general: &GeneralConfig) -> Result<()> {
        // Only the port fields something actually reads are validated here.
        // `mixed_port` and `socks_port` select the local inbound that captured
        // TUN traffic is handed to, and `bind_address` is the listen address an
        // inbound falls back to; `port`, `redir_port` and `tproxy_port` were
        // accepted and never read, so they are gone from the schema instead of
        // being validated for an effect they never had.
        for (label, port) in [
            ("socks_port", general.socks_port),
            ("mixed_port", general.mixed_port),
        ] {
            if port == Some(0) {
                return Err(Error::config(format!(
                    "Invalid {label}: must be between 1 and 65535"
                )));
            }
        }

        // Validate bind address
        if general.bind_address.is_empty() {
            return Err(Error::config("bind_address cannot be empty"));
        }

        // The external controller is served by `rpc::controller`. Its address is
        // parsed here so that a typo is a load error instead of a dashboard
        // that quietly never appears. Whether the address may be *served* is a
        // separate question, answered at bind time by
        // `ExternalControllerConfig::guard`, which refuses a non-loopback bind
        // without a secret.
        if let Some(external_controller) = general
            .external_controller
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            crate::rpc::controller::ExternalControllerConfig::parse(
                external_controller,
                general.secret.as_deref(),
            )
            .map_err(Error::config)?;
        }

        // `external-ui` serves a dashboard's static files, which this build
        // does not do. Saying so is the difference between a setting that does
        // nothing and a setting that silently does nothing.
        if general.external_ui.is_some() {
            tracing::warn!(
                "external-ui is configured but this build serves no static dashboard \
                 files, so the setting has no effect"
            );
        }

        // Validate IPv6 setting doesn't conflict with bind address
        if !general.ipv6
            && general.bind_address.contains(':')
            && !general.bind_address.starts_with('[')
        {
            return Err(Error::config(
                "IPv6 bind address requires ipv6 to be enabled",
            ));
        }

        Ok(())
    }

    /// Validate DNS configuration
    /// Validate the DNS section.
    ///
    /// Checked whether or not the section is enabled, because a syntax error is
    /// a syntax error: a profile that carries a mistyped `fake-ip-range` has a
    /// bug its author cannot see while the setting is inert, and it becomes a
    /// mystery the day the feature is switched on.
    fn validate_dns(dns: &DnsConfig) -> Result<()> {
        if dns.enable && dns.listen.trim().is_empty() {
            return Err(Error::config("DNS listen address cannot be empty"));
        }
        // A listener is started from this string, so an address it cannot parse
        // is a configuration error — not something to discover as a warning at
        // startup, when the operator has already stopped reading.
        if dns.enable {
            dns.listen
                .trim()
                .parse::<std::net::SocketAddr>()
                .map_err(|error| {
                    Error::config(format!(
                        "dns.listen '{}' is not an address: {error}",
                        dns.listen
                    ))
                })?;
        }

        for (label, servers) in [
            ("nameservers", &dns.nameservers),
            ("fallback", &dns.fallback),
            ("default-nameserver", &dns.default_nameserver),
        ] {
            for server in servers.iter() {
                if server.trim().is_empty() {
                    return Err(Error::config(format!(
                        "dns.{label} contains an empty entry"
                    )));
                }
            }
        }

        for (suffix, servers) in &dns.nameserver_policy {
            if suffix.trim().is_empty() {
                return Err(Error::config(
                    "dns.nameserver-policy contains an empty key".to_string(),
                ));
            }
            if servers.is_empty() {
                return Err(Error::config(format!(
                    "dns.nameserver-policy['{suffix}'] has no servers"
                )));
            }
        }

        // The fake-IP pool is an IPv4 pool: the stack hands out an `Ipv4Addr`,
        // so an IPv6 range here is not a preference, it is unusable.
        let pool = dns.fake_ip_network().map_err(Error::config)?;
        if !matches!(pool, ipnet::IpNet::V4(_)) {
            return Err(Error::config(format!(
                "dns.fake-ip-range '{}' must be IPv4; the fake-IP pool hands out IPv4 addresses",
                dns.fake_ip_range
            )));
        }

        for entry in &dns.fake_ip_filter {
            if entry.trim().is_empty() {
                return Err(Error::config(
                    "dns.fake-ip-filter contains an empty suffix".to_string(),
                ));
            }
        }

        for network in &dns.fallback_filter.ipcidr {
            if network.trim().parse::<ipnet::IpNet>().is_err() {
                return Err(Error::config(format!(
                    "dns.fallback-filter.ipcidr '{network}' is not a CIDR"
                )));
            }
        }

        for (host, address) in &dns.hosts {
            if host.trim().is_empty() {
                return Err(Error::config(
                    "dns.hosts contains an empty host name".to_string(),
                ));
            }
            // A value that is not an IP literal is deliberately accepted rather
            // than rejected: this dialect allows aliasing one name to another
            // here, and refusing to load a whole profile over an entry
            // this build cannot use would be a worse outcome than ignoring it.
            // The consumer warns about the entries it skips.
            if address.trim().is_empty() {
                return Err(Error::config(format!("dns.hosts['{host}'] has no value")));
            }
        }

        if dns.cache_size == 0 {
            return Err(Error::config(
                "dns.cache-size must be at least 1".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate inbound configurations
    fn validate_inbounds(inbounds: &[InboundConfig]) -> Result<()> {
        if inbounds.is_empty() {
            return Err(Error::config("At least one inbound must be configured"));
        }

        let mut tags = std::collections::HashSet::new();

        for inbound in inbounds {
            // Check for duplicate tags
            if !tags.insert(&inbound.tag) {
                return Err(Error::config(format!(
                    "Duplicate inbound tag: {}",
                    inbound.tag
                )));
            }

            // Validate tag
            if inbound.tag.is_empty() {
                return Err(Error::config("Inbound tag cannot be empty"));
            }

            // Validate listen address
            if inbound.listen.is_empty() {
                return Err(Error::config(format!(
                    "Inbound {} listen address cannot be empty",
                    inbound.tag
                )));
            }

            // Validate port
            if inbound.port == 0 {
                return Err(Error::config(format!(
                    "Inbound {} has invalid port",
                    inbound.tag
                )));
            }

            // Type-specific validation
            match inbound.inbound_type {
                InboundType::Http | InboundType::Socks5 | InboundType::Mixed => {
                    // These types are supported
                }
                InboundType::Redir | InboundType::Tproxy => {
                    // These require specific platform support
                    #[cfg(not(target_os = "linux"))]
                    {
                        return Err(Error::config(format!(
                            "Inbound type {:?} is only supported on Linux",
                            inbound.inbound_type
                        )));
                    }
                }
                InboundType::Tun => {}
            }
        }

        Ok(())
    }

    /// Validate outbound configurations
    fn validate_outbounds(outbounds: &[OutboundConfig]) -> Result<()> {
        if outbounds.is_empty() {
            return Err(Error::config("At least one outbound must be configured"));
        }

        let mut tags = std::collections::HashSet::new();
        let mut has_direct = false;

        for outbound in outbounds {
            // Check for duplicate tags
            if !tags.insert(&outbound.tag) {
                return Err(Error::config(format!(
                    "Duplicate outbound tag: {}",
                    outbound.tag
                )));
            }

            // Validate tag
            if outbound.tag.is_empty() {
                return Err(Error::config("Outbound tag cannot be empty"));
            }

            // A protocol this build did not compile in fails here, naming the
            // cargo feature — not later on a missing server field.
            if let Some(feature) = outbound.outbound_type.disabled_feature() {
                return Err(disabled_protocol_error(&outbound.tag, feature));
            }

            // Check for direct outbound
            if outbound.outbound_type == OutboundType::Direct {
                has_direct = true;
            }

            // Type-specific validation
            match outbound.outbound_type {
                OutboundType::Direct | OutboundType::Reject => {
                    // Direct and Reject don't need server/port
                }
                OutboundType::Socks5
                | OutboundType::Socks4
                | OutboundType::Http
                | OutboundType::Shadowsocks
                | OutboundType::ShadowsocksR
                | OutboundType::Snell
                | OutboundType::Vmess
                | OutboundType::Vless
                | OutboundType::Trojan
                | OutboundType::Wireguard
                | OutboundType::Tuic
                | OutboundType::Hysteria
                | OutboundType::Hysteria2
                | OutboundType::ShadowTls
                | OutboundType::Naive => {
                    Self::require_outbound_endpoint(outbound)?;
                }
                // Proxy group types don't need server/port
                OutboundType::Selector
                | OutboundType::Urltest
                | OutboundType::Fallback
                | OutboundType::Loadbalance
                | OutboundType::Relay => {
                    // Proxy groups reference other outbounds, no server needed
                }
            }
        }

        // Ensure there's at least one direct outbound
        if !has_direct {
            return Err(Error::config(
                "At least one direct outbound must be configured",
            ));
        }

        Ok(())
    }

    /// Validate that a server-based outbound has a non-empty server and a
    /// valid port (1..=65535).
    fn require_outbound_endpoint(outbound: &OutboundConfig) -> Result<()> {
        let server = outbound
            .server
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                Error::config(format!(
                    "Outbound '{}' requires a non-empty server address",
                    outbound.tag
                ))
            })?;

        let port = outbound.port.ok_or_else(|| {
            Error::config(format!(
                "Outbound '{}' requires a server port",
                outbound.tag
            ))
        })?;
        if port == 0 {
            return Err(Error::config(format!(
                "Outbound '{}' has invalid server port: must be between 1 and 65535",
                outbound.tag
            )));
        }
        let _ = server;
        Ok(())
    }

    /// Validate routing rules
    ///
    /// Payload syntax — CIDR, regex, port ranges, transports — is checked by
    /// the router while it compiles. This pass only rejects rules that are
    /// missing the one thing their type cannot work without, so a caller gets
    /// the diagnostic at config load instead of on the first connection.
    fn validate_rules(rules: &[RuleConfig]) -> Result<()> {
        for rule in rules {
            // `match` is the catch-all and a combinator carries its condition
            // in its children, so nothing else may have an empty payload.
            let needs_payload = !matches!(
                rule.rule_type,
                RuleType::And | RuleType::Or | RuleType::Not | RuleType::Match
            );
            if needs_payload && rule.payload.trim().is_empty() {
                return Err(Error::config(format!(
                    "{:?} rule payload cannot be empty",
                    rule.rule_type
                )));
            }

            if matches!(rule.rule_type, RuleType::And | RuleType::Or | RuleType::Not)
                && rule.rules.is_empty()
            {
                return Err(Error::config(format!(
                    "{:?} rule needs at least one child rule",
                    rule.rule_type
                )));
            }

            if rule.rule_type == RuleType::Not && rule.rules.len() != 1 {
                return Err(Error::config(
                    "not rule takes exactly one child rule".to_string(),
                ));
            }

            // Validate outbound tag
            if rule.outbound.is_empty() {
                return Err(Error::config("Rule outbound cannot be empty"));
            }
        }

        Ok(())
    }

    /// Validate cross-references between configuration sections
    fn validate_cross_references(config: &Config) -> Result<()> {
        // Collect all outbound tags
        let outbound_tags: std::collections::HashSet<_> =
            config.outbounds.iter().map(|o| o.tag.as_str()).collect();

        // Check that all rule outbound references exist
        for rule in &config.rules {
            if !outbound_tags.contains(rule.outbound.as_str()) {
                return Err(Error::config(format!(
                    "Rule references non-existent outbound: {}",
                    rule.outbound
                )));
            }
        }

        // Proxy groups (selector/url-test/fallback/load-balance/relay) reference
        // other outbounds by tag through their `outbounds` option. Validate those
        // references eagerly so a typo fails config validation instead of at
        // runtime when traffic is routed.
        for outbound in &config.outbounds {
            if !matches!(
                outbound.outbound_type,
                OutboundType::Selector
                    | OutboundType::Urltest
                    | OutboundType::Fallback
                    | OutboundType::Loadbalance
                    | OutboundType::Relay
            ) {
                continue;
            }

            let Some(outbounds_value) = outbound.options.get("outbounds") else {
                return Err(Error::config(format!(
                    "Proxy group '{}' requires an 'outbounds' list",
                    outbound.tag
                )));
            };

            let members: Vec<String> = if let Some(arr) = outbounds_value.as_array() {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            } else if let Some(s) = outbounds_value.as_str() {
                nextjson::from_str::<Vec<String>>(s).unwrap_or_default()
            } else {
                return Err(Error::config(format!(
                    "Proxy group '{}' has an invalid 'outbounds' value",
                    outbound.tag
                )));
            };

            if members.is_empty() {
                return Err(Error::config(format!(
                    "Proxy group '{}' must reference at least one outbound",
                    outbound.tag
                )));
            }

            // Proxy providers supply dynamic outbound tags that are not known
            // at config-validation time. When any provider is declared, member
            // references that are neither static outbounds nor builtins are
            // allowed (they are resolved at group-construction time); when no
            // provider is declared the check stays strict so typos fail early.
            let provider_names: std::collections::HashSet<String> =
                crate::engine::proxy_provider::runtime_proxy_providers()
                    .iter()
                    .map(|provider| provider.name.clone())
                    .collect();
            let has_dynamic_tags = !provider_names.is_empty();

            for member in &members {
                let is_builtin =
                    member.eq_ignore_ascii_case("direct") || member.eq_ignore_ascii_case("reject");
                let is_static =
                    outbound_tags.contains(member.as_str()) || provider_names.contains(member);
                if !is_builtin && !is_static && !has_dynamic_tags {
                    return Err(Error::config(format!(
                        "Proxy group '{}' references non-existent outbound: {}",
                        outbound.tag, member
                    )));
                }
            }

            // A group's `use:` option must reference a declared proxy provider.
            if let Some(use_value) = outbound.options.get("use") {
                let use_names: Vec<String> = if let Some(arr) = use_value.as_array() {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                } else if let Some(s) = use_value.as_str() {
                    nextjson::from_str::<Vec<String>>(s).unwrap_or_default()
                } else {
                    return Err(Error::config(format!(
                        "Proxy group '{}' has an invalid 'use' value",
                        outbound.tag
                    )));
                };
                for use_name in use_names {
                    if !provider_names.contains(&use_name) {
                        return Err(Error::config(format!(
                            "Proxy group '{}' references unknown proxy provider: {}",
                            outbound.tag, use_name
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config() {
        let config = Config {
            general: GeneralConfig::default(),
            dns: DnsConfig::default(),
            inbounds: vec![InboundConfig {
                inbound_type: InboundType::Http,
                tag: "http-in".to_string(),
                listen: "127.0.0.1".to_string(),
                port: 7890,
                options: Default::default(),
            }],
            outbounds: vec![
                OutboundConfig {
                    outbound_type: OutboundType::Direct,
                    tag: "direct".to_string(),
                    server: None,
                    port: None,
                    options: Default::default(),
                },
                OutboundConfig {
                    outbound_type: OutboundType::Socks5,
                    tag: "proxy".to_string(),
                    server: Some("127.0.0.1".to_string()),
                    port: Some(1080),
                    options: Default::default(),
                },
            ],
            rules: vec![RuleConfig {
                rule_type: RuleType::Match,
                payload: "".to_string(),
                outbound: "direct".to_string(),
                process_name: None,
                ..RuleConfig::default()
            }],
        };

        assert!(ConfigValidator::validate(&config).is_ok());
    }

    #[test]
    fn test_invalid_config_no_inbound() {
        let config = Config {
            general: GeneralConfig::default(),
            dns: DnsConfig::default(),
            inbounds: vec![],
            outbounds: vec![OutboundConfig {
                outbound_type: OutboundType::Direct,
                tag: "direct".to_string(),
                server: None,
                port: None,
                options: Default::default(),
            }],
            rules: vec![],
        };

        assert!(ConfigValidator::validate(&config).is_err());
    }

    #[test]
    fn test_invalid_config_no_direct_outbound() {
        let config = Config {
            general: GeneralConfig::default(),
            dns: DnsConfig::default(),
            inbounds: vec![InboundConfig {
                inbound_type: InboundType::Http,
                tag: "http-in".to_string(),
                listen: "127.0.0.1".to_string(),
                port: 7890,
                options: Default::default(),
            }],
            outbounds: vec![OutboundConfig {
                outbound_type: OutboundType::Socks5,
                tag: "proxy".to_string(),
                server: Some("127.0.0.1".to_string()),
                port: Some(1080),
                options: Default::default(),
            }],
            rules: vec![],
        };

        assert!(ConfigValidator::validate(&config).is_err());
    }

    /// A protocol whose cargo feature this build disabled must be rejected at
    /// validation time with a message naming the feature — fail closed, never
    /// a silent fallback to a direct connection.
    #[test]
    fn feature_gated_outbounds_fail_closed() {
        for (outbound_type, feature) in [
            (OutboundType::Wireguard, "wireguard"),
            (OutboundType::Tuic, "tuic"),
            (OutboundType::Hysteria2, "hysteria2"),
        ] {
            let config = Config {
                general: GeneralConfig::default(),
                dns: DnsConfig::default(),
                inbounds: vec![InboundConfig {
                    inbound_type: InboundType::Http,
                    tag: "http-in".to_string(),
                    listen: "127.0.0.1".to_string(),
                    port: 7890,
                    options: Default::default(),
                }],
                outbounds: vec![
                    OutboundConfig {
                        outbound_type: OutboundType::Direct,
                        tag: "direct".to_string(),
                        server: None,
                        port: None,
                        options: Default::default(),
                    },
                    OutboundConfig {
                        outbound_type,
                        tag: "proxy".to_string(),
                        server: Some("example.com".to_string()),
                        port: Some(443),
                        options: Default::default(),
                    },
                ],
                rules: vec![],
            };

            match outbound_type.disabled_feature() {
                Some(missing) => {
                    assert_eq!(missing, feature);
                    let error = ConfigValidator::validate(&config)
                        .expect_err("a disabled protocol must be rejected")
                        .to_string();
                    assert!(
                        error.contains(feature),
                        "error must name the missing feature: {error}"
                    );
                }
                None => ConfigValidator::validate(&config)
                    .expect("a compiled-in protocol must validate"),
            }
        }
    }
}
