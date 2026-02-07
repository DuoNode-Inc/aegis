//! AI endpoint recognition — only inspect traffic destined for known AI APIs.
//!
//! Maps gateway path prefixes to upstream API hosts and determines whether
//! a given hostname should be inspected.

/// Gateway route: maps a path prefix to an upstream host.
#[derive(Debug, Clone)]
pub struct GatewayRoute {
    pub prefix: String,
    pub upstream_host: String,
    pub upstream_scheme: String,
}

/// Endpoint matcher — built once at startup.
pub struct EndpointMatcher {
    routes: Vec<GatewayRoute>,
    known_hosts: Vec<String>,
}

impl EndpointMatcher {
    /// Build the matcher from the configured endpoint targets.
    pub fn new(targets: &[String]) -> Self {
        let routes = default_routes();
        Self {
            routes,
            known_hosts: targets.to_vec(),
        }
    }

    /// Match a request path to a gateway route.
    /// Returns (upstream_url, stripped_path) if matched.
    pub fn match_route(&self, path: &str) -> Option<(String, String)> {
        for route in &self.routes {
            if let Some(rest) = path.strip_prefix(&route.prefix) {
                let rest = format!("/{rest}");
                let upstream_url = format!(
                    "{}://{}{}",
                    route.upstream_scheme, route.upstream_host, rest
                );
                return Some((upstream_url, rest));
            }
        }
        None
    }

    /// Check if a hostname is a known AI endpoint.
    pub fn is_ai_endpoint(&self, host: &str) -> bool {
        self.known_hosts.iter().any(|h| host.contains(h.as_str()))
    }
}

/// Default gateway routes mapping path prefixes to upstream AI APIs.
fn default_routes() -> Vec<GatewayRoute> {
    vec![
        GatewayRoute {
            prefix: "/openai/".into(),
            upstream_host: "api.openai.com".into(),
            upstream_scheme: "https".into(),
        },
        GatewayRoute {
            prefix: "/anthropic/".into(),
            upstream_host: "api.anthropic.com".into(),
            upstream_scheme: "https".into(),
        },
        GatewayRoute {
            prefix: "/google/".into(),
            upstream_host: "generativelanguage.googleapis.com".into(),
            upstream_scheme: "https".into(),
        },
        GatewayRoute {
            prefix: "/cohere/".into(),
            upstream_host: "api.cohere.com".into(),
            upstream_scheme: "https".into(),
        },
        GatewayRoute {
            prefix: "/mistral/".into(),
            upstream_host: "api.mistral.ai".into(),
            upstream_scheme: "https".into(),
        },
        GatewayRoute {
            prefix: "/groq/".into(),
            upstream_host: "api.groq.com".into(),
            upstream_scheme: "https".into(),
        },
        GatewayRoute {
            prefix: "/together/".into(),
            upstream_host: "api.together.xyz".into(),
            upstream_scheme: "https".into(),
        },
        GatewayRoute {
            prefix: "/deepseek/".into(),
            upstream_host: "api.deepseek.com".into(),
            upstream_scheme: "https".into(),
        },
        GatewayRoute {
            prefix: "/fireworks/".into(),
            upstream_host: "api.fireworks.ai".into(),
            upstream_scheme: "https".into(),
        },
        GatewayRoute {
            prefix: "/perplexity/".into(),
            upstream_host: "api.perplexity.ai".into(),
            upstream_scheme: "https".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher() -> EndpointMatcher {
        EndpointMatcher::new(&["api.openai.com".into(), "api.anthropic.com".into()])
    }

    #[test]
    fn matches_openai_route() {
        let m = matcher();
        let result = m.match_route("/openai/v1/chat/completions");
        assert!(result.is_some());
        let (url, _) = result.unwrap();
        assert_eq!(url, "https://api.openai.com/v1/chat/completions");
    }

    #[test]
    fn matches_anthropic_route() {
        let m = matcher();
        let result = m.match_route("/anthropic/v1/messages");
        assert!(result.is_some());
        let (url, _) = result.unwrap();
        assert_eq!(url, "https://api.anthropic.com/v1/messages");
    }

    #[test]
    fn no_match_unknown_prefix() {
        let m = matcher();
        assert!(m.match_route("/unknown/v1/foo").is_none());
    }

    #[test]
    fn is_ai_endpoint() {
        let m = matcher();
        assert!(m.is_ai_endpoint("api.openai.com"));
        assert!(!m.is_ai_endpoint("example.com"));
    }
}
