//! Implements event filtering for events originating from CSP endpoints
//!
//! Events originating from a CSP message can be filtered based on the source URL

use relay_general::protocol::{Event, EventType};

use crate::{CspFilterConfig, FilterStatKey};

/// Filters CSP events based on disallowed sources.
pub fn should_filter(event: &Event, config: &CspFilterConfig) -> Result<(), FilterStatKey> {
    let disallowed_sources = &config.disallowed_sources;
    if disallowed_sources.is_empty() || event.ty.value() != Some(&EventType::Csp) {
        return Ok(());
    }

    // parse the sources for easy processing
    let disallowed_sources: Vec<SchemeDomainPort> = disallowed_sources
        .iter()
        .map(|origin| -> SchemeDomainPort { origin.as_str().into() })
        .collect();

    if let Some(csp) = event.csp.value() {
        if matches_any_origin(csp.blocked_uri.as_str(), &disallowed_sources) {
            return Err(FilterStatKey::InvalidCsp);
        }
        if matches_any_origin(csp.source_file.as_str(), &disallowed_sources) {
            return Err(FilterStatKey::InvalidCsp);
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedUrl<'a> {
    scheme: Option<&'a str>,
    domain: &'a str,
    port: Option<&'a str>,
    path: Option<&'a str>,
}

impl<'a> ParsedUrl<'a> {
    pub fn new(url: &'a str) -> Self {
        // Split the scheme from the url.
        let (scheme, rest) = match url.find("://") {
            Some(index) => (Some(&url[..index]), &url[index + 3..]),
            None => (None, url),
        };

        // Extract domain:port from the path of the url.
        let (host, mut path) = match rest.find('/') {
            Some(index) => (&rest[..index], Some(&rest[index + 1..])),
            None => (rest, None),
        };

        if path == Some("") {
            path = None;
        }

        // Split the domain and the port
        let (domain, port) = match host.find(':') {
            Some(index) => (&host[..index], Some(&host[index + 1..])),
            None => (host, None),
        };

        Self {
            scheme,
            domain,
            port,
            path,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PatternComponent<'a> {
    All,
    Pattern(&'a str),
    DomainSuffix(&'a str),
    PathPrefix(&'a str),
}

impl<'a> PatternComponent<'a> {
    pub fn new(pattern: &'a str) -> Self {
        if pattern == "*" {
            Self::All
        } else {
            Self::Pattern(pattern)
        }
    }

    pub fn from_option(pattern: Option<&'a str>) -> Self {
        match pattern {
            Some(pattern) => Self::new(pattern),
            None => Self::All,
        }
    }

    pub fn into_domain_suffix(self) -> Self {
        match self {
            Self::Pattern(pattern) if pattern.starts_with("*.") => {
                Self::DomainSuffix(&pattern[1..])
            }
            other => other,
        }
    }

    pub fn into_path_prefix(self) -> Self {
        match self {
            Self::Pattern(pattern) if pattern.ends_with("*") => {
                Self::PathPrefix(&pattern[..pattern.len() - 1])
            }
            other => other,
        }
    }

    pub fn is_match(&self, component: &str) -> bool {
        match self {
            Self::All => true,
            Self::Pattern(pattern) => pattern.eq_ignore_ascii_case(component),
            Self::DomainSuffix(pattern) => {
                pattern[1..].eq_ignore_ascii_case(component)
                    || component.len() >= pattern.len()
                        && component[component.len() - pattern.len()..]
                            .eq_ignore_ascii_case(pattern)
            }
            Self::PathPrefix(pattern) => {
                component.len() >= pattern.len()
                    && component[..pattern.len()].eq_ignore_ascii_case(component)
            }
        }
    }
}

impl Default for PatternComponent<'_> {
    fn default() -> Self {
        Self::All
    }
}

/// A pattern used to match allowed paths
///
/// scheme, domain and port are extracted from an url
/// they may be either a string (to be matched exactly, case insensitive)
/// or None (matches anything in the respective position)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedUrlPattern<'a> {
    scheme: PatternComponent<'a>,
    domain: PatternComponent<'a>,
    port: PatternComponent<'a>,
    path: PatternComponent<'a>,
}

impl<'a> ParsedUrlPattern<'a> {
    pub fn new(url: &'a str) -> Self {
        Self::from_parsed(ParsedUrl::new(url))
    }

    fn from_parsed(parsed: ParsedUrl<'a>) -> Self {
        Self {
            scheme: PatternComponent::from_option(parsed.scheme),
            domain: PatternComponent::new(parsed.domain).into_domain_suffix(),
            port: PatternComponent::from_option(parsed.port),
            path: PatternComponent::from_option(parsed.path).into_path_prefix(),
        }
    }
}

impl ParsedUrlPattern<'_> {
    pub fn is_match(&self, url: &ParsedUrl) -> bool {
        self.scheme.is_match(url.scheme.unwrap_or(""))
            && self.domain.is_match(url.domain)
            && self.port.is_match(url.port.unwrap_or(""))
            && self.path.is_match(url.path.unwrap_or(""))
    }
}

/// Checks if a url satisfies one of the specified origins.
///
/// An origin specification may be in any of the following formats:
///  - http://domain.com[:port]
///  - an exact match is required
///  - * : anything goes
///  - *.domain.com : matches domain.com and any subdomains
///  - *:port : matches any hostname as long as the port matches
pub fn matches_any_origin(url: Option<&str>, allowed_origins: &[&str]) -> bool {
    let url = match url {
        Some(url) => ParsedUrl::new(url),
        None => return false,
    };

    for allowed_origin in allowed_origins {
        if ParsedUrlPattern::new(allowed_origin).is_match(&url) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    use relay_general::protocol::Csp;
    use relay_general::types::Annotated;

    fn get_csp_event(blocked_uri: Option<&str>, source_file: Option<&str>) -> Event {
        fn annotated_string_or_none(val: Option<&str>) -> Annotated<String> {
            match val {
                None => Annotated::empty(),
                Some(val) => Annotated::from(val.to_string()),
            }
        }
        Event {
            ty: Annotated::from(EventType::Csp),
            csp: Annotated::from(Csp {
                blocked_uri: annotated_string_or_none(blocked_uri),
                source_file: annotated_string_or_none(source_file),
                ..Csp::default()
            }),
            ..Event::default()
        }
    }

    #[test]
    fn test_scheme_domain_port() {
        let examples = &[
            ("*", None, None, None),
            ("*://*", None, None, None),
            ("*://*:*", None, None, None),
            ("https://*", Some("https"), None, None),
            ("https://*.abc.net", Some("https"), Some("*.abc.net"), None),
            ("https://*:*", Some("https"), None, None),
            ("x.y.z", None, Some("x.y.z"), None),
            ("x.y.z:*", None, Some("x.y.z"), None),
            ("*://x.y.z:*", None, Some("x.y.z"), None),
            ("*://*.x.y.z:*", None, Some("*.x.y.z"), None),
            ("*:8000", None, None, Some("8000")),
            ("*://*:8000", None, None, Some("8000")),
            ("http://x.y.z", Some("http"), Some("x.y.z"), None),
            ("http://*:8000", Some("http"), None, Some("8000")),
            ("abc:8000", None, Some("abc"), Some("8000")),
            ("*.abc.com:8000", None, Some("*.abc.com"), Some("8000")),
            ("*.com:86", None, Some("*.com"), Some("86")),
            (
                "http://abc.com:86",
                Some("http"),
                Some("abc.com"),
                Some("86"),
            ),
            (
                "http://x.y.z:4000",
                Some("http"),
                Some("x.y.z"),
                Some("4000"),
            ),
        ];

        for (url, scheme, domain, port) in examples {
            let actual = SchemeDomainPort::from(*url);
            let expected = SchemeDomainPort {
                scheme: scheme.map(str::to_owned),
                domain: domain.map(str::to_owned),
                port: port.map(str::to_owned),
            };

            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn test_matches_any_origin() {
        let examples = &[
            //MATCH
            //generic matches
            ("http://abc1.com", vec!["*://*:*", "bbc.com"], true),
            ("http://abc2.com", vec!["*:*", "bbc.com"], true),
            ("http://abc3.com", vec!["*", "bbc.com"], true),
            ("http://abc4.com", vec!["http://*", "bbc.com"], true),
            (
                "http://abc5.com",
                vec!["http://abc5.com:*", "bbc.com"],
                true,
            ),
            ("http://abc.com:80", vec!["*://*:*", "bbc.com"], true),
            ("http://abc.com:81", vec!["*:*", "bbc.com"], true),
            ("http://abc.com:82", vec!["*:82", "bbc.com"], true),
            ("http://abc.com:83", vec!["http://*:83", "bbc.com"], true),
            ("http://abc.com:84", vec!["abc.com:*", "bbc.com"], true),
            //partial domain matches
            ("http://abc.com:85", vec!["*.abc.com:85", "bbc.com"], true),
            ("http://abc.com:86", vec!["*.com:86"], true),
            ("http://abc.com:86", vec!["*.com:86", "bbc.com"], true),
            ("http://abc.def.ghc.com:87", vec!["*.com:87"], true),
            ("http://abc.def.ghc.com:88", vec!["*.ghc.com:88"], true),
            ("http://abc.def.ghc.com:89", vec!["*.def.ghc.com:89"], true),
            //exact matches
            ("http://abc.com:90", vec!["abc.com", "bbc.com"], true),
            ("http://abc.com:91", vec!["abc.com:91", "bbc.com"], true),
            ("http://abc.com:92", vec!["http://abc.com:92"], true),
            ("http://abc.com:93", vec!["http://abc.com", "bbc.com"], true),
            //matches in various positions
            ("http://abc6.com", vec!["abc6.com", "bbc.com"], true),
            ("http://abc7.com", vec!["bbc.com", "abc7.com"], true),
            ("http://abc8.com", vec!["bbc.com", "abc8.com", "def"], true),
            //NON MATCH
            //different domain
            (
                "http://abc9.com",
                vec!["http://other.com", "bbc.com"],
                false,
            ),
            ("http://abc10.com", vec!["http://*.other.com", "bbc"], false),
            ("abc11.com", vec!["*.other.com", "bbc"], false),
            //different scheme
            (
                "https://abc12.com",
                vec!["http://abc12.com", "bbc.com"],
                false,
            ),
            //different port
            (
                "http://abc13.com:80",
                vec!["http://abc13.com:8080", "bbc.com"],
                false,
            ),
        ];

        for (url, origins, expected) in examples {
            let origins: Vec<_> = origins
                .iter()
                .map(|url| SchemeDomainPort::from(*url))
                .collect();
            let actual = matches_any_origin(Some(&(*url).to_string()), &origins[..]);
            assert_eq!(*expected, actual, "Could not match {}.", url);
        }
    }

    #[test]
    fn test_filters_known_blocked_source_files() {
        let event = get_csp_event(None, Some("http://known.bad.com"));
        let config = CspFilterConfig {
            disallowed_sources: vec!["http://known.bad.com".to_string()],
        };

        let actual = should_filter(&event, &config);
        assert_ne!(
            actual,
            Ok(()),
            "CSP filter should have filtered known bad source file"
        );
    }

    #[test]
    fn test_does_not_filter_benign_source_files() {
        let event = get_csp_event(None, Some("http://good.file.com"));
        let config = CspFilterConfig {
            disallowed_sources: vec!["http://known.bad.com".to_string()],
        };

        let actual = should_filter(&event, &config);
        assert_eq!(
            actual,
            Ok(()),
            "CSP filter should have NOT filtered good source file"
        );
    }

    #[test]
    fn test_filters_known_blocked_uris() {
        let event = get_csp_event(Some("http://known.bad.com"), None);
        let config = CspFilterConfig {
            disallowed_sources: vec!["http://known.bad.com".to_string()],
        };

        let actual = should_filter(&event, &config);
        assert_ne!(
            actual,
            Ok(()),
            "CSP filter should have filtered known blocked uri"
        );
    }

    #[test]
    fn test_does_not_filter_benign_uris() {
        let event = get_csp_event(Some("http://good.file.com"), None);
        let config = CspFilterConfig {
            disallowed_sources: vec!["http://known.bad.com".to_string()],
        };

        let actual = should_filter(&event, &config);
        assert_eq!(
            actual,
            Ok(()),
            "CSP filter should have NOT filtered unknown blocked uri"
        );
    }

    #[test]
    fn test_does_not_filter_non_csp_messages() {
        let mut event = get_csp_event(Some("http://known.bad.com"), None);
        event.ty = Annotated::from(EventType::Transaction);
        let config = CspFilterConfig {
            disallowed_sources: vec!["http://known.bad.com".to_string()],
        };

        let actual = should_filter(&event, &config);
        assert_eq!(
            actual,
            Ok(()),
            "CSP filter should have NOT filtered non CSP event"
        );
    }

    fn get_disallowed_sources() -> Vec<String> {
        vec![
            "about".to_string(),
            "ms-browser-extension".to_string(),
            "*.superfish.com".to_string(),
            "chrome://*".to_string(),
            "chrome-extension://*".to_string(),
            "chromeinvokeimmediate://*".to_string(),
            "chromenull://*".to_string(),
            "localhost".to_string(),
        ]
    }

    /// Copy the test cases from Sentry
    #[test]
    fn test_sentry_csp_filter_compatibility_bad_reports() {
        let examples = &[
            (Some("about"), None),
            (Some("ms-browser-extension"), None),
            (Some("http://foo.superfish.com"), None),
            (None, Some("chrome-extension://fdsa")),
            (None, Some("http://localhost:8000")),
            (None, Some("http://localhost")),
            (None, Some("http://foo.superfish.com")),
        ];

        for (blocked_uri, source_file) in examples {
            let event = get_csp_event(*blocked_uri, *source_file);
            let config = CspFilterConfig {
                disallowed_sources: get_disallowed_sources(),
            };

            let actual = should_filter(&event, &config);
            assert_ne!(
                actual,
                Ok(()),
                "CSP filter should have filtered  bad request {:?} {:?}",
                blocked_uri,
                source_file
            );
        }
    }

    #[test]
    fn test_sentry_csp_filter_compatibility_good_reports() {
        let examples = &[
            (Some("http://example.com"), None),
            (None, Some("http://example.com")),
            (None, None),
        ];

        for (blocked_uri, source_file) in examples {
            let event = get_csp_event(*blocked_uri, *source_file);
            let config = CspFilterConfig {
                disallowed_sources: get_disallowed_sources(),
            };

            let actual = should_filter(&event, &config);
            assert_eq!(
                actual,
                Ok(()),
                "CSP filter should have  NOT filtered  request {:?} {:?}",
                blocked_uri,
                source_file
            );
        }
    }
}
