use std::collections::BTreeMap;
use std::time::Duration;

const DIRECTIVES: &[(&str, &[&str])] = &[
    ("default-src", &["'self'"]),
    ("script-src", &["'self'"]),
    ("style-src", &["'self'"]),
    ("img-src", &["'self'", "data:"]),
    ("font-src", &["'self'"]),
    ("connect-src", &["'self'"]),
    ("frame-ancestors", &["'none'"]),
    ("object-src", &["'none'"]),
    ("base-uri", &["'self'"]),
    ("form-action", &["'self'"]),
];

fn validate(policy: &str) -> Result<(), &'static str> {
    let mut directives = BTreeMap::new();
    for directive in policy.split(';').filter(|s| !s.trim().is_empty()) {
        let mut words = directive.split_ascii_whitespace();
        let name = words.next().ok_or("invalid sidecar CSP")?;
        let sources: Vec<_> = words.collect();
        if directives.insert(name, sources).is_some() {
            return Err("duplicate sidecar CSP directive");
        }
    }
    if directives.len() != DIRECTIVES.len() {
        return Err("unexpected sidecar CSP directives");
    }
    for (name, allowed) in DIRECTIVES {
        let sources = directives
            .get(name)
            .ok_or("missing sidecar CSP directive")?;
        if sources.is_empty()
            || (sources.as_slice() != ["'none'"]
                && sources.iter().any(|source| !allowed.contains(source)))
        {
            return Err("unsafe sidecar CSP source");
        }
    }
    Ok(())
}

/// Check the server's enforced policy before issuing any desktop credentials.
pub fn verify_sidecar(base: &str) -> Result<(), &'static str> {
    let url = crate::session::bootstrap_url(base).map_err(|_| "invalid sidecar origin")?;
    let response = ureq::AgentBuilder::new()
        .redirects(0)
        .try_proxy_from_env(false)
        .timeout(Duration::from_secs(5))
        .build()
        .get(url.as_str())
        .call()
        .map_err(|_| "sidecar CSP request failed")?;
    if response.status() != 200 {
        return Err("sidecar CSP request refused");
    }
    let policies = response.all("Content-Security-Policy");
    if policies.len() != 1 {
        return Err("missing or ambiguous sidecar CSP");
    }
    validate(policies[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> String {
        DIRECTIVES
            .iter()
            .map(|(name, sources)| format!("{name} {}", sources.join(" ")))
            .collect::<Vec<_>>()
            .join("; ")
    }

    #[test]
    fn accepts_expected_policy_and_stricter_sources() {
        assert!(validate(&policy()).is_ok());
        assert!(validate(
            &policy()
                .replace("'self'", "'none'")
                .replace("'none' data:", "'none'")
        )
        .is_ok());
    }

    #[test]
    fn rejects_missing_duplicate_and_overriding_directives() {
        for (name, _) in DIRECTIVES {
            let missing = policy()
                .split(';')
                .filter(|d| !d.trim().starts_with(name))
                .collect::<Vec<_>>()
                .join(";");
            assert!(validate(&missing).is_err(), "accepted missing {name}");
            assert!(validate(&format!("{}; {name} *", policy())).is_err());
        }
        for extra in [
            "script-src-elem *",
            "script-src-attr 'unsafe-inline'",
            "style-src-elem *",
        ] {
            assert!(validate(&format!("{}; {extra}", policy())).is_err());
        }
        for source in [
            "*",
            "http:",
            "https:",
            "'unsafe-inline'",
            "'unsafe-eval'",
            "data:",
        ] {
            assert!(validate(
                &policy().replace("script-src 'self'", &format!("script-src 'self' {source}"))
            )
            .is_err());
        }
        assert!(validate("").is_err());
    }

    #[test]
    fn checks_actual_headers_without_credentials_and_refuses_redirects() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        for (status, headers, accepted) in [
            (
                "200 OK",
                format!("Content-Security-Policy: {}\r\n", policy()),
                true,
            ),
            (
                "200 OK",
                format!("Content-Security-Policy-Report-Only: {}\r\n", policy()),
                false,
            ),
            (
                "200 OK",
                "Content-Security-Policy: default-src *\r\n".to_string(),
                false,
            ),
            (
                "302 Found",
                "Location: http://127.0.0.1:1/\r\n".to_string(),
                false,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                    request.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\n{headers}Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
                request
            });
            assert_eq!(verify_sidecar(&base).is_ok(), accepted);
            let request = server.join().unwrap();
            assert!(request.starts_with("GET /__bootstrap HTTP/1.1\r\n"));
            assert!(!request.to_ascii_lowercase().contains("cookie:"));
            assert!(!request.to_ascii_lowercase().contains("authorization:"));
        }
    }
}
