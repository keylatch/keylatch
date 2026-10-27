use std::io::Read;
use std::time::Duration;

use serde::de::DeserializeOwned;
use url::Url;

use crate::session::bootstrap_url;

pub const SESSION_EXPIRED: &str = "approval session expired";

/// A separate native session; never reads the WebView cookie jar.
pub struct DesktopHttp {
    agent: ureq::Agent,
    origin: Url,
    cookie: String,
}

impl DesktopHttp {
    pub fn connect(base: &str, token: &str) -> Result<Self, &'static str> {
        let bootstrap = bootstrap_url(base).map_err(|_| "invalid sidecar origin")?;
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .try_proxy_from_env(false)
            .timeout(Duration::from_secs(5))
            .build();
        let response = agent
            .post(bootstrap.as_str())
            .send_json(serde_json::json!({"token": token}))
            .map_err(|_| "native session exchange failed")?;
        if response.status() != 204 {
            return Err("native session exchange refused");
        }
        let mut cookies = response
            .all("set-cookie")
            .into_iter()
            .filter_map(|header| header.split(';').next())
            .filter(|value| value.starts_with("kl_session="));
        let cookie = cookies.next().ok_or("missing native session cookie")?;
        let value = cookie.strip_prefix("kl_session=").unwrap_or("");
        if value.len() != 32
            || !value.bytes().all(|b| b.is_ascii_hexdigit())
            || cookies.next().is_some()
        {
            return Err("invalid native session cookie");
        }
        let mut origin = bootstrap;
        origin.set_path("/");
        Ok(Self {
            agent,
            origin,
            cookie: cookie.to_string(),
        })
    }

    pub fn approvals<T: DeserializeOwned>(&self) -> Result<T, &'static str> {
        let mut url = self.origin.clone();
        url.set_path("/api/approvals");
        let response = self
            .agent
            .get(url.as_str())
            .set("Cookie", &self.cookie)
            .call()
            .map_err(|error| match error {
                ureq::Error::Status(401, _) => SESSION_EXPIRED,
                _ => "approval poll failed",
            })?;
        if response.status() != 200 {
            return Err("approval poll refused");
        }
        let mut body = Vec::new();
        response
            .into_reader()
            .take(1_048_577)
            .read_to_end(&mut body)
            .map_err(|_| "approval response read failed")?;
        if body.len() > 1_048_576 {
            return Err("approval response too large");
        }
        serde_json::from_slice(&body).map_err(|_| "invalid approval response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    fn serve(responses: Vec<String>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request = String::new();
                    let mut length = 0;
                    loop {
                        let mut line = String::new();
                        assert_ne!(
                            reader.read_line(&mut line).unwrap(),
                            0,
                            "request ended before headers"
                        );
                        if let Some(value) =
                            line.to_ascii_lowercase().strip_prefix("content-length:")
                        {
                            length = value.trim().parse::<usize>().unwrap();
                        }
                        request.push_str(&line);
                        if line == "\r\n" {
                            break;
                        }
                    }
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    request.push_str(std::str::from_utf8(&body).unwrap());
                    stream.write_all(response.as_bytes()).unwrap();
                    request
                })
                .collect()
        });
        (base, thread)
    }

    #[test]
    fn exchanges_body_token_and_authenticates_poll() {
        let cookie = "0123456789abcdef0123456789abcdef";
        let (base, server) = serve(vec![
            format!("HTTP/1.1 204 No Content\r\nSet-Cookie: kl_session={cookie}; HttpOnly; SameSite=Strict\r\nConnection: close\r\n\r\n"),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]".into(),
        ]);
        let client = DesktopHttp::connect(&base, "one-use-token").unwrap();
        assert!(client
            .approvals::<Vec<serde_json::Value>>()
            .unwrap()
            .is_empty());
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("POST /__bootstrap HTTP/1.1\r\n"));
        assert!(requests[0].ends_with("{\"token\":\"one-use-token\"}"));
        assert!(requests[1].starts_with("GET /api/approvals HTTP/1.1\r\n"));
        assert!(requests[1]
            .to_ascii_lowercase()
            .contains(&format!("cookie: kl_session={cookie}\r\n")));
        assert!(!requests[1].contains("one-use-token"));
    }

    #[test]
    fn rejects_redirects_and_invalid_cookies() {
        for response in [
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 204 No Content\r\nSet-Cookie: kl_session=invalid\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
        ] {
            let (base, server) = serve(vec![response.to_string()]);
            assert!(DesktopHttp::connect(&base, "token").is_err());
            assert_eq!(server.join().unwrap().len(), 1);
        }
    }

    #[test]
    fn polling_rejects_redirects_malformed_and_oversized_responses() {
        let oversized = "x".repeat(1_048_577);
        for (response, expected) in [
            ("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(), SESSION_EXPIRED),
            ("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(), "approval poll failed"),
            ("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(), "approval poll refused"),
            ("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_string(), "invalid approval response"),
            (format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{oversized}", oversized.len()), "approval response too large"),
        ] {
            let (base, server) = serve(vec![
                "HTTP/1.1 204 No Content\r\nSet-Cookie: kl_session=0123456789abcdef0123456789abcdef; HttpOnly\r\nConnection: close\r\n\r\n".into(), response,
            ]);
            let client = DesktopHttp::connect(&base, "token").unwrap();
            assert_eq!(client.approvals::<Vec<serde_json::Value>>().unwrap_err(), expected);
            assert_eq!(server.join().unwrap().len(), 2);
        }
    }
}
