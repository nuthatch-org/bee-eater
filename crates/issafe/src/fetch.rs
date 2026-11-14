use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use bee_static::Fetch;
use ureq::Agent;
use ureq::http::Uri;

const MAX_BYTES: u64 = 2 * 1024 * 1024;
const MAX_HOPS: usize = 5;
// A lure server expects curl, and may hand anything else a harmless decoy.
const USER_AGENT: &str = "curl/8.7.1";

pub fn fetch(url: &str) -> Fetch {
    match fetch_bytes(url) {
        Ok(bytes) => Fetch::Got {
            url: url.to_string(),
            bytes,
        },
        Err(reason) => Fetch::Failed {
            url: url.to_string(),
            reason,
        },
    }
}

fn fetch_bytes(start: &str) -> Result<Vec<u8>, String> {
    let agent: Agent = Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .max_redirects(0)
        .user_agent(USER_AGENT)
        .http_status_as_error(false)
        .build()
        .into();

    let mut url = start.to_string();
    for _ in 0..=MAX_HOPS {
        let uri: Uri = url.parse().map_err(|_| "not a valid address".to_string())?;
        // Checked per hop because redirects are followed by hand. The resolver runs again
        // inside ureq, so a rebinding DNS server could still slip past this.
        check_public(&uri)?;
        let mut resp = agent
            .get(&url)
            .header("Accept", "*/*")
            .call()
            .map_err(|e| e.to_string())?;
        let status = resp.status();
        if status.is_redirection() {
            let loc = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or("a redirect with no destination")?;
            url = resolve(&uri, loc)?;
            continue;
        }
        if !status.is_success() {
            return Err(format!("the server answered {status}"));
        }
        return resp
            .body_mut()
            .with_config()
            .limit(MAX_BYTES)
            .read_to_vec()
            .map_err(|e| match e {
                ureq::Error::BodyExceedsLimit(_) => "larger than 2 MiB".to_string(),
                e => e.to_string(),
            });
    }
    Err("too many redirects".into())
}

fn check_public(uri: &Uri) -> Result<(), String> {
    let scheme = uri.scheme_str().unwrap_or("");
    let port = match scheme {
        "https" => 443,
        "http" => 80,
        _ => return Err("only http and https addresses are fetched".into()),
    };
    let host = uri.host().ok_or("an address with no host")?;
    let port = uri.port_u16().unwrap_or(port);
    let addrs: Vec<_> = (host.trim_matches(['[', ']']), port)
        .to_socket_addrs()
        .map_err(|_| format!("{host} does not resolve"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("{host} does not resolve"));
    }
    if let Some(a) = addrs.iter().find(|a| !is_public(a.ip())) {
        return Err(format!(
            "{host} points at a private or local address ({}), which is never fetched",
            a.ip()
        ));
    }
    Ok(())
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

fn resolve(base: &Uri, location: &str) -> Result<String, String> {
    let lower = location.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        return Ok(location.to_string());
    }
    let scheme = base.scheme_str().unwrap_or("https");
    if let Some(rest) = location.strip_prefix("//") {
        return Ok(format!("{scheme}://{rest}"));
    }
    if location.starts_with('/') {
        let authority = base
            .authority()
            .ok_or("a redirect from an address with no host")?;
        return Ok(format!("{scheme}://{authority}{location}"));
    }
    Err("a redirect to a relative address, which is not followed".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_and_local_addresses_are_not_public() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.5.1",
            "172.16.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        assert!(is_public("93.184.216.34".parse().unwrap()));
        assert!(is_public("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn local_hosts_are_refused_before_any_request() {
        let uri: Uri = "http://127.0.0.1:8080/x".parse().unwrap();
        assert!(check_public(&uri).unwrap_err().contains("private or local"));
        let uri: Uri = "ftp://example.com/x".parse().unwrap();
        assert!(check_public(&uri).is_err());
    }

    #[test]
    fn redirects_resolve_against_the_hop() {
        let base: Uri = "https://a.invalid/one/two".parse().unwrap();
        assert_eq!(resolve(&base, "/three").unwrap(), "https://a.invalid/three");
        assert_eq!(
            resolve(&base, "//b.invalid/x").unwrap(),
            "https://b.invalid/x"
        );
        assert_eq!(
            resolve(&base, "http://c.invalid/").unwrap(),
            "http://c.invalid/"
        );
        assert!(resolve(&base, "three").is_err());
    }
}
