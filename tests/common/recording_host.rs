//! A host the built `fabric` binary is pointed at, which records every request
//! it gets, headers and body included, and answers the product probe apart
//! from the command's own requests.

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

/// Request line of the anonymous probe that asks a host which product it is.
pub const PROBE_REQUEST: &str = "GET /api/v1/permissions/public HTTP/1.1";

/// Every request a host received, headers and body included, in order.
pub type Requests = Arc<Mutex<Vec<String>>>;

/// One answer of [`host_replying`]: the method and path it answers, such as
/// `GET /api/v1/users`, then the status, such as `200 OK`, and the body.
pub type Reply = (&'static str, &'static str, &'static str);

/// Starts a host that answers a request for the public permission list with
/// `permissions` and any other request with `body`, both as a 200, until the
/// test process ends. Returns its base URL and every request it received.
pub fn host_answering(
    permissions: &'static str,
    body: &'static str,
) -> (String, Requests) {
    let probe = PROBE_REQUEST.trim_end_matches(" HTTP/1.1");
    host_replying(vec![(probe, "200 OK", permissions)], ("200 OK", body))
}

/// Starts a host that answers each request with the first of `replies` whose
/// method and path start its request line, and with `otherwise`, a status and
/// a body, when none does, until the test process ends. Returns its base URL
/// and every request it received.
pub fn host_replying(
    replies: Vec<Reply>,
    otherwise: (&'static str, &'static str),
) -> (String, Requests) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener
        .local_addr()
        .expect("local addr");
    let requests: Requests = Arc::default();
    let recorded = Arc::clone(&requests);
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let request = read_request(&mut stream);
            let (status, answer) = replies
                .iter()
                .find(|(start, _, _)| request.starts_with(&format!("{start} ")))
                .map_or(otherwise, |(_, status, body)| (*status, *body));
            recorded
                .lock()
                .expect("recorded requests")
                .push(request);
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                answer.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (format!("http://{address}"), requests)
}

/// Reads one request from `stream`: its head, then as much body as its
/// `Content-Length` names.
fn read_request(stream: &mut impl Read) -> String {
    let mut request = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream
            .read(&mut chunk)
            .unwrap_or(0);
        request.extend_from_slice(&chunk[..read]);
        let text = String::from_utf8_lossy(&request);
        let complete = text
            .split_once("\r\n\r\n")
            .is_some_and(|(head, body)| body.len() >= content_length(head));
        if read == 0 || complete {
            break;
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

/// The `Content-Length` a request `head` names, or 0 when it names none.
fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0)
}

/// The request line of every request in `requests`, in order.
pub fn request_lines(requests: &Requests) -> Vec<String> {
    requests
        .lock()
        .expect("recorded requests")
        .iter()
        .map(|request| {
            request
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

/// Request `index` of `requests` in lower case, headers included, so a test
/// can look for a header whatever its case.
pub fn request_lowercase(
    requests: &Requests,
    index: usize,
) -> String {
    requests
        .lock()
        .expect("recorded requests")[index]
        .to_ascii_lowercase()
}
