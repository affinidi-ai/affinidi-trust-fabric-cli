//! A host the built `fabric` binary is pointed at, which records every request
//! it gets, headers included, and answers the product probe apart from the
//! command's own requests.

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

/// Request line of the anonymous probe that asks a host which product it is.
pub const PROBE_REQUEST: &str = "GET /api/v1/permissions/public HTTP/1.1";

/// Every request a [`host_answering`] host received, headers included, in order.
pub type Requests = Arc<Mutex<Vec<String>>>;

/// Starts a host that answers a request for the public permission list with
/// `permissions` and any other request with `body`, both as a 200, until the
/// test process ends. Returns its base URL and every request it received.
pub fn host_answering(
    permissions: &'static str,
    body: &'static str,
) -> (String, Requests) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener
        .local_addr()
        .expect("local addr");
    let requests: Requests = Arc::default();
    let recorded = Arc::clone(&requests);
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request
                .windows(4)
                .any(|window| window == b"\r\n\r\n")
            {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&chunk[..read]),
                }
            }
            let request = String::from_utf8_lossy(&request).into_owned();
            let answer = if request.starts_with(PROBE_REQUEST) {
                permissions
            } else {
                body
            };
            recorded
                .lock()
                .expect("recorded requests")
                .push(request);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                answer.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (format!("http://{address}"), requests)
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
