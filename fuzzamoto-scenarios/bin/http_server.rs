use fuzzamoto::{
    fuzzamoto_main,
    runners::Runner,
    scenarios::{Scenario, ScenarioInput, ScenarioResult},
    targets::{BitcoinCoreTarget, TargetNode},
};

use arbitrary::{Arbitrary, Unstructured};
use std::fmt;
use std::io::Write;

use std::net::TcpStream;

#[derive(Arbitrary, Clone, Copy)]
enum Method {
    Get,
    Post,
    Put,
    Delete,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
        }
    }

    fn can_have_body(self) -> bool {
        // maybe cover delete?
        matches!(self, Method::Post | Method::Put)
    }
}

#[derive(Arbitrary)]
struct Path<'a> {
    raw: &'a [u8],
}

impl fmt::Display for Path<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MAX_LEN: usize = 128;

        // Ensure it starts with '/'
        write!(f, "/")?;

        for &b in self.raw.iter().take(MAX_LEN) {
            match b {
                // "unreserved" + a few common URL delimiters
                b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'-'
                | b'_'
                | b'.'
                | b'~'
                | b'/'
                | b'?'
                | b'&'
                | b'='
                | b'%'
                | b'+'
                | b':' => {
                    // Avoid introducing request-line breaking whitespace/control chars
                    write!(f, "{}", b as char)?;
                }
                // Explicitly disallow spaces and controls (including \r, \n, \t)
                0x00..=0x20 | 0x7f..=0xff => {
                    // Percent-encode to keep it URL-like without breaking the request
                    write!(
                        f,
                        "%{}{}",
                        nibble_to_hex((b >> 4) & 0xF),
                        nibble_to_hex(b & 0xF)
                    )?;
                }
                _ => {
                    write!(
                        f,
                        "%{}{}",
                        nibble_to_hex((b >> 4) & 0xF),
                        nibble_to_hex(b & 0xF)
                    )?;
                }
            }
        }

        Ok(())
    }
}

fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'A' + (n - 10)) as char,
        _ => '0',
    }
}

struct HttpMessage<'a> {
    is_chaos: bool,
    method: Method,
    path: Path<'a>,
    body: &'a [u8],
    chaos_data: &'a [u8],
}

impl<'a> Arbitrary<'a> for HttpMessage<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let is_chaos: bool = Arbitrary::arbitrary(u)?;

        Ok(HttpMessage {
            is_chaos,
            method: Arbitrary::arbitrary(u)?,
            path: Arbitrary::arbitrary(u)?,
            body: Arbitrary::arbitrary(u)?,
            chaos_data: Arbitrary::arbitrary(u)?,
        })
    }
}

fn build_request(msg: &HttpMessage<'_>) -> Vec<u8> {
    if msg.is_chaos {
        const MAX_CHAOS: usize = 8 * 1024;
        if msg.chaos_data.len() > MAX_CHAOS {
            msg.chaos_data[..MAX_CHAOS].to_vec()
        } else {
            msg.chaos_data.to_vec()
        }
    } else {
        build_wellformed_request(msg.method, &msg.path, msg.body)
    }
}

fn build_wellformed_request(method: Method, path: &Path<'_>, body: &[u8]) -> Vec<u8> {
    const MAX_BODY: usize = 8 * 1024;
    let body = if body.len() > MAX_BODY {
        &body[..MAX_BODY]
    } else {
        body
    };

    let mut req = Vec::with_capacity(256 + body.len());

    let _ = write!(
        req,
        "{} {} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: keep-alive\r\n",
        method.as_str(),
        path,
    );

    if method.can_have_body() {
        let _ = write!(
            req,
            "Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n",
            body.len()
        );
        req.extend_from_slice(body);
    } else {
        req.extend_from_slice(b"\r\n");
    }

    req
}

#[derive(Arbitrary)]
enum Action<'a> {
    Connect,
    SendMessage {
        connection_id: u8,
        message: HttpMessage<'a>,
    },
    Disconnect {
        connection_id: u8,
    },
}

#[derive(Arbitrary)]
struct TestCase<'a> {
    actions: Vec<Action<'a>>,
}

impl<'a> ScenarioInput<'a> for TestCase<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        let mut unstructured = Unstructured::new(bytes);
        let actions = Vec::arbitrary(&mut unstructured).map_err(|e| e.to_string())?;
        Ok(Self { actions })
    }
}

/// `HttpServerScenario` is a scenario that tests the HTTP server of Bitcoin Core.
///
/// Testcases simulate the processing of a series of actions by the HTTP server of Bitcoin Core.
/// Each testcase represents a series of three types of actions:
///
/// 1. Connect to the HTTP server
/// 2. Send a message to the HTTP server from a specific connection
/// 3. Disconnect one of the existing connections
struct HttpServerScenario {
    target: BitcoinCoreTarget,
}

impl<'a> Scenario<'a, TestCase<'a>> for HttpServerScenario {
    fn new(args: &[String]) -> Result<Self, String> {
        Ok(Self {
            target: BitcoinCoreTarget::from_path(&args[1])?,
        })
    }

    fn run(&mut self, input: TestCase, _runner: &dyn Runner) -> ScenarioResult {
        // Network actions are slow; limit them
        const MAX_ACTIONS: usize = 128;
        if input.actions.len() > MAX_ACTIONS {
            return ScenarioResult::Ok;
        }

        let mut connections = Vec::with_capacity(MAX_ACTIONS);
        for action in input.actions {
            match action {
                Action::Connect => {
                    let Ok(stream) = TcpStream::connect(self.target.node.params.rpc_socket) else {
                        return ScenarioResult::Fail("Failed to connect to the target".to_string());
                    };
                    let _ = stream.set_nodelay(true);
                    connections.push(stream);
                }
                Action::SendMessage {
                    connection_id,
                    message,
                } => {
                    if connections.is_empty() {
                        continue;
                    }
                    let index = connection_id as usize % connections.len();
                    let connection = connections.get_mut(index).unwrap();
                    let req = build_request(&message);
                    let _ = connection.write_all(&req);
                    let _ = connection.flush();
                }
                Action::Disconnect { connection_id } => {
                    if connections.is_empty() {
                        continue;
                    }
                    let index = connection_id as usize % connections.len();
                    let _ = connections.swap_remove(index);
                }
            }
        }

        if let Err(e) = self.target.is_alive() {
            return ScenarioResult::Fail(format!("Target is not alive: {e}"));
        }

        ScenarioResult::Ok
    }
}

fuzzamoto_main!(HttpServerScenario, TestCase);
