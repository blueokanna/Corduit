//! Bounded HTTP latency measurement over a connected TCP tunnel.
//! Transport setup, TLS and the response share one wall-clock budget.
use crate::common::stream::{BoxStream, SyncStream};
use crate::engine::error::{Error, Result};
use courierust::courierust_error::Error as IoError;
use courierust::courierust_h1 as h1;
use courierust::courierust_http::uri::Url;
use courierust::courierust_io::{BufReader, Read as CRead, Write as CWrite};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const MAX_STATUS_LINE: usize = 8192;

pub(crate) struct HttpProbe {
    pub url: Url,
    start: Instant,
    deadline: Instant,
}

impl HttpProbe {
    pub fn new(url: &str, timeout: Duration) -> Result<Self> {
        // Reject whitespace before interpolation into an HTTP request.
        if url.len() > MAX_STATUS_LINE || url.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(Error::config("Invalid HTTP probe URL"));
        }
        let url = Url::parse(url).map_err(|e| Error::config(format!("Invalid test URL: {e}")))?;
        if url.userinfo.is_some() {
            return Err(Error::config("Probe URLs must not contain credentials"));
        }
        let start = Instant::now();
        let deadline = start
            .checked_add(timeout)
            .filter(|_| !timeout.is_zero())
            .ok_or_else(|| Error::config("Invalid probe timeout"))?;
        Ok(Self {
            url,
            start,
            deadline,
        })
    }

    pub fn remaining(&self) -> Result<Duration> {
        remaining(self.deadline).map_err(Error::from)
    }

    pub fn transport<'a>(&self, tcp: &'a TcpStream) -> DeadlineSocket<'a> {
        DeadlineSocket {
            tcp,
            deadline: self.deadline,
        }
    }

    pub fn finish(&self, tcp: &TcpStream) -> Result<Duration> {
        self.finish_with(self.transport(tcp))
    }

    /// Encrypted tunnels use the same HTTP/TLS validation as plain TCP.
    pub fn finish_stream(&self, stream: BoxStream) -> Result<Duration> {
        let stream = RefCell::new(stream);
        self.finish_with(ProbeStream(&stream))
    }

    /// Install below the record codec so each framing read shares the probe's
    /// deadline, including partial salts and payloads.
    pub fn bound_stream(&self, inner: BoxStream) -> BoxStream {
        Box::new(DeadlineStream {
            inner,
            deadline: self.deadline,
        })
    }

    fn finish_with<S: CRead + CWrite + Clone>(&self, mut transport: S) -> Result<Duration> {
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.url.path_and_query.as_str(),
            self.url.authority()
        );
        if self.url.scheme == "https" {
            let mut tls = super::http::shared_tls_connector()
                .connect(&self.url.host, transport.clone(), transport)
                .map_err(|e| Error::network(format!("Probe TLS handshake failed: {e}")))?;
            exchange(&mut tls, request.as_bytes())?;
        } else {
            exchange(&mut transport, request.as_bytes())?;
        }
        self.remaining()?;
        Ok(self.start.elapsed())
    }
}

fn exchange<S: CRead + CWrite>(stream: &mut S, request: &[u8]) -> Result<()> {
    CWrite::write_all(stream, request)
        .and_then(|_| CWrite::flush(stream))
        .map_err(|e| Error::network(format!("Probe write failed: {e}")))?;
    let mut reader = BufReader::new(stream, 1024);
    let mut informational = 0;
    let mut remaining_head = 2 * MAX_STATUS_LINE;
    loop {
        let line = reader
            .read_until(b'\n', MAX_STATUS_LINE.min(remaining_head))
            .map_err(|e| Error::network(format!("Probe status read failed: {e}")))?;
        remaining_head = remaining_head.saturating_sub(line.len());
        let line = line
            .strip_suffix(b"\r\n")
            .ok_or_else(|| Error::protocol("Incomplete HTTP probe status line"))?;
        let (status, _) = h1::parse_status_line(line)
            .map_err(|e| Error::protocol(format!("Invalid probe status: {e}")))?;
        if status.is_informational() {
            informational += 1;
            if status.as_u16() == 101 || informational > 8 {
                return Err(Error::protocol("Unexpected HTTP probe protocol transition"));
            }
            // 103 Early Hints and other interim responses precede the final
            // response. Discard their headers within one cumulative bound.
            loop {
                let header = reader
                    .read_until(b'\n', MAX_STATUS_LINE.min(remaining_head))
                    .map_err(|e| Error::protocol(format!("Invalid interim probe head: {e}")))?;
                remaining_head = remaining_head.saturating_sub(header.len());
                if header == b"\r\n" {
                    break;
                }
                if !header.ends_with(b"\r\n") || !header.contains(&b':') {
                    return Err(Error::protocol("Malformed interim probe header"));
                }
            }
            continue;
        }
        if !(200..400).contains(&status.as_u16()) {
            return Err(Error::network(format!(
                "Probe returned HTTP {}",
                status.as_u16()
            )));
        }
        break;
    }
    Ok(())
}

fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "probe deadline exceeded"))
}

/// Re-arm each blocking operation with the remaining budget. An upstream
/// trickling one byte per timeout cannot extend a probe indefinitely.
#[derive(Clone)]
pub(crate) struct DeadlineSocket<'a> {
    tcp: &'a TcpStream,
    deadline: Instant,
}

#[derive(Clone, Copy)]
struct ProbeStream<'a>(&'a RefCell<BoxStream>);

impl CRead for ProbeStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, IoError> {
        self.0.borrow_mut().read(buf).map_err(IoError::from)
    }
}

impl CWrite for ProbeStream<'_> {
    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, IoError> {
        self.0.borrow_mut().write(buf).map_err(IoError::from)
    }
    fn flush(&mut self) -> std::result::Result<(), IoError> {
        self.0.borrow_mut().flush().map_err(IoError::from)
    }
}

struct DeadlineStream {
    inner: BoxStream,
    deadline: Instant,
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        self.inner.read(buf)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.inner.flush()
    }
}

impl SyncStream for DeadlineStream {
    fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        self.inner.shutdown(how)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }
}

impl Read for DeadlineSocket<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.tcp.set_read_timeout(Some(remaining(self.deadline)?))?;
        Read::read(&mut self.tcp, buf)
    }
}
impl Write for DeadlineSocket<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tcp
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        Write::write(&mut self.tcp, buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Write::flush(&mut self.tcp)
    }
}
impl CRead for DeadlineSocket<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, IoError> {
        Read::read(self, buf).map_err(IoError::from)
    }
}
impl CWrite for DeadlineSocket<'_> {
    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, IoError> {
        Write::write(self, buf).map_err(IoError::from)
    }
    fn flush(&mut self) -> std::result::Result<(), IoError> {
        Write::flush(self).map_err(IoError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use courierust::courierust_io::SliceReader;
    use std::net::TcpListener;

    struct Wire {
        input: SliceReader<'static>,
        output: Vec<u8>,
    }
    impl CRead for Wire {
        fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, IoError> {
            self.input.read(buf)
        }
    }
    impl CWrite for Wire {
        fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, IoError> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::result::Result<(), IoError> {
            Ok(())
        }
    }

    #[test]
    fn interim_responses_need_a_final_status_and_have_a_shared_bound() {
        let mut wire = Wire {
            input: SliceReader::new(
                b"HTTP/1.1 103 Early Hints\r\nLink: </asset>\r\n\r\nHTTP/1.1 204 No Content\r\n",
            ),
            output: Vec::new(),
        };
        assert!(exchange(&mut wire, b"GET / HTTP/1.1\r\n\r\n").is_ok());
        let mut upgrade = Wire {
            input: SliceReader::new(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"),
            output: Vec::new(),
        };
        assert!(exchange(&mut upgrade, b"GET / HTTP/1.1\r\n\r\n").is_err());
        struct EndlessHints {
            offset: usize,
        }
        impl CRead for EndlessHints {
            fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, IoError> {
                let hint = b"HTTP/1.1 103 Early Hints\r\n\r\n";
                for b in buf.iter_mut() {
                    *b = hint[self.offset % hint.len()];
                    self.offset += 1;
                }
                Ok(buf.len())
            }
        }
        impl CWrite for EndlessHints {
            fn write(&mut self, b: &[u8]) -> std::result::Result<usize, IoError> {
                Ok(b.len())
            }
            fn flush(&mut self) -> std::result::Result<(), IoError> {
                Ok(())
            }
        }
        assert!(exchange(&mut EndlessHints { offset: 0 }, b"GET / HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn rejects_malformed_failed_and_unbounded_responses() {
        for response in [
            &b"HTTP/not-a-response\r\n"[..],
            &b"HTTP/1.1 200 OK"[..],
            &b"HTTP/1.1 500 Failure\r\n"[..],
            &b"HTTP/1.1 100 Continue\r\n"[..],
        ] {
            let mut wire = Wire {
                input: SliceReader::new(response),
                output: Vec::new(),
            };
            assert!(exchange(&mut wire, b"GET / HTTP/1.1\r\n\r\n").is_err());
        }
        // Infinite peer data must be rejected without waiting for EOF.
        struct Endless;
        impl CRead for Endless {
            fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, IoError> {
                buf.fill(b'x');
                Ok(buf.len())
            }
        }
        impl CWrite for Endless {
            fn write(&mut self, b: &[u8]) -> std::result::Result<usize, IoError> {
                Ok(b.len())
            }
            fn flush(&mut self) -> std::result::Result<(), IoError> {
                Ok(())
            }
        }
        assert!(exchange(&mut Endless, b"GET / HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn preserves_query_and_authority_on_wire() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut data = Vec::new();
            let mut byte = [0];
            while !data.ends_with(b"\r\n\r\n") {
                peer.read_exact(&mut byte).unwrap();
                data.push(byte[0]);
                assert!(data.len() < 4096);
            }
            peer.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
            String::from_utf8(data).unwrap()
        });
        let probe = HttpProbe::new(
            &format!("http://{addr}/check?x=1#ignore"),
            Duration::from_secs(2),
        )
        .unwrap();
        let tcp = TcpStream::connect(addr).unwrap();
        assert!(probe.finish(&tcp).is_ok());
        let request = worker.join().unwrap();
        assert!(request.starts_with("GET /check?x=1 HTTP/1.1\r\n"));
        assert!(request.contains(&format!("Host: {addr}\r\n")));
        assert!(!request.contains("ignore"));
    }

    #[test]
    fn https_never_sends_plaintext_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut first = [0; 3];
            peer.read_exact(&mut first).unwrap();
            first
        });
        let probe = HttpProbe::new(&format!("https://{addr}/"), Duration::from_secs(3)).unwrap();
        let tcp = TcpStream::connect(addr).unwrap();
        assert!(probe.finish(&tcp).is_err());
        assert_eq!(worker.join().unwrap()[..2], [0x16, 0x03]);
    }

    #[test]
    fn rejects_unsafe_urls_and_zero_budget() {
        for url in [
            "ftp://host/",
            "http://user:pass@host/",
            "http://host/a b",
            "http://host/\r\nx:y",
        ] {
            assert!(
                HttpProbe::new(url, Duration::from_secs(1)).is_err(),
                "{url}"
            );
        }
        assert!(HttpProbe::new("http://host/", Duration::ZERO).is_err());
    }

    #[test]
    fn trickle_cannot_extend_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            for _ in 0..50 {
                if peer.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let probe = HttpProbe::new(&format!("http://{addr}/"), Duration::from_millis(150)).unwrap();
        let tcp = TcpStream::connect(addr).unwrap();
        assert!(probe.finish(&tcp).is_err());
        assert!(probe.start.elapsed() < Duration::from_secs(1));
        drop(tcp);
        worker.join().unwrap();
    }
}
