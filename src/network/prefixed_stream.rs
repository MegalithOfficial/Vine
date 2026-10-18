use std::io::{self, Cursor};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

/// An `AsyncRead` wrapper that yields a prefix of bytes before delegating to an underlying stream.
pub struct PrefixedRead<R> {
    prefix: Option<Cursor<Vec<u8>>>,
    inner: R,
}

impl<R> PrefixedRead<R> {
    pub fn new(inner: R, prefix_bytes: Vec<u8>) -> Self {
        let prefix = if prefix_bytes.is_empty() {
            None
        } else {
            Some(Cursor::new(prefix_bytes))
        };
        Self { prefix, inner }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixedRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(prefix) = &mut self.prefix {
            let initial_len = buf.filled().len();
            let n = std::io::Read::read(prefix, buf.initialize_unfilled())?;
            buf.advance(n);

            if prefix.position() >= prefix.get_ref().len() as u64 {
                self.prefix = None;
            }

            if buf.filled().len() > initial_len {
                return Poll::Ready(Ok(()));
            }
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_prefixed_read() {
        let prefix = b"PROXY HEADER ".to_vec();
        let inner = Cursor::new(b"MINECRAFT DATA");
        let mut stream = PrefixedRead::new(inner, prefix);

        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();

        assert_eq!(output, b"PROXY HEADER MINECRAFT DATA");
    }
}
