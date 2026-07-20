use std::io;

use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};

/// Byte counts produced by a completed bidirectional relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayStats {
    inbound_to_outbound: u64,
    outbound_to_inbound: u64,
}

impl RelayStats {
    /// Returns the bytes copied from the inbound stream to the outbound stream.
    pub fn inbound_to_outbound_bytes(&self) -> u64 {
        self.inbound_to_outbound
    }

    /// Returns the bytes copied from the outbound stream to the inbound stream.
    pub fn outbound_to_inbound_bytes(&self) -> u64 {
        self.outbound_to_inbound
    }
}

/// Copies bytes in both directions until both stream directions are closed.
///
/// EOF in one direction is propagated by shutting down the corresponding
/// writer while the reverse direction continues to be relayed.
pub async fn relay_bidirectional<I, O>(inbound: &mut I, outbound: &mut O) -> io::Result<RelayStats>
where
    I: AsyncRead + AsyncWrite + Unpin + ?Sized,
    O: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (inbound_to_outbound, outbound_to_inbound) = copy_bidirectional(inbound, outbound).await?;

    Ok(RelayStats {
        inbound_to_outbound,
        outbound_to_inbound,
    })
}

#[cfg(test)]
mod tests {
    use std::{io, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, duplex},
        time::timeout,
    };

    use super::relay_bidirectional;

    const REQUEST: &[u8] = b"request";
    const RESPONSE: &[u8] = b"response after request EOF";

    #[tokio::test(flavor = "current_thread")]
    async fn preserves_reverse_flow_after_inbound_half_close() {
        let (mut client, mut relay_inbound) = duplex(64);
        let (mut relay_outbound, mut upstream) = duplex(64);

        let exchange = async {
            let relay = relay_bidirectional(&mut relay_inbound, &mut relay_outbound);

            let client_io = async {
                client.write_all(REQUEST).await?;
                client.shutdown().await?;

                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;

                Ok::<_, io::Error>(response)
            };

            let upstream_io = async {
                let mut request = Vec::new();
                upstream.read_to_end(&mut request).await?;

                upstream.write_all(RESPONSE).await?;
                upstream.shutdown().await?;

                Ok::<_, io::Error>(request)
            };

            tokio::join!(relay, client_io, upstream_io)
        };

        let (relay_result, client_result, upstream_result) =
            timeout(Duration::from_secs(5), exchange)
                .await
                .expect("relay exchange should not time out");

        let stats = relay_result.expect("relay should succeed");
        let response = client_result.expect("client I/O should succeed");
        let request = upstream_result.expect("upstream I/O should succeed");

        assert_eq!(request.as_slice(), REQUEST);
        assert_eq!(response.as_slice(), RESPONSE);

        assert_eq!(stats.inbound_to_outbound_bytes(), REQUEST.len() as u64,);
        assert_eq!(stats.outbound_to_inbound_bytes(), RESPONSE.len() as u64,);
    }
}
