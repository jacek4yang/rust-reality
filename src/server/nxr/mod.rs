use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{self, Instant},
};
use zeroize::Zeroizing;

use crate::{
    config::node::landing::NxrLandingConfig,
    network::NetworkEnvironment,
    protocol::{
        nxr::{
            FLAG_TCP, FLAG_UDP, NxrKey, NxrProtocolError, REQUEST_HEADER_LEN, peek_open_flags,
            request_len_from_header,
        },
        nxr_udp::{
            DIR_LANDING_TO_LINE, DIR_LINE_TO_LANDING, FRAME_TYPE_CLOSE, FRAME_TYPE_DATAGRAM,
            NXR_UDP_MAX_PAYLOAD, NxrUdpError, NxrUdpSeq, NxrUdpSessionKey, drain_frames,
            encode_frame, udp_open_len_from_header,
        },
        vless::{Address, Destination},
    },
    transport::{RelayContext, relay::RelayStats, tcp_relay::TcpRelay},
};

use crate::runtime::{PressureGauge, ResourceGovernor};

use super::{
    connector::{DestinationConnectError, DestinationConnector},
    pre_auth::{PreAuthGeneration, begin_authentication},
};
use crate::config::node::network::NetworkConfig;
use crate::runtime::policy::ResourceGovernorPolicy;

mod auth;
mod error;
mod replay;

pub use auth::NxrAuthenticator;
pub use replay::NxrReplayCache;
pub(crate) use replay::{REPLAY_NONCE_CAPACITY, replay_retention_seconds};

pub use error::{NxrAuthenticationError, NxrLandingConfigError, NxrLandingError, NxrReplayError};

/// One NXR landing connection: authenticate once, connect once, then relay raw
/// bytes with normal TCP half-close semantics.
#[derive(Clone)]
pub struct NxrLandingHandler {
    authenticator: NxrAuthenticator,
    connector: DestinationConnector,
    pre_auth_idle_timeout: Duration,
    authentication_timeout: Duration,
    governor: ResourceGovernor,
    pressure: PressureGauge,
    generation: PreAuthGeneration,
    relay: TcpRelay,
    /// Pending-write stall bound. Quiet reads retain normal TCP lifetime.
    write_stall: Duration,
}

impl NxrLandingHandler {
    /// Compiles one validated listener while retaining its process-lifetime
    /// replay history across immutable runtime generations.
    ///
    /// # Errors
    ///
    /// Rejects malformed or incorrectly sized PSK material.
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per immutable landing policy and process authority"
    )]
    pub(crate) fn from_landing_with_replay(
        inbound: &NxrLandingConfig,
        replay: NxrReplayCache,
        relay: TcpRelay,
        write_stall: Duration,
        network: &NetworkConfig,
        network_environment: NetworkEnvironment,
        governor: ResourceGovernor,
        pressure: PressureGauge,
        generation: PreAuthGeneration,
    ) -> Result<Self, NxrLandingConfigError> {
        let decoded = Zeroizing::new(
            BASE64_URL_SAFE_NO_PAD
                .decode(inbound.psk.expose())
                .map_err(|_| NxrLandingConfigError::Key)?,
        );
        let key: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| NxrLandingConfigError::Key)?;
        let mut handler = Self::new(
            NxrAuthenticator::new(
                NxrKey::new(key),
                replay,
                inbound.timing().max_time_difference_seconds,
            ),
            Duration::from_millis(inbound.timing().connect_timeout_ms),
            Duration::from_millis(inbound.timing().authentication_timeout_ms),
            relay,
            write_stall,
        );
        handler.pre_auth_idle_timeout =
            Duration::from_millis(inbound.timing().pre_auth_idle_timeout_ms);
        handler.governor = governor;
        handler.pressure = pressure;
        handler.generation = generation;
        handler.connector = DestinationConnector::with_environment(
            Duration::from_millis(inbound.timing().connect_timeout_ms),
            *network,
            network_environment,
        );
        Ok(handler)
    }

    /// Creates a landing handler from already compiled policy.
    #[must_use]
    pub fn new(
        authenticator: NxrAuthenticator,
        connect_timeout: Duration,
        authentication_timeout: Duration,
        relay: TcpRelay,
        write_stall: Duration,
    ) -> Self {
        let governor = ResourceGovernor::new(&ResourceGovernorPolicy::default());
        Self {
            authenticator,
            connector: DestinationConnector::new(connect_timeout),
            pre_auth_idle_timeout: Duration::from_secs(60),
            authentication_timeout,
            governor,
            pressure: PressureGauge::new(),
            generation: PreAuthGeneration::default(),
            relay,
            write_stall,
        }
    }

    /// Processes a single NXR TCP connection. Authentication failures return
    /// without writing a response and occur before destination DNS or connect.
    ///
    /// # Errors
    ///
    /// Returns bounded request-read, clock, authentication, destination, or relay
    /// errors. Callers must silently close on every error.
    pub async fn handle(&self, mut inbound: TcpStream) -> Result<RelayStats, NxrLandingError> {
        let authentication = begin_authentication(
            &mut inbound,
            self.pre_auth_idle_timeout,
            self.authentication_timeout,
            &self.governor,
            &self.pressure,
            &self.generation,
        )
        .await
        .map_err(NxrLandingError::from_pre_auth)?;
        let request = read_request_after_first(
            &mut inbound,
            authentication.first_byte,
            authentication.deadline,
        )
        .await?;
        let now = unix_seconds()?;
        let flags = request
            .get(..REQUEST_HEADER_LEN)
            .and_then(peek_open_flags)
            .ok_or(NxrLandingError::Protocol(NxrProtocolError::Version))?;
        match flags {
            FLAG_TCP => {
                let destination = self.authenticator.authenticate(&request, now)?;
                drop(authentication);
                self.handle_tcp_relay(inbound, destination).await
            }
            FLAG_UDP => {
                let (open, session) = self.authenticator.authenticate_udp(&request, now)?;
                drop(authentication);
                self.handle_udp_association(inbound, open.destination().clone(), session)
                    .await
            }
            _ => Err(NxrLandingError::Protocol(NxrProtocolError::Flags)),
        }
    }

    async fn handle_tcp_relay(
        &self,
        inbound: TcpStream,
        destination: Destination,
    ) -> Result<RelayStats, NxrLandingError> {
        // The descriptor unit is reserved before connect(2) and outlives the
        // relay: the outbound socket closes before its unit is released.
        let connected = self
            .connector
            .connect_resolved_accounted(&destination, &[], self.relay.fd_budget())
            .await
            .map_err(|error| match error {
                DestinationConnectError::DescriptorBudget => NxrLandingError::DescriptorBudget,
                error => NxrLandingError::Destination(error),
            })?;
        let (outbound, _fd_permit) = connected.into_parts();
        let outcome = self
            .relay
            .relay_owned(
                inbound,
                outbound,
                RelayContext::owned().with_write_stall(self.write_stall),
            )
            .await
            .map_err(NxrLandingError::Relay)?;
        Ok(RelayStats::new(
            outcome.inbound_to_outbound(),
            outcome.outbound_to_inbound(),
        ))
    }

    /// Authenticated NXR UDP association: framed datagrams on `inbound`, UDP
    /// sockets owned here. Destination changes are accepted only when covered
    /// by the session MAC (LINE is routing authority).
    async fn handle_udp_association(
        &self,
        mut inbound: TcpStream,
        initial_destination: Destination,
        session: NxrUdpSessionKey,
    ) -> Result<RelayStats, NxrLandingError> {
        let mut current = socket_addr_for_udp(&initial_destination)?;
        // Bind the UDP socket to the same local IP the NXR TCP listener accepted
        // on so echo peers observe LANDING's address (not LINE's) on loopback
        // multi-address topologies (e.g. LANDING on 127.0.0.2).
        let bind = inbound
            .local_addr()
            .map(|addr| std::net::SocketAddr::new(addr.ip(), 0))
            .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
        let udp = UdpSocket::bind(bind)
            .await
            .map_err(NxrLandingError::UdpIo)?;
        // Charge one outbound FD unit for the UDP socket for the association life.
        let _udp_permit = self
            .relay
            .fd_budget()
            .try_acquire(crate::transport::UNITS_OUTBOUND_SOCKET)
            .ok_or(NxrLandingError::DescriptorBudget)?;

        let mut inbound_buf = Vec::new();
        let mut udp_buf = vec![0_u8; 64 * 1024];
        let mut frame_out = Vec::new();
        let mut seq_in = NxrUdpSeq::new();
        let mut seq_out = NxrUdpSeq::new();
        let mut uplink = 0_u64;
        let mut downlink = 0_u64;
        let idle = Duration::from_secs(60);

        loop {
            tokio::select! {
                biased;
                read = inbound.read_buf(&mut inbound_buf) => {
                    let n = read.map_err(NxrLandingError::Read)?;
                    if n == 0 {
                        break;
                    }
                    if inbound_buf.len() > MAX_FRAME_BUFFER {
                        return Err(NxrLandingError::UdpProtocol(NxrUdpError::Length));
                    }
                    let frames = drain_frames(
                        &mut inbound_buf,
                        &session,
                        DIR_LINE_TO_LANDING,
                    )
                    .map_err(NxrLandingError::UdpProtocol)?;
                    for frame in frames {
                        seq_in.accept_in(frame.seq).map_err(NxrLandingError::UdpProtocol)?;
                        if frame.frame_type == FRAME_TYPE_CLOSE {
                            return Ok(RelayStats::new(uplink, downlink));
                        }
                        if frame.frame_type != FRAME_TYPE_DATAGRAM {
                            return Err(NxrLandingError::UdpProtocol(NxrUdpError::FrameType));
                        }
                        if let Some(dest) = frame.destination.as_ref() {
                            current = socket_addr_for_udp(dest)?;
                        }
                        if frame.payload.len() > NXR_UDP_MAX_PAYLOAD {
                            return Err(NxrLandingError::UdpProtocol(NxrUdpError::Payload));
                        }
                        if !frame.payload.is_empty() {
                            udp.send_to(&frame.payload, current)
                                .await
                                .map_err(NxrLandingError::UdpIo)?;
                            uplink = uplink.saturating_add(frame.payload.len() as u64);
                        }
                    }
                }
                recv = udp.recv_from(&mut udp_buf) => {
                    let (n, from) = recv.map_err(NxrLandingError::UdpIo)?;
                    let source = Destination::from(from);
                    if n > NXR_UDP_MAX_PAYLOAD {
                        return Err(NxrLandingError::UdpProtocol(NxrUdpError::Payload));
                    }
                    let payload = &udp_buf[..n];
                    let seq = seq_out.next_out().map_err(NxrLandingError::UdpProtocol)?;
                    encode_frame(
                        &session,
                        DIR_LANDING_TO_LINE,
                        FRAME_TYPE_DATAGRAM,
                        seq,
                        Some(&source),
                        payload,
                        &mut frame_out,
                    )
                    .map_err(NxrLandingError::UdpProtocol)?;
                    inbound
                        .write_all(&frame_out)
                        .await
                        .map_err(NxrLandingError::UdpIo)?;
                    downlink = downlink.saturating_add(payload.len() as u64);
                }
                () = tokio::time::sleep(idle) => {
                    break;
                }
            }
        }
        Ok(RelayStats::new(uplink, downlink))
    }
}

/// Bound on unreassembled TCP buffer bytes for NXR UDP framing.
const MAX_FRAME_BUFFER: usize = 256 * 1024;

fn socket_addr_for_udp(destination: &Destination) -> Result<std::net::SocketAddr, NxrLandingError> {
    match destination.address() {
        Address::Ipv4(addr) => Ok(std::net::SocketAddr::from((*addr, destination.port()))),
        Address::Ipv6(addr) => Ok(std::net::SocketAddr::from((*addr, destination.port()))),
        Address::Domain(_) => Err(NxrLandingError::UdpProtocol(NxrUdpError::Address)),
    }
}

async fn read_request_after_first(
    stream: &mut TcpStream,
    first_byte: u8,
    deadline: Instant,
) -> Result<Vec<u8>, NxrLandingError> {
    let mut header = [0_u8; REQUEST_HEADER_LEN];
    header[0] = first_byte;
    read_exact_before(stream, &mut header[1..], deadline).await?;
    let total = match peek_open_flags(&header) {
        Some(FLAG_UDP) => udp_open_len_from_header(&header)
            .map_err(|error| NxrLandingError::Protocol(NxrProtocolError::from(error)))?,
        _ => request_len_from_header(&header).map_err(NxrLandingError::Protocol)?,
    };
    let mut request = Vec::new();
    request
        .try_reserve_exact(total)
        .map_err(|_| NxrLandingError::Allocation)?;
    request.extend_from_slice(&header);
    request.resize(total, 0);
    read_exact_before(stream, &mut request[REQUEST_HEADER_LEN..], deadline).await?;
    Ok(request)
}

async fn read_exact_before(
    stream: &mut TcpStream,
    output: &mut [u8],
    deadline: Instant,
) -> Result<(), NxrLandingError> {
    time::timeout_at(deadline, stream.read_exact(output))
        .await
        .map_err(|_| NxrLandingError::Timeout)?
        .map(|_| ())
        .map_err(NxrLandingError::Read)
}

fn unix_seconds() -> Result<u64, NxrLandingError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| NxrLandingError::Clock)
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time,
    };

    use super::{NxrAuthenticator, NxrLandingHandler, NxrReplayCache, NxrReplayError};
    use crate::{
        protocol::{
            nxr::{NxrKey, encode_request},
            vless::{Address, Destination},
        },
        transport::tcp_relay::{TcpRelay, TcpRelayConfig},
    };

    #[test]
    fn replay_cache_is_bounded_and_expires_monotonically() {
        let cache =
            NxrReplayCache::new(1, Duration::from_millis(100)).expect("cache policy must compile");
        let now = std::time::Instant::now();
        cache
            .reserve_at([1; 16], now)
            .expect("first nonce must reserve");
        assert_eq!(
            cache.reserve_at([1; 16], now),
            Err(NxrReplayError::Duplicate)
        );
        assert_eq!(
            cache.reserve_at([2; 16], now),
            Err(NxrReplayError::Capacity)
        );
        cache
            .reserve_at([2; 16], now + Duration::from_millis(101))
            .expect("expired nonce must release capacity");
        assert_eq!(cache.entry_count(), 1);
    }

    #[test]
    fn authenticator_rejects_nonce_reuse_before_returning_destination() {
        let key = NxrKey::new([0x11; 32]);
        let cache =
            NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
        let authenticator = NxrAuthenticator::new(key.clone(), cache, 5);
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);
        let mut request = Vec::new();
        encode_request(&destination, 100, [0x22; 16], &key, &mut request)
            .expect("request must encode");

        assert_eq!(
            authenticator
                .authenticate(&request, 100)
                .expect("first request must authenticate"),
            destination
        );
        assert!(authenticator.authenticate(&request, 100).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn first_byte_enters_short_deadline_without_reserving_replay() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("landing must bind");
        let address = listener.local_addr().expect("landing address");
        let cache =
            NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
        let mut handler = NxrLandingHandler::new(
            NxrAuthenticator::new(NxrKey::new([0x33; 32]), cache.clone(), 5),
            Duration::from_secs(1),
            Duration::from_secs(1),
            TcpRelay::new(
                TcpRelayConfig::for_test(),
                crate::transport::FdBudget::new(4_096),
            )
            .expect("relay policy must compile"),
            Duration::from_secs(1),
        );
        handler.pre_auth_idle_timeout = Duration::from_secs(60);
        let client = TcpStream::connect(address);
        let accepted = listener.accept();
        let (client, accepted) = tokio::join!(client, accepted);
        let mut client = client.expect("client must connect");
        let (server, _) = accepted.expect("landing must accept");
        let task = tokio::spawn(async move { handler.handle(server).await });

        client.write_all(b"N").await.expect("first byte");
        tokio::task::yield_now().await;
        time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            task.await.expect("handler must join"),
            Err(super::NxrLandingError::Timeout)
        ));
        assert_eq!(cache.entry_count(), 0, "slowloris must reserve no nonce");
    }

    #[tokio::test(start_paused = true)]
    async fn valid_nxr_authenticates_across_the_pre_auth_idle_age_matrix() {
        let key = NxrKey::new([0x34; 32]);
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9);
        for (index, idle_age) in [0, 1, 5, 15, 30, 59].into_iter().enumerate() {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("landing must bind");
            let address = listener.local_addr().expect("landing address");
            let cache =
                NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
            let handler = NxrLandingHandler::new(
                NxrAuthenticator::new(key.clone(), cache, 5),
                Duration::from_secs(1),
                Duration::from_secs(1),
                TcpRelay::new(
                    TcpRelayConfig::for_test(),
                    crate::transport::FdBudget::new(4_096),
                )
                .expect("relay policy must compile"),
                Duration::from_secs(1),
            );
            let client = TcpStream::connect(address);
            let accepted = listener.accept();
            let (client, accepted) = tokio::join!(client, accepted);
            let mut client = client.expect("client must connect");
            let (server, _) = accepted.expect("landing must accept");
            let mut nonce = [0x45; 16];
            nonce[0] = u8::try_from(index).expect("small matrix index");
            let mut request = Vec::new();
            encode_request(
                &destination,
                super::unix_seconds().expect("clock must be valid"),
                nonce,
                &key,
                &mut request,
            )
            .expect("request must encode");
            let task = tokio::spawn(async move { handler.handle(server).await });
            tokio::task::yield_now().await;
            time::advance(Duration::from_secs(idle_age)).await;
            assert!(
                !task.is_finished(),
                "valid NXR idle age {idle_age}s must remain accepted"
            );
            client.write_all(&request).await.expect("request write");
            assert!(matches!(
                task.await.expect("handler must join"),
                Err(super::NxrLandingError::Destination(_))
            ));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unused_nxr_socket_expires_without_replay_state() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("landing must bind");
        let address = listener.local_addr().expect("landing address");
        let cache =
            NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
        let mut handler = NxrLandingHandler::new(
            NxrAuthenticator::new(NxrKey::new([0x36; 32]), cache.clone(), 5),
            Duration::from_secs(1),
            Duration::from_secs(1),
            TcpRelay::new(
                TcpRelayConfig::for_test(),
                crate::transport::FdBudget::new(4_096),
            )
            .expect("relay policy must compile"),
            Duration::from_secs(1),
        );
        handler.pre_auth_idle_timeout = Duration::from_secs(60);
        let client = TcpStream::connect(address);
        let accepted = listener.accept();
        let (_client, accepted) = tokio::join!(client, accepted);
        let (server, _) = accepted.expect("landing must accept");
        let task = tokio::spawn(async move { handler.handle(server).await });
        tokio::task::yield_now().await;
        time::advance(Duration::from_secs(60)).await;
        assert!(matches!(
            task.await.expect("handler must join"),
            Err(super::NxrLandingError::Timeout)
        ));
        assert_eq!(cache.entry_count(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn replay_is_rejected_on_preestablished_nxr_sockets() {
        let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("landing must bind");
        let landing_address = landing_listener.local_addr().expect("landing address");
        let key = NxrKey::new([0x35; 32]);
        let cache =
            NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
        let handler = NxrLandingHandler::new(
            NxrAuthenticator::new(key.clone(), cache, 5),
            Duration::from_secs(1),
            Duration::from_secs(1),
            TcpRelay::new(
                TcpRelayConfig::for_test(),
                crate::transport::FdBudget::new(4_096),
            )
            .expect("relay policy must compile"),
            Duration::from_secs(1),
        );
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9);
        let mut request = Vec::new();
        encode_request(
            &destination,
            super::unix_seconds().expect("clock must be valid"),
            [0x47; 16],
            &key,
            &mut request,
        )
        .expect("request must encode");

        let landing = async {
            let (first, _) = landing_listener.accept().await?;
            let (second, _) = landing_listener.accept().await?;
            let first_handler = handler.clone();
            let (first, second) = tokio::join!(first_handler.handle(first), handler.handle(second));
            Ok::<_, io::Error>([first, second])
        };
        let line = async {
            let mut streams = [
                TcpStream::connect(landing_address).await?,
                TcpStream::connect(landing_address).await?,
            ];
            tokio::task::yield_now().await;
            for stream in &mut streams {
                stream.write_all(&request).await?;
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await?;
                assert!(response.is_empty(), "rejections stay silent");
            }
            Ok::<_, io::Error>(())
        };
        let (landing, line) = time::timeout(Duration::from_secs(3), async {
            tokio::join!(landing, line)
        })
        .await
        .expect("replay test must not stall");
        line.expect("line exchange must succeed");
        let outcomes = landing.expect("landing exchange must succeed");
        assert!(matches!(
            outcomes[0],
            Err(super::NxrLandingError::Destination(_))
        ));
        assert!(matches!(
            outcomes[1],
            Err(super::NxrLandingError::Authentication(
                super::NxrAuthenticationError::Replay(super::NxrReplayError::Duplicate)
            ))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn landing_relays_raw_payload_and_preserves_half_close() {
        const REQUEST: &[u8] = b"request after auth";
        const RESPONSE: &[u8] = b"response after half-close";

        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("target must bind");
        let target_address = target_listener.local_addr().expect("target address");
        let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("landing must bind");
        let landing_address = landing_listener.local_addr().expect("landing address");
        let key = NxrKey::new([0x33; 32]);
        let cache =
            NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
        let handler = NxrLandingHandler::new(
            NxrAuthenticator::new(key.clone(), cache, 5),
            Duration::from_secs(1),
            Duration::from_secs(1),
            TcpRelay::new(
                TcpRelayConfig::for_test(),
                crate::transport::FdBudget::new(4_096),
            )
            .expect("relay policy must compile"),
            Duration::from_secs(1),
        );
        let destination =
            Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), target_address.port());
        let now = super::unix_seconds().expect("test clock must be valid");
        let mut authentication = Vec::new();
        encode_request(&destination, now, [0x44; 16], &key, &mut authentication)
            .expect("request must encode");

        let exchange = async {
            let landing = async {
                let (stream, _) = landing_listener.accept().await?;
                handler.handle(stream).await.map_err(io::Error::other)
            };
            let line = async {
                let mut stream = TcpStream::connect(landing_address).await?;
                stream.set_nodelay(true)?;
                stream.write_all(&authentication).await?;
                stream.write_all(REQUEST).await?;
                stream.shutdown().await?;
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            let target = async {
                let (mut stream, _) = target_listener.accept().await?;
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await?;
                stream.write_all(RESPONSE).await?;
                stream.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(landing, line, target)
        };

        let (landing, line, target) = time::timeout(Duration::from_secs(3), exchange)
            .await
            .expect("NXR loopback must not time out");
        let stats = landing.expect("landing relay must succeed");
        assert_eq!(line.expect("line client must succeed"), RESPONSE);
        assert_eq!(target.expect("target must succeed"), REQUEST);
        assert_eq!(stats.inbound_to_outbound_bytes(), REQUEST.len() as u64);
        assert_eq!(stats.outbound_to_inbound_bytes(), RESPONSE.len() as u64);
    }
}

#[cfg(test)]
mod udp_association_tests {
    use std::{net::Ipv4Addr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
        time,
    };

    use super::{NxrAuthenticator, NxrLandingHandler, NxrReplayCache};
    use crate::{
        protocol::{
            nxr::NxrKey,
            nxr_udp::{
                DIR_LANDING_TO_LINE, DIR_LINE_TO_LANDING, FRAME_TYPE_DATAGRAM, NxrUdpSeq,
                NxrUdpSessionKey, drain_frames, encode_frame, encode_udp_open,
                open_authenticated_prefix,
            },
            vless::{Address, Destination},
        },
        transport::{TcpRelay, TcpRelayConfig},
    };

    fn landing_handler(key: [u8; 32]) -> NxrLandingHandler {
        let relay = TcpRelay::new(
            TcpRelayConfig::for_test(),
            crate::transport::FdBudget::new(4_096),
        )
        .expect("relay");
        let cache =
            NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
        NxrLandingHandler::new(
            NxrAuthenticator::new(NxrKey::new(key), cache, 30),
            Duration::from_secs(2),
            Duration::from_secs(2),
            relay,
            Duration::from_secs(5),
        )
    }

    #[tokio::test]
    async fn nxr_udp_landing_echo_round_trip() {
        let key_bytes = [0x42_u8; 32];
        let key = NxrKey::new(key_bytes);
        let echo = UdpSocket::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let dest = Destination::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), echo_addr.port());

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let land_addr = listener.local_addr().unwrap();
        let handler = landing_handler(key_bytes);
        let land_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handler.handle(stream).await
        });

        let mut client = TcpStream::connect(land_addr).await.unwrap();
        let mut open = Vec::new();
        encode_udp_open(
            &dest,
            [0x11; 16],
            super::unix_seconds().unwrap(),
            [0x99; 16],
            &key,
            &mut open,
        )
        .unwrap();
        client.write_all(&open).await.unwrap();
        let session = NxrUdpSessionKey::derive(&key, open_authenticated_prefix(&open).unwrap());

        let mut seq_out = NxrUdpSeq::new();
        let mut frame = Vec::new();
        encode_frame(
            &session,
            DIR_LINE_TO_LANDING,
            FRAME_TYPE_DATAGRAM,
            seq_out.next_out().unwrap(),
            Some(&dest),
            b"hello-nxr-udp",
            &mut frame,
        )
        .unwrap();
        client.write_all(&frame).await.unwrap();

        let mut buf = [0_u8; 64];
        let (n, from) = time::timeout(Duration::from_secs(2), echo.recv_from(&mut buf))
            .await
            .expect("echo recv")
            .unwrap();
        assert_eq!(&buf[..n], b"hello-nxr-udp");
        echo.send_to(b"echo-ok", from).await.unwrap();

        let mut reply_buf = vec![0_u8; 0];
        // Read until one complete frame arrives.
        let mut scratch = [0_u8; 4096];
        let deadline = time::Instant::now() + Duration::from_secs(2);
        let mut seq_in = NxrUdpSeq::new();
        let reply = loop {
            let n = time::timeout_at(deadline, client.read(&mut scratch))
                .await
                .expect("reply read timeout")
                .unwrap();
            assert!(n > 0);
            reply_buf.extend_from_slice(&scratch[..n]);
            let frames = drain_frames(&mut reply_buf, &session, DIR_LANDING_TO_LINE).unwrap();
            if let Some(frame) = frames.into_iter().next() {
                seq_in.accept_in(frame.seq).unwrap();
                break frame;
            }
        };
        assert_eq!(reply.payload, b"echo-ok");
        assert_eq!(reply.destination, Some(dest));

        // An oversized UDP reply must not become a valid truncated datagram.
        echo.send_to(&vec![0x5a; super::NXR_UDP_MAX_PAYLOAD + 1], from)
            .await
            .unwrap();
        assert_eq!(
            time::timeout(Duration::from_secs(2), client.read(&mut scratch))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(matches!(
            time::timeout(Duration::from_secs(2), land_task)
                .await
                .unwrap()
                .unwrap(),
            Err(super::NxrLandingError::UdpProtocol(
                super::NxrUdpError::Payload
            ))
        ));
    }

    #[tokio::test]
    async fn tcp_open_still_relays_bytes() {
        // Non-regression: TCP NXR path unchanged.
        let key_bytes = [0x33_u8; 32];
        let key = NxrKey::new(key_bytes);
        let dest_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let dest_addr = dest_listener.local_addr().unwrap();
        let dest = Destination::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), dest_addr.port());
        let dest_task = tokio::spawn(async move {
            let (mut stream, _) = dest_listener.accept().await.unwrap();
            let mut buf = [0_u8; 16];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
        });

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let land_addr = listener.local_addr().unwrap();
        let handler = landing_handler(key_bytes);
        let land_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handler.handle(stream).await
        });

        let mut client = TcpStream::connect(land_addr).await.unwrap();
        let mut open = Vec::new();
        crate::protocol::nxr::encode_request(
            &dest,
            super::unix_seconds().unwrap(),
            [0x22; 16],
            &key,
            &mut open,
        )
        .unwrap();
        client.write_all(&open).await.unwrap();
        client.write_all(b"tcp-payload").await.unwrap();
        let mut buf = [0_u8; 16];
        let n = time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"tcp-payload");
        dest_task.await.unwrap();
        land_task.abort();
    }
}
