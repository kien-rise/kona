//! Ethereum utilities for the host binary.

use alloy_provider::{Network, RootProvider};
use alloy_rpc_client::{ClientBuilder, RpcClient};
use alloy_transport::layers::{RetryBackoffLayer, ThrottleLayer};
use alloy_transport_http::Http;
use reqwest::{Client, Url};

use std::io;

mod precompiles;
pub(crate) use precompiles::execute;

/// Returns an HTTP provider for the given URL.
pub fn http_provider<N: Network>(url: &str) -> RootProvider<N> {
    let url = url.parse().unwrap();
    let http = Http::<Client>::new(url);
    RootProvider::new(RpcClient::new(http, true))
}

/// Creates an `RpcClient` from a URL, optionally adding throttling or retry logic.
/// If both RPS and retries are given, retry-backoff is used; if only RPS is given, throttling is used.
/// Returns an error for invalid URLs or for retries without RPS.
pub fn rpc_client(
    url: impl TryInto<Url, Error: std::fmt::Debug>,
    requests_per_second: Option<u32>,
    max_retries: Option<u32>,
) -> io::Result<RpcClient> {
    let url = url.try_into().map_err(|e| io::Error::other(format!("cannot parse url: {:?}", e)))?;
    match (requests_per_second, max_retries) {
        (Some(rps), Some(lim)) => Ok(ClientBuilder::default()
            .layer(RetryBackoffLayer::new(lim, 1000 / rps as u64, rps as u64).with_avg_unit_cost(1))
            .http(url)),

        (Some(rps), None) => Ok(ClientBuilder::default().layer(ThrottleLayer::new(rps)).http(url)),
        (None, Some(_)) => Err(io::Error::other("max_retries requires requests_per_second")),
        (None, None) => Ok(ClientBuilder::default().http(url)),
    }
}
