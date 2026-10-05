// SPDX-FileCopyrightText: 2025-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

use tonic::Request;
use tonic::transport::Channel;

use crate::endpoint::EndpointConfig;
use givc_common::pb::exec::{
    OtaAction, OtaUpdateRequest, OtaUpdateResponse, UptimeRequest, UptimeResponse,
};

type Client = givc_common::pb::exec::exec_client::ExecClient<Channel>;

/// `ExecClient` struct for interacting with the dedicated gRPC server
pub struct ExecClient {
    client: Client,
}

impl ExecClient {
    /// Connects to the gRPC server at the specified address
    /// # Errors
    /// Raise error if unable to connect
    pub async fn connect(endpoint: EndpointConfig) -> anyhow::Result<Self> {
        let channel = endpoint.connect().await?;
        let client = Client::new(channel);
        Ok(Self { client })
    }

    /// Queries system uptime via dedicated RPC
    /// # Errors
    /// Raise error on gRPC IO error
    pub async fn get_uptime(&mut self) -> anyhow::Result<UptimeResponse> {
        let resp = self
            .client
            .get_uptime(Request::new(UptimeRequest {}))
            .await?;
        Ok(resp.into_inner())
    }

    /// Executes dedicated OTA update operations via typed RPC
    /// # Errors
    /// Raise error on gRPC IO error
    pub async fn run_ota_update(
        &mut self,
        action: OtaAction,
        pin: Option<String>,
        cache: Option<String>,
        token: Option<String>,
        cachix_host: Option<String>,
    ) -> anyhow::Result<OtaUpdateResponse> {
        let request = OtaUpdateRequest {
            action: action.into(),
            pin,
            cache,
            token,
            cachix_host,
        };
        let resp = self.client.run_ota_update(Request::new(request)).await?;
        Ok(resp.into_inner())
    }
}
