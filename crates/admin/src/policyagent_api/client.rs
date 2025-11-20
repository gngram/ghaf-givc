// Copyright 2024 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

use crate::pb::policyagent::{
    PolicyUpdate, policy_agent_client::PolicyAgentClient as GrpcPolicyAgentClient,
};
use anyhow::Result;
use futures_util::stream::Stream;
use givc_client::endpoint::EndpointConfig;
use tonic::transport::Channel;

#[derive(Debug, Clone)]
pub struct PolicyAgentClient {
    endpoint: EndpointConfig,
}

impl PolicyAgentClient {
    pub fn new(endpoint: EndpointConfig) -> Self {
        Self { endpoint }
    }

    async fn connect(&self) -> Result<GrpcPolicyAgentClient<Channel>> {
        let client = self.endpoint.connect().await?;
        Ok(GrpcPolicyAgentClient::new(client))
    }

    pub async fn stream_policy(
        &self,
        updates: impl Stream<Item = PolicyUpdate> + Send + 'static,
    ) -> Result<()> {
        let mut client = self.connect().await?;
        client.stream_policy(updates).await?;
        Ok(())
    }
}
