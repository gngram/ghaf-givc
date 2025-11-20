// SPDX-FileCopyrightText: 2024-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package policyagent

import (
	"io"

	log "github.com/sirupsen/logrus"
	pb "givc/modules/api/policyagent"
	"google.golang.org/grpc"
)

type PolicyAgentServer struct {
	pb.UnimplementedPolicyAgentServer
}

func (s *PolicyAgentServer) Name() string {
	return "Policy Agent Server"
}

func (s *PolicyAgentServer) RegisterGrpcService(srv *grpc.Server) {
	pb.RegisterPolicyAgentServer(srv, s)
}

func NewPolicyAgentServer() (*PolicyAgentServer, error) {
	return &PolicyAgentServer{}, nil
}

// StreamPolicy is the implementation of the gRPC bidirectional streaming method.
func (s *PolicyAgentServer) StreamPolicy(stream pb.PolicyAgent_StreamPolicyServer) error {
	log.Info("Policy stream initiated by givc-admin.")

	for {
		// Receive a message from the client (givc-admin)
		in, err := stream.Recv()
		if err == io.EOF {
			// The client has closed the stream.
			log.Info("Policy stream closed by givc-admin.")
			return nil
		}
		if err != nil {
			log.Errorf("Error receiving from policy stream: %v", err)
			return err
		}

		// --- YOUR POLICY LOGIC GOES HERE ---
		// For this skeleton, we just print the received message.
		log.Infof("!!!!!! POLICY AGENT RECEIVED: '%s' !!!!!!", in.Message)
		// --- END OF YOUR LOGIC ---
	}
}
