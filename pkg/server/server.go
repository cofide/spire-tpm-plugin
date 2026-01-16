/*
 ** Copyright 2019 Bloomberg Finance L.P.
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cofide/spire-tpm-plugin/pkg/common"
	"github.com/google/go-attestation/attest"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Config struct {
	trustDomain string
	CaPath      string `hcl:"ca_path"`
	HashPath    string `hcl:"hash_path"`
}

func buildConfig(hclText string) (*Config, error) {
	config := &Config{}
	if err := hcl.Decode(config, hclText); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration file: %v", err)
	}

	if config.CaPath != "" {
		if _, err := os.Stat(config.CaPath); os.IsNotExist(err) {
			return nil, status.Errorf(codes.InvalidArgument, "ca_path '%s' does not exist", config.CaPath)
		}
	} else {
		tryCaPath := "/opt/spire/.data/certs"
		if _, err := os.Stat(tryCaPath); !os.IsNotExist(err) {
			config.CaPath = tryCaPath
		}
	}
	if config.HashPath != "" {
		if _, err := os.Stat(config.HashPath); os.IsNotExist(err) {
			return nil, status.Errorf(codes.InvalidArgument, "hash_path '%s' does not exist", config.HashPath)
		}
	} else {
		tryHashPath := "/opt/spire/.data/hashes"
		if _, err := os.Stat(tryHashPath); !os.IsNotExist(err) {
			config.HashPath = tryHashPath
		}
	}

	if config.CaPath == "" && config.HashPath == "" {
		return nil, status.Errorf(codes.InvalidArgument, "either ca_path, hash_path, or both are required")
	}

	return config, nil
}

// Plugin implements the nodeattestor Plugin interface
type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer
	config *Config
	m      sync.Mutex
	ns     NodeStore
}

type NodeStore interface {
	Attest(ctx context.Context, ek *attest.EK) (NodeMeta, error)
	Configure(string) (*Config, error)
	Validate(string) error
}

// NodeMeta defines metadata about a node in a node store.
type NodeMeta struct {
	// SelectorValues is a slice of additional node selector values to use for the node.
	SelectorValues []string
}

type FileNodeStore struct {
	caPath   string
	hashPath string
}

func (s *FileNodeStore) Attest(ctx context.Context, ek *attest.EK) (NodeMeta, error) {
	hashEncoded, err := common.GetPubHash(ek)
	if err != nil {
		return NodeMeta{}, status.Errorf(codes.InvalidArgument, "tpm: could not get public key hash: %v", err)
	}

	validEK := false

	if s.hashPath != "" {
		filename := filepath.Join(s.hashPath, hashEncoded)
		if _, err := os.Stat(filename); !os.IsNotExist(err) {
			validEK = true
		}
	}

	if !validEK && s.caPath != "" && ek.Certificate != nil {
		files, err := os.ReadDir(s.caPath)
		if err != nil {
			return NodeMeta{}, status.Errorf(codes.InvalidArgument, "tpm: could not open ca directory: %v", err)
		}

		roots := x509.NewCertPool()
		for _, file := range files {
			if !file.IsDir() {
				filename := filepath.Join(s.caPath, file.Name())
				certData, err := os.ReadFile(filename)
				if err != nil {
					return NodeMeta{}, status.Errorf(codes.InvalidArgument, "tpm: could not read cert data for '%s': %v", filename, err)
				}

				ok := roots.AppendCertsFromPEM(certData)
				if ok {
					continue
				}

				root, err := x509.ParseCertificate(certData)
				if err == nil {
					roots.AddCert(root)
					continue
				}

				return NodeMeta{}, status.Errorf(codes.InvalidArgument, "tpm: could not parse cert data for '%s': %v", filename, err)
			}
		}

		opts := x509.VerifyOptions{Roots: roots}
		if _, err = ek.Certificate.Verify(opts); err != nil {
			return NodeMeta{}, fmt.Errorf("tpm: could not verify cert: %v", err)
		}
		validEK = true
	}

	if !validEK {
		return NodeMeta{}, fmt.Errorf("tpm: could not validate EK")
	}

	return NodeMeta{}, nil
}

func (s *FileNodeStore) Configure(hclCfg string) (*Config, error) {
	config, err := buildConfig(hclCfg)
	if err != nil {
		return nil, err
	}
	s.caPath = config.CaPath
	s.hashPath = config.HashPath

	return config, nil
}

func (s *FileNodeStore) Validate(hclCfg string) error {
	_, err := buildConfig(hclCfg)
	return err
}

func New(ns NodeStore) *Plugin {
	return &Plugin{ns: ns}
}

func NewFromConfig(config *Config) *Plugin {
	return &Plugin{
		config: config,
		ns: &FileNodeStore{
			caPath:   config.CaPath,
			hashPath: config.HashPath,
		},
	}
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	cfg, err := p.ns.Configure(req.GetHclConfiguration())
	if err != nil {
		return nil, err
	}
	p.config = cfg

	if req.CoreConfiguration == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "tpm: core configuration not set")
	}

	if req.CoreConfiguration.GetTrustDomain() == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "tpm: trust domain is not set")
	}
	p.config.trustDomain = req.CoreConfiguration.GetTrustDomain()

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	err := p.ns.Validate(req.GetHclConfiguration())

	var notes []string
	if err != nil {
		notes = append(notes, err.Error())
	}

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	if p.config == nil {
		return errors.New("plugin not configured")
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	conf := p.getConfiguration()
	if conf == nil {
		return status.Error(codes.FailedPrecondition, "tpm: not configured")
	}

	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "tpm: missing attestation payload")
	}

	attestationData := new(common.AttestationData)
	err = json.Unmarshal(payload, attestationData)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "tpm: failed to unmarshal attestation data: %v", err)
	}

	ek, err := common.DecodeEK(attestationData.EK)
	if err != nil {
		return err
	}

	nodeMeta, err := p.ns.Attest(stream.Context(), ek)
	if err != nil {
		return err
	}

	hashEncoded, err := common.GetPubHash(ek)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "tpm: could not get public key hash: %v", err)
	}

	ap := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         ek.Public,
		AK:         *attestationData.AK,
	}

	secret, ec, err := ap.Generate()
	if err != nil {
		return status.Errorf(codes.Internal, "tpm: could not generate credential challenge: %v", err)
	}

	challenge := &common.Challenge{
		EC: ec,
	}

	challengeBytes, err := json.Marshal(challenge)
	if err != nil {
		return status.Errorf(codes.Internal, "tpm: unable to marshal challenge: %v", err)
	}

	if err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: challengeBytes,
		},
	}); err != nil {
		return status.Errorf(status.Code(err), "tpm: unable to send challenge: %v", err)
	}

	challengeResp, err := stream.Recv()
	if err != nil {
		return status.Errorf(status.Code(err), "tpm: unable to receive challenge response: %v", err)
	}

	response := &common.ChallengeResponse{}
	if err := json.Unmarshal(challengeResp.GetChallengeResponse(), response); err != nil {
		return status.Errorf(codes.InvalidArgument, "tpm: unable to unmarshal challenge response: %v", err)
	}

	if !bytes.Equal(secret, response.Secret) {
		return status.Errorf(codes.PermissionDenied, "tpm: incorrect secret from attestor")
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       common.AgentID(p.config.trustDomain, hashEncoded),
				SelectorValues: append(buildSelectors(hashEncoded), nodeMeta.SelectorValues...),
				CanReattest:    true,
			},
		},
	})
}

func buildSelectors(pubHash string) []string {
	var selectors []string
	selectors = append(selectors, "pub_hash:"+pubHash)
	return selectors
}

func (p *Plugin) getConfiguration() *Config {
	p.m.Lock()
	defer p.m.Unlock()
	return p.config
}
