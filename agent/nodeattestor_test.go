package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	agentnodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	common "github.com/rodrigolc/spire_k8s_plugin_boilerplate/pkg/common"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire-plugin-sdk/templates/agent/nodeattestor"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

const (
		podName = "MYPOD"
		clusterName = "MYCLUSTER"
)

type attestorSuite struct {
	agentPlugin         *Plugin
	agentAttestorClient *agentnodeattestorv1.NodeAttestorPluginClient
	agentHCL            string

	psatData  *common.PSATData
	token     string
	tokenPath string

	t       *testing.T
	require *require.Assertions
}

func (a *attestorSuite) loadAgentPlugin(agentHLC string) error {
	a.agentPlugin = new(Plugin)

	a.agentAttestorClient = new(agentnodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)

	plugintest.ServeInBackground(a.t, plugintest.Config{
		PluginServer:   agentnodeattestorv1.NodeAttestorPluginServer(a.agentPlugin),
		PluginClient:   a.agentAttestorClient,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(a.agentPlugin)},
		ServiceClients: []pluginsdk.ServiceClient{configClient},
	})

	hcl := fmt.Sprintf(`
		cluster = "FOO"
		token_path = %q
	`, a.tokenPath)

	if agentHLC != "" {
		hcl = agentHLC
	}

	_, err := configClient.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: hcl,
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: "TrustDomain",
		},
	})

	return err
}

func (a *attestorSuite) createAndWriteToken() {
	var err error
	dir := "/tmp/token"
	a.token, err = common.CreatePSAT(clusterName, podName)
	require.NoError(a.t, err)
	a.tokenPath = dir
}

func loadAgent(t *testing.T) attestorSuite {
	a := attestorSuite{
		t: t,
		psatData: common.DefaultPSATData(),
		require: require.New(t),
	}
	a.createAndWriteToken()
	a.require.NoError(a.loadAgentPlugin(`token_path = "./token" cluster = "FOO"`))
	return a
}

func loadTokenAgent(t *testing.T, tokenPath string) attestorSuite {
	a := attestorSuite{
		t: t,
		psatData: common.DefaultPSATData(),
		require: require.New(t),
	}
	a.createAndWriteToken()
	a.require.NoError(a.loadAgentPlugin(fmt.Sprintf(`token_path = "%s" cluster = "FOO"`, tokenPath)))
	return a
}

type AttestorSuite struct {
	spiretest.Suite

	dir string
}

func (s *AttestorSuite) SetupTest() {
	s.dir = s.TempDir()
}

func TestAttestationSuccess(t *testing.T) {
	a := loadAgent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start attestation
	agentStream, err := a.agentAttestorClient.AidAttestation(ctx)
	a.require.NoError(err)

	// Generate a challenge from the payload
	agentResponse, err := agentStream.Recv()
	a.require.NoError(err)

	attestationData := new(k8s.PSATAttestationData)
	err = json.Unmarshal(agentResponse.GetPayload(), attestationData)
	a.require.Equal(a.token, attestationData.Token, "Expected token: %s got %s", a.token, attestationData.Token)
	a.require.NoError(err)
}

func TestConfig(t *testing.T) {
	tests := []struct {
		name           string
		agentHclConfig string
		expectedErr    string
	}{
		{
			name:           "Poorly formatted HCL config",
			agentHclConfig: `poorly formatted hcl`,
			expectedErr:    "failed to decode configuration",
		},
		{
			name:           "No Cluster config",
			agentHclConfig: `token_path = "foo/bar"`,
			expectedErr:    "configuration missing cluster",
		},
		{
			name:           "Config success",
			agentHclConfig: `token_path = "/foo/bar" cluster = "FOO"`,
			expectedErr:    "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := &attestorSuite{
				t:        t,
				require:  require.New(t),
				agentHCL: test.agentHclConfig,
			}
			err := a.loadAgentPlugin(test.agentHclConfig)
			if test.expectedErr == "" {
				require.NoError(t, err)
			} else {
				a.require.Error(err)
				a.require.Contains(err.Error(), test.expectedErr, "unexpected server configuration error")
			}

		})
	}
}

func TestAidAttestationFailures(t *testing.T) {
	tests := []struct {
		name        string
		tokenPath   string
		expectedErr string
	}{
		{
			name:        "Wrong token path",
			tokenPath:   "./tokenn",
			expectedErr: "unable to load token from ./tokenn",
		},
		{
			name:        "Empty token",
			tokenPath:   "./empty_token",
			expectedErr: `"./empty_token" is empty`,
		},
		{
			name:        "Wrong token",
			tokenPath:   "./wrongtoken",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := loadTokenAgent(t, test.tokenPath)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Start attestation
			agentStream, err := a.agentAttestorClient.AidAttestation(ctx)
			a.require.NoError(err)

			// Generate a challenge from the payload
			agentResponse, err := agentStream.Recv()
			if test.expectedErr != "" {
				a.require.NotNil(err)
				a.require.Error(err)
				a.require.Contains(err.Error() , test.expectedErr)
				return
			}
			a.require.NoError(err)
			attestationData := new(k8s.PSATAttestationData)
			err = json.Unmarshal(agentResponse.GetPayload(), attestationData)
			a.require.NoError(err)
			a.require.NotEqual(a.token, attestationData.Token, "Expected token: %s got %s", a.token, attestationData.Token)
		})
	}
}

func Test(t *testing.T) {
	plugin := new(nodeattestor.Plugin)
	naClient := new(agentnodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)

	// Serve the plugin in the background with the configured plugin and
	// service servers. The servers will be cleaned up when the test finishes.
	// TODO: Remove the config service server and client if no configuration
	// is required.
	// TODO: Provide host service server implementations if required by the
	// plugin.
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: agentnodeattestorv1.NodeAttestorPluginServer(plugin),
		PluginClient: naClient,
		ServiceServers: []pluginsdk.ServiceServer{
			configv1.ConfigServiceServer(plugin),
		},
		ServiceClients: []pluginsdk.ServiceClient{
			configClient,
		},
	})

	// TODO: Invoke methods on the clients and assert the results
}
