package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	agentnodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire-plugin-sdk/templates/agent/nodeattestor"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	sat_common "github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var sampleKeyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBywIBAAJhAMB4gbT09H2RKXaxbu6IV9C3WY+pvkGAbrlQRIHLHwV3Xt1HchjX
c08v1VEoTBN2YTjhZJlDb/VUsNMJsmBFBBted5geRcbrDtXFlUJ8tQoQx1dWM4Aa
xcdULJ83A9ICKwIDAQABAmBR1asInrIphYQEtHJ/NzdnRd3tqHV9cjch0dAfA5dA
Ar4yBYOsrkaX37WqWSDnkYgN4FWYBWn7WxeotCtA5UQ3SM5hLld67rUqAm2dLrs1
z8va6SwLzrPTu2+rmRgovFECMQDpbfPBRex7FY/xWu1pYv6X9XZ26SrC2Wc6RIpO
38AhKGjTFEMAPJQlud4e2+4I3KkCMQDTFLUvBSXokw2NvcNiM9Kqo5zCnCIkgc+C
hM3EzSh2jh4gZvRzPOhXYvNKgLx8+LMCMQDL4meXlpV45Fp3eu4GsJqi65jvP7VD
v1P0hs0vGyvbSkpUo0vqNv9G/FNQLNR6FRECMFXEMz5wxA91OOuf8HTFg9Lr+fUl
RcY5rJxm48kUZ12Mr3cQ/kCYvftL7HkYR/4rewIxANdritlIPu4VziaEhYZg7dvz
pG3eEhiqPxE++QHpwU78O+F1GznOPBvpZOB3GfyjNQ==
-----END RSA PRIVATE KEY-----`)

const (
		podName = "MYPOD"
		clusterName = "MYCLUSTER"
)

type attestorSuite struct {
	agentPlugin         *Plugin
	agentAttestorClient *agentnodeattestorv1.NodeAttestorPluginClient
	agentHCL            string

	psatData  *k8s.PSATAttestationData
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
	dir := "/temp/token"
	a.token, err = createPSAT(clusterName, podName)
	require.NoError(a.t, err)
	a.tokenPath = dir
}

func loadAgent(t *testing.T) attestorSuite {
	a := attestorSuite{
		t: t,
		//psatData: common.DefaultPSATData(),
		require: require.New(t),
	}
	a.createAndWriteToken()
	a.require.NoError(a.loadAgentPlugin(`token_path = "./token" cluster = "FOO"`))
	return a
}

func loadTokenAgent(t *testing.T, tokenPath string) attestorSuite {
	a := attestorSuite{
		t: t,
		//psatData: common.DefaultPSATData(),
		require: require.New(t),
	}
	a.createAndWriteToken()
	a.require.NoError(a.loadAgentPlugin(fmt.Sprintf(`token_path = "%s" cluster = "FOO"`, tokenPath)))
	return a
}

// Creates a PSAT using the given namespace and podName (just for testing)
func createPSAT(namespace, podName string) (string, error) {
	// Create a jwt builder
	s, err := createSigner()
	if err != nil {
		return "", err
	}

	builder := jwt.Signed(s)

	// Set useful claims for testing
	claims := sat_common.PSATClaims{}
	claims.K8s.Namespace = namespace
	claims.K8s.Pod.Name = podName
	builder = builder.Claims(claims)

	// Serialize and return token
	token, err := builder.CompactSerialize()
	if err != nil {
		return "", err
	}

	return token, nil
}

func createSigner() (jose.Signer, error) {
	sampleKey, err := pemutil.ParseRSAPrivateKey(sampleKeyPEM)
	if err != nil {
		return nil, err
	}

	sampleSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       sampleKey,
	}, nil)

	if err != nil {
		return nil, err
	}

	return sampleSigner, nil
}

func (s *AttestorSuite) joinPath(path string) string {
	return filepath.Join(s.dir, path)
}

func (s *AttestorSuite) writeValue(path, data string) string {
	valuePath := s.joinPath(path)
	err := os.MkdirAll(filepath.Dir(valuePath), 0755)
	s.Require().NoError(err)
	err = os.WriteFile(valuePath, []byte(data), 0600)
	s.Require().NoError(err)
	return valuePath
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

// func TestAttestationWrongToken(t *testing.T) {
// 	a := loadTokenAgent(t)
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	// Start attestation
// 	agentStream, err := a.agentAttestorClient.AidAttestation(ctx)
// 	a.require.NoError(err)

// 	// Generate a challenge from the payload
// 	agentResponse, err := agentStream.Recv()
// 	a.require.NoError(err)

// 	attestationData := new(k8s.PSATAttestationData)
// 	err = json.Unmarshal(agentResponse.GetPayload(), attestationData)
// 	a.require.NotEqual(a.token, attestationData.Token, "Expected token: %s got %s", a.token, attestationData.Token)
// 	a.require.NoError(err)
// }

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
				//psatData: test.psatData,
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

func TestAidAttestation(t *testing.T) {
	tests := []struct {
		name        string
		tokenPath   string
		expectedErr string
	}{
		{
			name:        "Wrong token path",
			tokenPath:   "./tokenn",
			expectedErr: "unable to load token from",
		},
		{
			name:        "Empty token",
			tokenPath:   "./empty_token",
			expectedErr: "unable to load token from",
		},
		{
			name:        "Wrong token",
			tokenPath:   "./wrongtoken",
			expectedErr: "wrong token",
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
				a.require.Error(err)
				a.require.Contains(err, test.expectedErr)
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
		PluginServer: nodeattestorv1.NodeAttestorPluginServer(plugin),
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
