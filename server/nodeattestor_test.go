package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	//common_devid "github.com/spiffe/spire/pkg/common/plugin/tpmdevid"
	"testing"

	"github.com/rodrigolc/psat-iid/pkg/common"

	"github.com/google/go-cmp/cmp"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	servernodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestConfigError(t *testing.T) {
	tests := []struct {
		name            string
		psatData        *common.PSATData
		trustDomain     string
		serverHclConfig string
		expectedErr     string
	}{
		{
			name:            "Poorly formatted HCL config",
			psatData:        common.DefaultPSATData(),
			serverHclConfig: "poorly formatted hcl",
			expectedErr:     "rpc error: code = InvalidArgument desc = failed to decode configuration",
		},
		{
			name:        "Missing trust domain",
			psatData:    common.DefaultPSATData(),
			trustDomain: "",
			expectedErr: "rpc error: code = InvalidArgument desc = core configuration missing trust domain",
		},
		{
			name:        "Missing cluster",
			psatData:    common.DefaultPSATData(),
			trustDomain: "any.domain",
			expectedErr: "rpc error: code = InvalidArgument desc = configuration must have at least one cluster",
		},
		{
			name:        "Missing allowed service account",
			psatData:    common.DefaultPSATData(),
			trustDomain: "any.domain",
			serverHclConfig: `
				clusters = {
					"any" = {
						service_account_allow_list = []
					}
				}`,
			expectedErr: `rpc error: code = InvalidArgument desc = cluster "any" configuration must have at least one service account allowed`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := &attestorSuite{t: t}
			a.require = require.New(t)
			a.psatData = test.psatData
			a.createAndWriteToken()

			// load and configure server
			s := new(Plugin)
			serverAttestorClient := new(servernodeattestorv1.NodeAttestorPluginClient)
			serverConfigClient := new(configv1.ConfigServiceClient)
			plugintest.ServeInBackground(t, plugintest.Config{
				PluginServer:   servernodeattestorv1.NodeAttestorPluginServer(s),
				PluginClient:   serverAttestorClient,
				ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(s)},
				ServiceClients: []pluginsdk.ServiceClient{serverConfigClient},
			})
			_, err := serverConfigClient.Configure(context.Background(), &configv1.ConfigureRequest{
				HclConfiguration: test.serverHclConfig,
				CoreConfiguration: &configv1.CoreConfiguration{
					TrustDomain: test.trustDomain,
				},
			})
			a.require.Error(err)
			a.require.Contains(err.Error(), test.expectedErr, "unexpected server configuration error")
		})
	}
}

func TestAttestationSetupFail(t *testing.T) {
	t.Run("Server not configured", func(t *testing.T) {
		a := &attestorSuite{t: t}
		a.require = require.New(t)

		a.serverPlugin = new(Plugin)
		a.serverAttestorClient = new(servernodeattestorv1.NodeAttestorPluginClient)
		configClient := new(configv1.ConfigServiceClient)
		plugintest.ServeInBackground(a.t, plugintest.Config{
			PluginServer:   servernodeattestorv1.NodeAttestorPluginServer(a.serverPlugin),
			PluginClient:   a.serverAttestorClient,
			ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(a.serverPlugin)},
			ServiceClients: []pluginsdk.ServiceClient{configClient},
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		serverStream, err := a.serverAttestorClient.Attest(ctx)
		a.require.NoError(err, "attest failed")
		_, err = serverStream.Recv()

		a.require.Error(err)
		a.require.Contains(err.Error(), "rpc error: code = FailedPrecondition desc = not configured")
	})
	t.Run("Empty payload", func(t *testing.T) {
		a := &attestorSuite{t: t}
		a.require = require.New(t)
		a.psatData = common.DefaultPSATData()

		a.createAndWriteToken()
		a.require.NoError(a.loadServerPlugin())

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		serverStream, err := a.serverAttestorClient.Attest(ctx)
		a.require.NoError(err)

		err = serverStream.Send(&servernodeattestorv1.AttestRequest{})
		a.require.NoError(err, "failed to send attestation request")
		_, err = serverStream.Recv()

		a.require.Error(err)
		a.require.Contains(err.Error(), "rpc error: code = InvalidArgument desc = missing attestation payload")
	})

	t.Run("No Token in payload", func(t *testing.T) {
		a := &attestorSuite{t: t}
		a.require = require.New(t)
		a.psatData = common.DefaultPSATData()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		serverStream, err := a.serverAttestorClient.Attest(ctx)
		a.require.NoError(err, "attest failed")
		_, err = serverStream.Recv()

		a.require.Error(err)
		a.require.Contains(err.Error(), "rpc error: code = FailedPrecondition desc = missing token in attestation data")
	})
}

func TestAttestationFail(t *testing.T) {
	a := &attestorSuite{t: t}
	a.require = require.New(t)
	a.psatData = common.DefaultPSATData()
	a.createAndWriteToken()

	tests := []struct {
		name         string
		psatData     *common.PSATData
		attRequest   common.AttestationRequest
		createMockFn func(*common.PSATData, string) *apiClientMock
		badToken     bool
		expectedErr  string
	}{
		{
			name:         "Failed to unmarshal",
			psatData:     common.DefaultPSATData(),
			createMockFn: createAPIClientMock,
			expectedErr:  `rpc error: code = InvalidArgument desc = missing cluster in attestation data`,
		},
		{
			name:     "Missing token",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
				},
			},
			createMockFn: createAPIClientMock,
			badToken:     true,
			expectedErr:  `rpc error: code = InvalidArgument desc = missing token in attestation data`,
		},
		{
			name:     "Failed to find configuration for provided cluster",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "foo",
					Token:   a.token,
				},
			},
			createMockFn: createAPIClientMock,
			expectedErr:  `not configured for cluster "foo"`,
		},
		{
			name:     "Invalid token",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   "Bad token",
				},
			},
			createMockFn: createAPIClientMock,
			badToken:     true,
			expectedErr:  `rpc error: code = Internal desc = unable to validate token with TokenReview API`,
		},
		{
			name:     "Missing namespace",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
				},
			},
			createMockFn: func(psatData *common.PSATData, token string) *apiClientMock {
				return createAPIClientMock(&common.PSATData{
					Namespace: "",
				}, token)
			},
			expectedErr: `fail to parse username from token review status`,
		},
		{
			name:     "Missing pod name",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
				},
			},
			createMockFn: func(psatData *common.PSATData, token string) *apiClientMock {
				return createAPIClientMock(&common.PSATData{
					PodName: "",
				}, token)
			},
			expectedErr: `fail to parse username from token review status`,
		},
		{
			name:     "Token not authenticated",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   a.token,
				},
			},
			createMockFn: func(psatData *common.PSATData, token string) *apiClientMock {
				clientMock := createAPIClientMock(psatData, token)
				clientMock.SetTokenStatus(token, createTokenStatus(psatData, false, defaultAudience))
				return clientMock
			},
			expectedErr: `rpc error: code = PermissionDenied desc = token not authenticated according to TokenReview API`,
		},
		{
			name:     "Failed to parse user from token",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   a.token,
				},
			},
			createMockFn: func(psatData *common.PSATData, token string) *apiClientMock {
				clientMock := createAPIClientMock(psatData, token)
				badTokenStatus := &authv1.TokenReviewStatus{
					Authenticated: true,
					User: authv1.UserInfo{
						Extra: make(map[string]authv1.ExtraValue),
					},
					Audiences: defaultAudience,
				}
				clientMock.SetTokenStatus(token, badTokenStatus)
				return clientMock
			},
			expectedErr: `rpc error: code = Internal desc = fail to parse username from token review status`,
		},
		{
			name:     "Forbidden service account name",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   a.token,
				},
			},
			createMockFn: func(psatData *common.PSATData, token string) *apiClientMock {
				return createAPIClientMock(&common.PSATData{
					Namespace:          "NS2",
					ServiceAccountName: "SA2",
				}, token)
			},
			expectedErr: `"NS2:SA2" is not an allowed service account`,
		},
		{
			name:     "Failed to get pod uid from token",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   a.token,
				},
			},
			createMockFn: func(psatData *common.PSATData, token string) *apiClientMock {
				clientMock := createAPIClientMock(psatData, token)
				clientMock.status[token].User.Extra["authentication.kubernetes.io/pod-uid"] = nil
				return clientMock
			},
			expectedErr: "rpc error: code = Internal desc = fail to get pod UID from token review status",
		},
		{
			name:     "Failed to get pod uid from token",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   a.token,
				},
			},
			createMockFn: func(psatData *common.PSATData, token string) *apiClientMock {
				clientMock := &apiClientMock{
					apiClientConfig: apiClientConfig{
						status: make(map[string]*authv1.TokenReviewStatus),
					},
				}
				clientMock.SetTokenStatus(token, createTokenStatus(psatData, true, defaultAudience))

				return clientMock
			},
			expectedErr: "rpc error: code = Internal desc = fail to get pod from k8s API server",
		},
		{
			name:     "Failed to get node",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   a.token,
				},
			},
			createMockFn: func(psatData *common.PSATData, token string) *apiClientMock {
				clientMock := &apiClientMock{
					apiClientConfig: apiClientConfig{
						status: make(map[string]*authv1.TokenReviewStatus),
					},
				}
				clientMock.SetTokenStatus(token, createTokenStatus(psatData, true, defaultAudience))

				return clientMock
			},
			expectedErr: "rpc error: code = Internal desc = fail to get node from k8s API server",
		},
		{
			name:     "Failed to get node uid from token",
			psatData: common.DefaultPSATData(),
			attRequest: common.AttestationRequest{
				PSATAttestationData: k8s.PSATAttestationData{
					Cluster: "FOO",
					Token:   a.token,
				},
			},
			createMockFn: func(psatData *common.PSATData, token string) *apiClientMock {
				clientMock := createAPIClientMock(psatData, token)
				clientMock.status[token].User.Extra["authentication.kubernetes.io/node-uid"] = nil
				return clientMock
			},
			expectedErr: "rpc error: code = Internal desc = fail to get node UID from token review status",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Spin up server plugin
			a.require.NoError(a.loadServerPlugin(), "failed to load server")
			a.serverPlugin.config.clusters[a.psatData.Cluster].client = test.createMockFn(a.psatData, a.token)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Begin attestation
			serverStream, err := a.serverAttestorClient.Attest(ctx)
			a.require.NoError(err, "failed opening server Attest stream")

			payload, err := json.Marshal(test.attRequest)
			a.require.NoError(err, "failed to marshal testing payload")

			// Send attestation payload to plugin
			a.require.NoError(serverStream.Send(&servernodeattestorv1.AttestRequest{
				Request: &servernodeattestorv1.AttestRequest_Payload{
					Payload: payload,
				},
			}))
			a.require.NoError(err, "failed to send attestation request to server")

		})
	}
}

/*
func (a *attestorSuite) TestAttestSuccess() {
	// Success with FOO signed token
	a.apiServerClient.SetTokenStatus(token, createTokenStatus(tokenData, true, defaultAudience))
	a.apiServerClient.SetPod(createPod("NS1", "PODNAME-1", "NODENAME-1", "172.16.10.1"))
	a.apiServerClient.SetNode(createNode("NODENAME-1", "NODEUID-1"))

	result, err := a.attestor.Attest(context.Background(), makePayload("FOO", token), expectNoChallenge)
	a.Require().NoError(err)
	a.Require().NotNil(result)
	a.Require().Equal(result.AgentID, "spiffe://example.org/spire/agent/k8s_psat/FOO/NODEUID-1")
	a.RequireProtoListEqual([]*common.Selector{
		{Type: "k8s_psat", Value: "cluster:FOO"},
		{Type: "k8s_psat", Value: "agent_ns:NS1"},
		{Type: "k8s_psat", Value: "agent_sa:SA1"},
		{Type: "k8s_psat", Value: "agent_pod_name:PODNAME-1"},
		{Type: "k8s_psat", Value: "agent_pod_uid:PODUID-1"},
		{Type: "k8s_psat", Value: "agent_node_ip:172.16.10.1"},
		{Type: "k8s_psat", Value: "agent_node_name:NODENAME-1"},
		{Type: "k8s_psat", Value: "agent_node_uid:NODEUID-1"},
		{Type: "k8s_psat", Value: "agent_node_label:NODELABEL-B:B"},
		{Type: "k8s_psat", Value: "agent_pod_label:PODLABEL-A:A"},
	}, result.Selectors)

	// Success with BAR signed token
	tokenData = &TokenData{
		namespace:          "NS2",
		serviceAccountName: "SA2",
		podName:            "PODNAME-2",
		podUID:             "PODUID-2",
	}
	token = a.signToken(a.barSigner, tokenData)
	a.apiServerClient.SetTokenStatus(token, createTokenStatus(tokenData, true, []string{"AUDIENCE"}))
	a.apiServerClient.SetPod(createPod("NS2", "PODNAME-2", "NODENAME-2", "172.16.10.2"))
	a.apiServerClient.SetNode(createNode("NODENAME-2", "NODEUID-2"))

	// Success with BAR signed token
	result, err = a.attestor.Attest(context.Background(), makePayload("BAR", token), expectNoChallenge)
	a.Require().NoError(err)
	a.Require().NotNil(result)
	a.Require().Equal(result.AgentID, "spiffe://example.org/spire/agent/k8s_psat/BAR/NODEUID-2")
	a.RequireProtoListEqual([]*common.Selector{
		{Type: "k8s_psat", Value: "cluster:BAR"},
		{Type: "k8s_psat", Value: "agent_ns:NS2"},
		{Type: "k8s_psat", Value: "agent_sa:SA2"},
		{Type: "k8s_psat", Value: "agent_pod_name:PODNAME-2"},
		{Type: "k8s_psat", Value: "agent_pod_uid:PODUID-2"},
		{Type: "k8s_psat", Value: "agent_node_ip:172.16.10.2"},
		{Type: "k8s_psat", Value: "agent_node_name:NODENAME-2"},
		{Type: "k8s_psat", Value: "agent_node_uid:NODEUID-2"},
	}, result.Selectors)
}
*/
func (a *attestorSuite) TestAttestFailsWithNoTokenInPayload() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverStream, err := a.serverAttestorClient.Attest(ctx)
	a.require.NoError(err, "attest failed")
	_, err = serverStream.Recv()

	a.require.Error(err)
	a.require.Contains(err.Error(), "rpc error: code = FailedPrecondition desc = missing token in attestation data")
}

type attestorSuite struct {
	serverPlugin         *Plugin
	serverAttestorClient *servernodeattestorv1.NodeAttestorPluginClient

	psatData  *common.PSATData
	token     string
	tokenPath string

	t       *testing.T
	require *require.Assertions
}

func (a *attestorSuite) loadServerPlugin() error {
	a.serverPlugin = new(Plugin)

	a.serverAttestorClient = new(servernodeattestorv1.NodeAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)
	plugintest.ServeInBackground(a.t, plugintest.Config{
		PluginServer:   servernodeattestorv1.NodeAttestorPluginServer(a.serverPlugin),
		PluginClient:   a.serverAttestorClient,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(a.serverPlugin)},
		ServiceClients: []pluginsdk.ServiceClient{configClient},
	})

	_, err := configClient.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: generateServerHCL(a.psatData),
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: common.TrustDomain,
		},
	})

	return err
}

func (a *attestorSuite) createAndWriteToken() {
	var err error
	dir := a.t.TempDir()
	a.token, err = common.CreatePSAT(a.psatData.Namespace, a.psatData.PodName)
	require.NoError(a.t, err)
	a.tokenPath = common.WriteToken(a.t, dir, common.TokenRelativePath, a.token)
}

func generateServerHCL(p *common.PSATData) string {
	return fmt.Sprintf(`
		clusters = {
			"%s" = {
				service_account_allow_list = ["%s:%s"]
				kube_config_file = ""
				allowed_pod_label_keys = ["PODLABEL-A"]
				allowed_node_label_keys = ["NODELABEL-A"]
			}
		}
		endorsement_ca_path = %q
		`, p.Cluster, p.Namespace, p.ServiceAccountName, common.EndorsementBundlePath)
}

type namespacedName struct {
	namespace string
	name      string
}

type apiClientConfig struct {
	status map[string]*authv1.TokenReviewStatus
	pods   map[namespacedName]*corev1.Pod
	nodes  map[string]*corev1.Node
}

type apiClientMock struct {
	mock.Mock
	apiClientConfig
}

func createAPIClientMock(psatData *common.PSATData, token string) *apiClientMock {
	clientMock := &apiClientMock{
		apiClientConfig: apiClientConfig{
			status: make(map[string]*authv1.TokenReviewStatus),
			pods:   make(map[namespacedName]*corev1.Pod),
			nodes:  make(map[string]*corev1.Node),
		},
	}

	clientMock.SetTokenStatus(token, createTokenStatus(psatData, true, defaultAudience))
	clientMock.SetPod(createPod(psatData.Namespace, psatData.PodName, psatData.NodeName, psatData.NodeIP))
	clientMock.SetNode(createNode(psatData.NodeName, psatData.NodeUID))

	return clientMock
}

func (c *apiClientMock) GetNode(ctx context.Context, nodeName string) (*corev1.Node, error) {
	node, ok := c.apiClientConfig.nodes[nodeName]
	if !ok {
		return nil, fmt.Errorf("node %s not found", nodeName)
	}
	return node, nil
}

func (c *apiClientMock) GetPod(ctx context.Context, namespace, podName string) (*corev1.Pod, error) {
	pod, ok := c.apiClientConfig.pods[namespacedName{namespace: namespace, name: podName}]
	if !ok {
		return nil, fmt.Errorf("pod %s/%s not found", namespace, podName)
	}
	return pod, nil
}

func (c *apiClientMock) ValidateToken(ctx context.Context, token string, audiences []string) (*authv1.TokenReviewStatus, error) {
	status, ok := c.apiClientConfig.status[token]
	if !ok {
		return nil, errors.New("no status configured by test for token")
	}
	if !cmp.Equal(status.Audiences, audiences) {
		return nil, fmt.Errorf("got audiences %q; expected %q", audiences, status.Audiences)
	}
	return status, nil
}

func (c *apiClientMock) SetNode(node *corev1.Node) {
	c.apiClientConfig.nodes[node.Name] = node
}

func (c *apiClientMock) SetPod(pod *corev1.Pod) {
	c.apiClientConfig.pods[namespacedName{namespace: pod.Namespace, name: pod.Name}] = pod
}

func (c *apiClientMock) SetTokenStatus(token string, status *authv1.TokenReviewStatus) {
	c.apiClientConfig.status[token] = status
}

func createPod(namespace, podName, nodeName string, hostIP string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      podName,
			Labels: map[string]string{
				"PODLABEL-A": "A",
				"PODLABEL-B": "B",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
		Status: corev1.PodStatus{
			HostIP: hostIP,
		},
	}
}

func createNode(nodeName, nodeUID string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
			UID:  types.UID(nodeUID),
			Labels: map[string]string{
				"NODELABEL-A": "A",
				"NODELABEL-B": "B",
			},
		},
	}
}

func createTokenStatus(tokenData *common.PSATData, authenticated bool, audience []string) *authv1.TokenReviewStatus {
	values := make(map[string]authv1.ExtraValue)
	values["authentication.kubernetes.io/pod-name"] = authv1.ExtraValue([]string{tokenData.PodName})
	values["authentication.kubernetes.io/pod-uid"] = authv1.ExtraValue([]string{tokenData.PodUID})
	return &authv1.TokenReviewStatus{
		Authenticated: authenticated,
		User: authv1.UserInfo{
			Username: fmt.Sprintf("system:serviceaccount:%s:%s", tokenData.Namespace, tokenData.ServiceAccountName),
			Extra:    values,
		},
		Audiences: audience,
	}
}
