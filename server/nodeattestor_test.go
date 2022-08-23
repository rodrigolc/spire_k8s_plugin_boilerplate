package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	servernodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/rodrigolc/psat-iid/pkg/common"
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
