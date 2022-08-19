package common

import (
	"net/url"
	"strings"

	common_psat "github.com/spiffe/spire/pkg/common/plugin/k8s"
)

const (
	PluginName = "k8s_psat"
)

type AttestationRequest struct {
	PSATAttestationData common_psat.PSATAttestationData
}

func AgentID(trustDomain string) string {
	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   strings.Join([]string{"spire", "agent", "psat"}, "/"),
	}
	return u.String()
}
