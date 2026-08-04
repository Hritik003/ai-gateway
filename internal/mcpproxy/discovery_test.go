// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0

package mcpproxy

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func TestMergeDiscoverResults_DefaultCapabilitiesPresent(t *testing.T) {
	merged := mergeDiscoverResults(nil)

	require.NotNil(t, merged.Capabilities)
	require.NotNil(t, merged.Capabilities.Tools)
	require.NotNil(t, merged.Capabilities.Resources)
	require.NotNil(t, merged.Capabilities.Prompts)
	require.NotNil(t, merged.Capabilities.Completions)
}

func TestMergeDiscoverResults_UnionsCapabilityFlags(t *testing.T) {
	results := []*mcp.DiscoverResult{
		{
			Capabilities: &mcp.ServerCapabilities{
				Tools:     &mcp.ToolCapabilities{ListChanged: true},
				Resources: &mcp.ResourceCapabilities{ListChanged: true},
			},
		},
		{
			Capabilities: &mcp.ServerCapabilities{
				Tools:     &mcp.ToolCapabilities{ListChanged: false},
				Resources: &mcp.ResourceCapabilities{Subscribe: true},
			},
		},
	}

	merged := mergeDiscoverResults(results)
	require.NotNil(t, merged.Capabilities)
	require.True(t, merged.Capabilities.Tools.ListChanged)
	require.True(t, merged.Capabilities.Resources.ListChanged)
	require.True(t, merged.Capabilities.Resources.Subscribe)
}
