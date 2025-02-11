// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/upgradetest"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var osquery = `
{
  "policy_ids": [
    "%s"
  ],
  "package": {
    "name": "osquery_manager",
    "version": "1.15.0"
  },
  "name": "osquery_manager-3",
  "description": "",
  "namespace": "",
  "inputs": {
    "osquery_manager-osquery": {
      "enabled": true,
      "streams": {
        "osquery_manager.action.responses": {
          "enabled": true,
          "vars": {}
        },
        "osquery_manager.result": {
          "enabled": true,
          "vars": {}
        }
      }
    }
  }
}`

func TestOsquery(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: FleetPrivileged,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			define.OS{
				Type: "windows",
				Arch: "amd64",
			},
		},
	})
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	// Start at the build version as we want to test the retry
	// logic that is in the build.
	startFixture, err := atesting.NewFixture(
		t,
		"8.16.1",
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	) // define.NewFixtureFromLocalBuild(t, "8.16.1")
	require.NoError(t, err)
	require.NoError(t, startFixture.Prepare(ctx))

	endFixture, err := atesting.NewFixture(
		t,
		"8.17.1",
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)
	require.NoError(t, endFixture.Prepare(ctx))

	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err)

	t.Logf("Testing Elastic Agent upgrade from %s to %s with Fleet...",
		define.Version(), endVersionInfo.Binary.String())

	policyUUID := uuid.Must(uuid.NewV4()).String()

	policy := kibana.AgentPolicy{
		Name:        "osquery-policy-" + policyUUID,
		Namespace:   "default",
		Description: t.Name() + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	keepGoing(ctx, t, info, startFixture, endFixture, policy, false)
}

func keepGoing(
	ctx context.Context,
	t *testing.T,
	info *define.Info,
	startFixture *atesting.Fixture,
	endFixture *atesting.Fixture,
	policy kibana.AgentPolicy,
	unprivileged bool) {

	kibClient := info.KibanaClient

	startVersionInfo, err := startFixture.ExecVersion(ctx)
	require.NoError(t, err)
	startParsedVersion, err := version.ParseVersion(startVersionInfo.Binary.String())
	require.NoError(t, err)
	endVersionInfo, err := endFixture.ExecVersion(ctx)
	require.NoError(t, err)
	endParsedVersion, err := version.ParseVersion(endVersionInfo.Binary.String())
	require.NoError(t, err)

	if unprivileged {
		if !upgradetest.SupportsUnprivileged(startParsedVersion, endParsedVersion) {
			t.Skipf("Either starting version %s or ending version %s doesn't support --unprivileged", startParsedVersion.String(), endParsedVersion.String())
		}
	}

	if startVersionInfo.Binary.Commit == endVersionInfo.Binary.Commit {
		t.Skipf("target version has the same commit hash %q", endVersionInfo.Binary.Commit)
		return
	}

	t.Log("Creating Agent policy...")
	policyResp, err := kibClient.CreatePolicy(ctx, policy)
	require.NoError(t, err, "failed creating policy")
	policy = policyResp.AgentPolicy

	addOsQueryIntegration(t, info, policy.ID)

	t.Log("Creating Agent enrollment API key...")
	createEnrollmentApiKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policyResp.ID,
	}
	enrollmentToken, err := kibClient.CreateEnrollmentAPIKey(ctx, createEnrollmentApiKeyReq)
	require.NoError(t, err, "failed creating enrollment API key")

	t.Log("Getting default Fleet Server URL...")
	fleetServerURL, err := fleettools.DefaultURL(ctx, kibClient)
	require.NoError(t, err, "failed getting Fleet Server URL")

	t.Logf("Installing Elastic Agent (unprivileged: %t)...", unprivileged)
	var nonInteractiveFlag bool
	if upgradetest.Version_8_2_0.Less(*startParsedVersion) {
		nonInteractiveFlag = true
	}
	installOpts := atesting.InstallOpts{
		NonInteractive: nonInteractiveFlag,
		Force:          true,
		EnrollOpts: atesting.EnrollOpts{
			URL:             fleetServerURL,
			EnrollmentToken: enrollmentToken.APIKey,
		},
		Privileged: !unprivileged,
	}
	output, err := startFixture.Install(ctx, &installOpts)
	require.NoError(t, err, "failed to install start agent [output: %s]", string(output))

	t.Log("Waiting for Agent to be correct version and healthy...")
	err = upgradetest.WaitHealthyAndVersion(ctx, startFixture, startVersionInfo.Binary, 2*time.Minute, 10*time.Second, t)
	require.NoError(t, err)

	t.Log("Waiting for enrolled Agent status to be online...")
	require.Eventually(t,
		check.FleetAgentStatus(
			ctx, t, kibClient, policyResp.ID, "online"),
		2*time.Minute,
		10*time.Second,
		"Agent status is not online")

	t.Logf("Upgrading from version \"%s-%s\" to version \"%s-%s\"...",
		startParsedVersion, startVersionInfo.Binary.Commit,
		endVersionInfo.Binary.String(), endVersionInfo.Binary.Commit)
	err = fleettools.UpgradeAgent(ctx, kibClient, policyResp.ID, endVersionInfo.Binary.String(), true)
	require.NoError(t, err)

	t.Log("Waiting from upgrade details to show up in Fleet")
	hostname, err := os.Hostname()
	require.NoError(t, err)
	var agent *kibana.AgentExisting
	require.Eventuallyf(t, func() bool {
		agent, err = fleettools.GetAgentByPolicyIDAndHostnameFromList(ctx, kibClient, policy.ID, hostname)
		return err == nil && agent.UpgradeDetails != nil
	},
		5*time.Minute, time.Second,
		"last error: %v. agent.UpgradeDetails: %s",
		err, agentUpgradeDetailsString(agent))

	// wait for the watcher to show up
	t.Logf("Waiting for upgrade watcher to start...")
	err = upgradetest.WaitForWatcher(ctx, 5*time.Minute, 10*time.Second)
	require.NoError(t, err, "upgrade watcher did not start")
	t.Logf("Upgrade watcher started")

	// wait for the agent to be healthy and correct version
	err = upgradetest.WaitHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary, 2*time.Minute, 10*time.Second, t)
	require.NoError(t, err)

	t.Log("Waiting for enrolled Agent status to be online...")
	require.Eventually(t, check.FleetAgentStatus(ctx, t, kibClient, policyResp.ID, "online"), 10*time.Minute, 15*time.Second, "Agent status is not online")

	// wait for version
	require.Eventually(t, func() bool {
		t.Log("Getting Agent version...")
		newVersion, err := fleettools.GetAgentVersion(ctx, kibClient, policyResp.ID)
		if err != nil {
			t.Logf("error getting agent version: %v", err)
			return false
		}
		return endVersionInfo.Binary.Version == newVersion
	}, 5*time.Minute, time.Second)

	t.Logf("Waiting for upgrade watcher to finish...")
	err = upgradetest.WaitForNoWatcher(ctx, 2*time.Minute, 10*time.Second, 1*time.Minute+15*time.Second)
	require.NoError(t, err)
	t.Logf("Upgrade watcher finished")

	// now that the watcher has stopped lets ensure that it's still the expected
	// version, otherwise it's possible that it was rolled back to the original version
	err = upgradetest.CheckHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary)
	assert.NoError(t, err)
}

func addOsQueryIntegration(t *testing.T, info *define.Info, policyID string) {
	policyJSON := fmt.Sprintf(osquery, policyID)

	// Call Kibana to create the policy.
	// Docs: https://www.elastic.co/guide/en/fleet/current/fleet-api-docs.html#create-integration-policy-api
	resp, err := info.KibanaClient.Connection.Send(
		http.MethodPost,
		"/api/fleet/package_policies",
		nil,
		nil,
		bytes.NewBufferString(policyJSON))
	if err != nil {
		t.Fatalf("could not execute request to Kibana/Fleet: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		// On error dump the whole request response so we can easily spot
		// what went wrong.
		t.Errorf("received a non 200-OK when adding package to policy. "+
			"Status code: %d", resp.StatusCode)
		respDump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			t.Fatalf("could not dump error response from Kibana: %s", err)
		}
		// Make debugging as easy as possible
		t.Log("================================================================================")
		t.Log("Kibana error response:")
		t.Log(string(respDump))
		t.Log("================================================================================")
		t.Log("Rendered policy:")
		t.Log(policyJSON)
		t.Log("================================================================================")
		t.FailNow()
	}
}
