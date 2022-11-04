//go:build integration

package upgrade

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/reporter"
	"github.com/elastic/elastic-agent/internal/pkg/reporter/noop"
	//	_ "github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/noop" //acker "github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/noop"
)

type mockAction struct {
	version     string
	sourceURI   string
	fleetAction *fleetapi.ActionUpgrade
}

func (m mockAction) Version() string {
	return m.version
}

func (m mockAction) SourceURI() string {
	return m.sourceURI
}

func (m mockAction) FleetAction() *fleetapi.ActionUpgrade {
	return m.fleetAction
}

type nopReExec struct{}

func (m nopReExec) ReExec(shutdownCallback reexec.ShutdownCallbackFn, argOverrides ...string) {}

type nopAcker struct{}

func (n nopAcker) Ack(ctx context.Context, action fleetapi.Action) error { return nil }
func (n nopAcker) Commit(ctx context.Context) error                      { return nil }

const mockAgentScript = `#!/bin/sh
echo foo
exit 0
`

// SetupPathsForTesting creates all folders/files necessary for the integration
// tests on this file. It also sets some global values using the `paths` package.
func setupPathsForTesing(t *testing.T) {
	t.Helper()
	targetDirectory := t.TempDir()

	paths.SetDownloads(targetDirectory)
	paths.SetInstall(targetDirectory)
	paths.SetTop(targetDirectory)
	paths.SetVersionHome(true)

	if err := os.MkdirAll(paths.Home(), 0o755); err != nil {
		t.Fatalf("cannot create elastic-agent home path '%s': %s", paths.Home(), err)
	}

	mockAgent := filepath.Join(paths.Home(), "elastic-agent")
	agentFile, err := os.OpenFile(mockAgent, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatalf("cannot create 'elastic-agent binary' file: %s", err)
	}

	//	fmt.Fprint(agentFile, mockAgentScript)
	if _, err := agentFile.WriteString(mockAgentScript); err != nil {
		t.Fatal(err)
	}
	if err := agentFile.Close(); err != nil {
		t.Fatalf("cannot close elastic-agent-script': %s", err)
	}

	t.Logf("Paths: Download: %s, Install: %s, Home: %s", paths.Downloads(), paths.Install(), paths.Home())
}

// TestUpgrade unit-tests upgrader.TestUpgrade
// go test -v -tags=integration -run=Upgrade -ldflags="-X github.com/elastic/elastic-agent/internal/pkg/release.allowUpgrade=true -X github.com/elastic/elastic-agent/version.commit=188688"
// dlv test --build-flags="-ldflags='-X github.com/elastic/elastic-agent/internal/pkg/release.allowUpgrade=true -X github.com/elastic/elastic-agent/version.commit=188688' -tags=integration" . -- -test.run=Upgrade
func TestUpgrade(t *testing.T) {
	logp.DevelopmentSetup()
	setupPathsForTesing(t)

	// if err := os.Mkdir(filepath.Join(os.Getwd(), "elastic-agent-"+version.Commit()), 0750); err != nil {
	// 	t.Fatalf("cannot create dir: %s", err)
	// }

	agentInfo := &info.AgentInfo{}

	reporter := reporter.NewReporter(context.TODO(), logp.L(), agentInfo, noop.NewReporter())

	upgrader := NewUpgrader(
		agentInfo,
		artifact.DefaultConfig(),
		logp.L(), // I hate global state!
		[]context.CancelFunc{},
		nopReExec{}, //reexecManager
		nopAcker{},  //acker
		reporter,    //stateReporter
		nil,         //capabilities.Capability
	)

	callback, err := upgrader.Upgrade(context.Background(), mockAction{version: "8.4.0"}, false)
	if err != nil {
		os.Exit(1)
		t.Fatalf("could not execute upgrade: %s", err)
	}

	if callback != nil {
		if err := callback(); err != nil {
			t.Fatalf("error calling callback: %s", err)
		}
	}
}
