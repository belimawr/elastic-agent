//go:build integration

package upgrade

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/component"
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

const mockAgentScriptTpl = `#!/bin/sh
echo "reexec-called" >> %s
exit 0
`

// SetupPathsForTesting creates all folders/files necessary for the integration
// tests on this file. It also sets some global values using the `paths` package.
//
// The returned values are:
// - The temporary directory
// - The reexec log file.
func setupPathsForTesing(t *testing.T) (string, string) {
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

	reexecLogFile := filepath.Join(targetDirectory, "reexec-called")
	mockAgentScript := fmt.Sprintf(mockAgentScriptTpl, reexecLogFile)
	if _, err := agentFile.WriteString(mockAgentScript); err != nil {
		t.Fatal(err)
	}
	if err := agentFile.Close(); err != nil {
		t.Fatalf("cannot close elastic-agent-script': %s", err)
	}

	t.Logf("Paths: Download: %s, Install: %s, Home: %s", paths.Downloads(), paths.Install(), paths.Home())

	return targetDirectory, reexecLogFile
}

// setLogLevel configures logp in development mode if -test.v is true
//
// This helps a lot to debug failing tests
func setLogLevel(t *testing.T) {
	t.Helper()
	if !flag.Parsed() {
		t.Fatal("not parsed")
	}

	f := flag.CommandLine.Lookup("test.v")
	if f == nil {
		t.Fatal("test flag not set")
	}

	strVal := f.Value.String()
	verbose, err := strconv.ParseBool(strVal)
	if err != nil {
		// This should never happen because the testing package already ensures
		// that test.v is a valid boolean.
		t.Logf("cannot parse test.v='%s' as boolean, disabling logging.", strVal)
	}

	if verbose {
		logp.DevelopmentSetup()
		t.Log("logp level set as DevelopmentSetup")
	}
}

// TestUpgrade unit-tests upgrader.TestUpgrade
// go test -v -tags=integration -run=Upgrade -ldflags="-X github.com/elastic/elastic-agent/internal/pkg/release.allowEmptyPgp=true -X github.com/elastic/elastic-agent/internal/pkg/release.allowUpgrade=true"
// dlv test --build-flags="-ldflags='-X github.com/elastic/elastic-agent/internal/pkg/release.allowEmptyPgp=true -X github.com/elastic/elastic-agent/internal/pkg/release.allowUpgrade=true' -tags=integration" . -- -test.run=Upgrade
func TestUpgrade(t *testing.T) {
	setLogLevel(t)
	setupPathsForTesing(t)

	agentInfo := &info.AgentInfo{}

	upgrader := NewUpgrader(logp.L(), artifact.DefaultConfig(), agentInfo)
	callback, err := upgrader.Upgrade(context.Background(), "8.7.0", "file:///home/tiago/sandbox/dropPath", nil)
	if err != nil {
		t.Fatalf("could not execute upgrade: %s", err)
	}

	if callback != nil {
		if err := callback(); err != nil {
			t.Fatalf("error calling callback: %s", err)
		}
	}
}

// TestCoordinator unit-tests cordinator.Upgrade
// go test -v -tags=integration -run=Coordinator -ldflags="-X github.com/elastic/elastic-agent/internal/pkg/release.allowEmptyPgp=true -X github.com/elastic/elastic-agent/internal/pkg/release.allowUpgrade=true"
// dlv test --build-flags="-ldflags='-X github.com/elastic/elastic-agent/internal/pkg/release.allowEmptyPgp=true -X github.com/elastic/elastic-agent/internal/pkg/release.allowUpgrade=true' -tags=integration" . -- -test.run=Coordinator
func TestCoordinator(t *testing.T) {
	setLogLevel(t)
	_, reexecLogFile := setupPathsForTesing(t)

	agentInfo := &info.AgentInfo{}

	upgrader := NewUpgrader(logp.L(), artifact.DefaultConfig(), agentInfo)
	coord := coordinator.New(logp.L(), agentInfo, component.RuntimeSpecs{}, nopReExec{}, upgrader, nil, nil, nil, nil, nil)

	err := coord.Upgrade(context.Background(), "8.7.0", "file:///home/tiago/sandbox/dropPath", nil)
	if err != nil {
		t.Fatalf("could not execute upgrade: %s", err)
	}

	if _, err := os.Stat(reexecLogFile); err != nil {
		t.Fatalf("re-exec log file does not exisit, this usually means the"+
			" reexec operation/callback did not run successfully: %s", err.Error())
	}
}
