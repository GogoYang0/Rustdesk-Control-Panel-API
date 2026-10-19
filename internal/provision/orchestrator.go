package provision

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// InstanceSpec describes one hbbs/hbbr pair to deploy.
type InstanceSpec struct {
	Name       string
	OrgID      uint
	HbbsPort   uint16
	HbbrPort   uint16
	PrivatePEM string
}

// InstanceState is the observed state of one deployment.
type InstanceState struct {
	Name    string
	Running bool
}

// Orchestrator deploys and removes hbbs/hbbr instances.
type Orchestrator interface {
	Deploy(ctx context.Context, spec InstanceSpec) error
	Remove(ctx context.Context, name string) error
	Status(ctx context.Context, name string) (InstanceState, error)
}

// MockOrchestrator records calls for tests and can simulate failures.
type MockOrchestrator struct {
	Deployed []InstanceSpec
	Removed  []string
	FailWith error
}

// Deploy implements Orchestrator.
func (m *MockOrchestrator) Deploy(_ context.Context, spec InstanceSpec) error {
	if m.FailWith != nil {
		return m.FailWith
	}
	m.Deployed = append(m.Deployed, spec)
	return nil
}

// Remove implements Orchestrator.
func (m *MockOrchestrator) Remove(_ context.Context, name string) error {
	m.Removed = append(m.Removed, name)
	return nil
}

// Status implements Orchestrator.
func (m *MockOrchestrator) Status(_ context.Context, name string) (InstanceState, error) {
	for _, d := range m.Deployed {
		if d.Name == name {
			return InstanceState{Name: name, Running: true}, nil
		}
	}
	return InstanceState{Name: name}, nil
}

// DockerOrchestrator drives the docker CLI.
//
// The SDK is intentionally not vendored in M1: the CLI keeps the dependency
// surface small and the compose labels are the only contract we need. The
// interface stays the same, so swapping in the SDK later is local to this file.
type DockerOrchestrator struct {
	OrgLabel   string
	RoleLabel  string
	RelayHost  string
	ComposeDir string
}

// Deploy implements Orchestrator.
func (d *DockerOrchestrator) Deploy(ctx context.Context, spec InstanceSpec) error {
	args := []string{
		"run", "-d", "--name", spec.Name,
		"--label", fmt.Sprintf("%s=%d", d.OrgLabel, spec.OrgID),
		"--label", fmt.Sprintf("%s=hbbs-hbbr", d.RoleLabel),
		"-p", fmt.Sprintf("%d:21116/udp", spec.HbbsPort),
		"-p", fmt.Sprintf("%d:21116", spec.HbbsPort),
		"-p", fmt.Sprintf("%d:21115", spec.HbbsPort),
		"-p", fmt.Sprintf("%d:21117", spec.HbbrPort),
		"-p", fmt.Sprintf("%d:21118", spec.HbbrPort),
		"-p", fmt.Sprintf("%d:21119", spec.HbbrPort),
		"rustdesk/rustdesk-server:latest",
		"hbbs", "-r", fmt.Sprintf("%s:%d", d.relayHost(), spec.HbbrPort),
	}
	return runDocker(ctx, args...)
}

// Remove implements Orchestrator.
func (d *DockerOrchestrator) Remove(ctx context.Context, name string) error {
	if err := runDocker(ctx, "rm", "-f", name); err != nil {
		return fmt.Errorf("remove %s: %w", name, err)
	}
	return nil
}

// Status implements Orchestrator.
func (d *DockerOrchestrator) Status(ctx context.Context, name string) (InstanceState, error) {
	out, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Running}}", name).Output()
	if err != nil {
		return InstanceState{Name: name}, nil
	}
	return InstanceState{Name: name, Running: strings.TrimSpace(string(out)) == "true"}, nil
}

func runDocker(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// relayHost falls back to loopback when the deployment runs on one host.
func (d *DockerOrchestrator) relayHost() string {
	if d.RelayHost == "" {
		return "127.0.0.1"
	}
	return d.RelayHost
}
