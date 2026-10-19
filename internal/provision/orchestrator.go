package provision

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// InstanceSpec describes one hbbs/hbbr pair to deploy.
type InstanceSpec struct {
	Name       string
	OrgID      uint
	HbbsPort   uint16
	HbbrPort   uint16
	PrivateKey string
	PublicKey  string
	Image      string
	RelayHost  string
	DataDir    string
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
	Deployed  []InstanceSpec
	Removed   []string
	FailWith  error
	RemoveErr error
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
	if m.RemoveErr != nil {
		return m.RemoveErr
	}
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
// surface small and the container layout is the only contract we need.
type DockerOrchestrator struct {
	OrgLabel  string
	RoleLabel string
}

// Deploy starts one hbbs and one hbbr container that share a per-org data
// directory holding the generated key pair.
func (d *DockerOrchestrator) Deploy(ctx context.Context, spec InstanceSpec) error {
	if spec.Image == "" {
		return errors.New("provision.image must be configured")
	}
	if spec.RelayHost == "" {
		return errors.New("provision.relayHost must be configured")
	}
	if spec.DataDir == "" {
		return errors.New("provision.dataDir must be configured")
	}
	// hbbs and hbbr share one contiguous block of five host ports; any other
	// pairing would publish the same host port twice.
	if spec.HbbrPort != spec.HbbsPort+hbbrPortOffset {
		return fmt.Errorf(
			"invalid port block: hbbr port %d must be hbbs port %d + %d",
			spec.HbbrPort, spec.HbbsPort, hbbrPortOffset,
		)
	}
	// Docker treats a relative bind source as a named volume on versions before
	// 23.0 and rejects it, so the directory is resolved before use.
	dataDir, err := resolveDataDir(spec.DataDir)
	if err != nil {
		return err
	}
	spec.DataDir = dataDir
	if spec.PrivateKey == "" || spec.PublicKey == "" {
		return errors.New("device keys are required")
	}
	if err := writeKeyFiles(spec); err != nil {
		return err
	}

	hbbsName := spec.Name + "-hbbs"
	if err := runDocker(ctx, d.hbbsArgs(spec, hbbsName)...); err != nil {
		return err
	}

	hbbrName := spec.Name + "-hbbr"
	if err := runDocker(ctx, d.hbbrArgs(spec, hbbrName)...); err != nil {
		// Do not leave a half-deployed pair behind.
		_ = runDocker(ctx, "rm", "-f", hbbsName)
		return fmt.Errorf("start hbbr: %w", err)
	}
	return nil
}

// hbbsArgs renders the hbbs container arguments. hbbs serves 21115 (NAT type
// test), 21116 (tcp and udp, id registry) and 21118 (web client websocket). The
// relay port belongs to hbbr.
func (d *DockerOrchestrator) hbbsArgs(spec InstanceSpec, name string) []string {
	relay := net.JoinHostPort(spec.RelayHost, strconv.Itoa(int(spec.HbbrPort)))
	return []string{
		"run", "-d", "--name", name,
		// Containers must survive a host or daemon restart: nothing else
		// restarts a deployed pair, and the row would still say deployed.
		"--restart", "unless-stopped",
		"--label", fmt.Sprintf("%s=%d", d.OrgLabel, spec.OrgID),
		"--label", fmt.Sprintf("%s=hbbs", d.RoleLabel),
		"-v", spec.DataDir + ":/root",
		"-p", fmt.Sprintf("%d:21115", spec.HbbsPort),
		"-p", fmt.Sprintf("%d:21116", spec.HbbsPort+1),
		"-p", fmt.Sprintf("%d:21116/udp", spec.HbbsPort+1),
		"-p", fmt.Sprintf("%d:21118", spec.HbbsPort+2),
		spec.Image,
		"hbbs", "-r", relay,
	}
}

// hbbrArgs renders the hbbr container arguments. hbbr serves 21117 (relay) and
// 21119 (web client relay websocket); 21118 belongs to hbbs.
func (d *DockerOrchestrator) hbbrArgs(spec InstanceSpec, name string) []string {
	return []string{
		"run", "-d", "--name", name,
		// Containers must survive a host or daemon restart: nothing else
		// restarts a deployed pair, and the row would still say deployed.
		"--restart", "unless-stopped",
		"--label", fmt.Sprintf("%s=%d", d.OrgLabel, spec.OrgID),
		"--label", fmt.Sprintf("%s=hbbr", d.RoleLabel),
		"-v", spec.DataDir + ":/root",
		"-p", fmt.Sprintf("%d:21117", spec.HbbrPort),
		"-p", fmt.Sprintf("%d:21119", spec.HbbrPort+1),
		spec.Image,
		"hbbr",
	}
}

// resolveDataDir makes the bind source absolute. Docker versions before 23.0
// read a relative path as a named volume and fail with "invalid volume name"
// instead of mounting the directory.
func resolveDataDir(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve data dir %q: %w", dir, err)
	}
	return abs, nil
}

// writeKeyFiles stores the key pair in the per-org data directory.
func writeKeyFiles(spec InstanceSpec) error {
	if err := os.MkdirAll(spec.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(spec.DataDir, "id_ed25519"), []byte(spec.PrivateKey), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(spec.DataDir, "id_ed25519.pub"), []byte(spec.PublicKey), 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

// Remove stops both containers of an instance.
func (d *DockerOrchestrator) Remove(ctx context.Context, name string) error {
	var errs []string
	for _, suffix := range []string{"-hbbs", "-hbbr"} {
		if err := runDockerAllowMissing(ctx, "rm", "-f", name+suffix); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("remove %s: %s", name, strings.Join(errs, "; "))
	}
	return nil
}

// Status implements Orchestrator.
func (d *DockerOrchestrator) Status(ctx context.Context, name string) (InstanceState, error) {
	running, err := runDockerOutput(ctx, "inspect", "-f", "{{.State.Running}}", name+"-hbbs")
	if err != nil {
		return InstanceState{Name: name}, nil
	}
	return InstanceState{Name: name, Running: strings.TrimSpace(running) == "true"}, nil
}

var execCommand = exec.CommandContext

func runDocker(ctx context.Context, args ...string) error {
	cmd := execCommand(ctx, "docker", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// runDockerAllowMissing ignores "no such container", keeping Remove idempotent.
func runDockerAllowMissing(ctx context.Context, args ...string) error {
	cmd := execCommand(ctx, "docker", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if strings.Contains(strings.ToLower(msg), "no such container") {
			return nil
		}
		return fmt.Errorf("docker %s: %w: %s", args[0], err, msg)
	}
	return nil
}

func runDockerOutput(ctx context.Context, args ...string) (string, error) {
	out, err := execCommand(ctx, "docker", args...).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
