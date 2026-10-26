package clientbuild

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

type Manifest struct {
	SchemaVersion   int           `json:"schema_version"`
	BuildID         uint          `json:"build_id"`
	AppName         string        `json:"app_name"`
	Server          string        `json:"server"`
	ServerKey       string        `json:"server_key"`
	APIServer       string        `json:"api_server"`
	UpstreamVersion string        `json:"upstream_version"`
	Platforms       []string      `json:"platforms"`
	Logo            *ManifestLogo `json:"logo,omitempty"`
}

type ManifestLogo struct {
	SHA256 string `json:"sha256"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

func NewManifest(
	buildID uint,
	profile *model.ClientBuildProfile,
	sg *model.ServerGroup,
	relayHost, publicBaseURL, version string,
	platforms []string,
) (Manifest, error) {
	if buildID == 0 || profile == nil || sg == nil {
		return Manifest{}, fmt.Errorf("%w: manifest requires a build, profile and server group", ErrInvalidInput)
	}
	appName, err := ValidateAppName(profile.AppName)
	if err != nil {
		return Manifest{}, err
	}
	normalized, err := ValidatePlatforms(platforms, SupportedPlatforms)
	if err != nil {
		return Manifest{}, err
	}
	server, err := DeriveServer(relayHost, sg.HbbsPort)
	if err != nil {
		return Manifest{}, err
	}
	if err := ValidateServerKey(sg.PubKey); err != nil {
		return Manifest{}, err
	}
	apiServer := strings.TrimRight(strings.TrimSpace(publicBaseURL), "/")
	if apiServer == "" {
		return Manifest{}, fmt.Errorf("%w: API server is required", ErrInvalidInput)
	}

	m := Manifest{
		SchemaVersion:   1,
		BuildID:         buildID,
		AppName:         appName,
		Server:          server,
		ServerKey:       sg.PubKey,
		APIServer:       apiServer,
		UpstreamVersion: version,
		Platforms:       normalized,
	}
	if profile.LogoPath != "" {
		if profile.LogoSHA256 == "" || profile.LogoWidth == 0 || profile.LogoHeight == 0 {
			return Manifest{}, fmt.Errorf("%w: profile logo metadata is incomplete", ErrInvalidInput)
		}
		m.Logo = &ManifestLogo{
			SHA256: profile.LogoSHA256,
			Width:  profile.LogoWidth,
			Height: profile.LogoHeight,
		}
	}
	return m, nil
}

func (m Manifest) JSON() ([]byte, error) {
	return json.Marshal(m)
}

func ParseManifest(raw string) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return Manifest{}, fmt.Errorf("%w: stored manifest is unreadable: %v", ErrInvalidInput, err)
	}
	return m, nil
}

func MarshalPlatforms(platforms []string) (string, error) {
	b, err := json.Marshal(platforms)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func ParsePlatforms(raw string) ([]string, error) {
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("%w: stored platforms are unreadable: %v", ErrInvalidInput, err)
	}
	return out, nil
}
