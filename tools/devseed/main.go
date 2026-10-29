// Command devseed creates a disposable organization and login for local e2e or
// CI. It refuses to run unless PANEL_DEV_SEED=1, so pointing it at a real
// deployment by accident is not enough to seed an owner account.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "panel config file")
	flag.Parse()

	if os.Getenv("PANEL_DEV_SEED") != "1" {
		fmt.Fprintln(os.Stderr, "devseed: refusing to run without PANEL_DEV_SEED=1")
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "devseed:", err)
		os.Exit(1)
	}
	st, err := store.Open(cfg.Database)
	if err != nil {
		fmt.Fprintln(os.Stderr, "devseed:", err)
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()

	result, err := Seed(st.DB, Options{
		OrgName:       envOr("PANEL_SEED_ORG", "Acme 运维"),
		AdminEmail:    envOr("PANEL_SEED_EMAIL", "admin@acme.local"),
		AdminPassword: envOr("PANEL_SEED_PASSWORD", "admin12345"),
		OpsEmail:      envOr("PANEL_SEED_OPS_EMAIL", "ops@acme.local"),
		OpsPassword:   envOr("PANEL_SEED_OPS_PASSWORD", "ops12345"),
		AssetDir:      cfg.ClientBuild.AssetDir,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "devseed:", err)
		os.Exit(1)
	}
	fmt.Printf("devseed: org %d ready; owner %s; member %s\n",
		result.OrgID, result.AdminEmail, result.OpsEmail)
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
