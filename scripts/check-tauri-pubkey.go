//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Verifies that tauri.conf.json has a non-empty updater pubkey whenever
// TAURI_SIGNING_PRIVATE_KEY is configured. Full key-pair derivation isn't
// possible without the passphrase and minisign decryption, so we check the
// necessary condition: key present ↔ pubkey present.
func main() {
	privKey := os.Getenv("TAURI_SIGNING_PRIVATE_KEY")
	if privKey == "" {
		fmt.Println("TAURI_SIGNING_PRIVATE_KEY not configured; skipping pubkey check")
		return
	}

	conf, err := os.ReadFile("src-tauri/tauri.conf.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var cfg struct {
		Plugins struct {
			Updater struct {
				Pubkey string `json:"pubkey"`
			} `json:"updater"`
		} `json:"plugins"`
		App struct {
			Updater struct {
				Pubkey string `json:"pubkey"`
			} `json:"updater"`
		} `json:"app"`
	}
	if err := json.Unmarshal(conf, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pubkey := cfg.Plugins.Updater.Pubkey
	if pubkey == "" {
		pubkey = cfg.App.Updater.Pubkey
	}

	if pubkey == "" {
		fmt.Fprintln(os.Stderr, "ERROR: TAURI_SIGNING_PRIVATE_KEY is set but tauri.conf.json has no updater pubkey — set plugins.updater.pubkey before shipping")
		os.Exit(1)
	}
	fmt.Println("pubkey OK — updater pubkey present in tauri.conf.json")
}
