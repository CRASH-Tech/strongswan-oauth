package ipsec

import (
	"log"
	"os/exec"
	"strings"
)

// LoadCreds runs "swanctl --load-creds" to reload secrets and certificates
// without disrupting active connections.
func LoadCreds(caller string) {
	runSwanctl(caller, "--load-creds")
}

// LoadAll runs both --load-creds, --load-pools, --load-conns — use after startup or
// when connection config may have changed.
func LoadAll(caller string) {
	runSwanctl(caller, "--load-creds")
	runSwanctl(caller, "--load-pools")
	runSwanctl(caller, "--load-conns")
}

// RereadAll is an alias for LoadAll kept for call-site compatibility.
func RereadAll(caller string) {
	LoadAll(caller)
}

func runSwanctl(caller, arg string) {
	out, err := exec.Command("swanctl", arg).CombinedOutput()
	if err != nil {
		log.Printf("%s: swanctl %s error: %v: %s", caller, arg, err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("%s: swanctl %s ok: %s", caller, arg, strings.TrimSpace(string(out)))
}
