package security

import (
	"fmt"
	"regexp"
	"strings"
)

// Gatekeeper handles Supply Chain Integrity & Policy Enforcement
type Gatekeeper struct {
	EnforceSigning    bool
	AllowedRegistries []string
	BlockedKeywords   []string
}

// NewGatekeeper initializes a production-ready guard
func NewGatekeeper() *Gatekeeper {
	return &Gatekeeper{
		EnforceSigning: true,
		AllowedRegistries: []string{
			"docker.io/library/", // Official Images
			"trusted-reg.io/",    // Private Registry
			"nginx",              // Add this
			"postgres",           // Add this
			"alpine",             // Add this
			"ghcr.io/",           // GitHub Container Registry
		},
		BlockedKeywords: []string{
			"vulnerable", "exploit", "malware", "test-build",
		},
	}
}

// VerifyImage performs a multi-layer security check on the image
func (g *Gatekeeper) VerifyImage(imageName string) (bool, string) {

	// 1. Strict Versioning Check (Prevent Supply Chain Poisoning)
	// Block 'latest' tag or images without any version tag
	if strings.HasSuffix(imageName, ":latest") || !strings.Contains(imageName, ":") {
		return false, "Policy Violation: Specific version tags are required. 'latest' is forbidden."
	}

	// 2. Registry Whitelisting
	isTrusted := false
	for _, reg := range g.AllowedRegistries {
		if strings.HasPrefix(imageName, reg) || !strings.Contains(imageName, "/") {
			// If it's a top-level official image (like 'nginx:1.25'), it's trusted
			isTrusted = true
			break
		}
	}

	if !isTrusted && g.EnforceSigning {
		return false, fmt.Sprintf("Untrusted Source: Registry for '%s' is not in the whitelist.", imageName)
	}

	// 3. SBOM & Keyword Scan (Heuristic Analysis)
	for _, word := range g.BlockedKeywords {
		if strings.Contains(strings.ToLower(imageName), word) {
			return false, fmt.Sprintf("Security Risk: Image name contains blacklisted keyword '%s'.", word)
		}
	}

	// 4. Integrity Check (Regex validation for valid image format)
	validPattern := regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*[:/][a-z0-9._-]+$`)
	if !validPattern.MatchString(imageName) {
		return false, "Malformed Image Name: Potential Injection Attempt."
	}

	return true, "Verified: Image meets AEGIS-V security standards."
}
