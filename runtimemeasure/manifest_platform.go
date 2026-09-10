package runtimemeasure

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// manifestSchemaVersion is the build-manifest schema this package reads. The
// builder refuses to emit any other version rather than migrating, so an older
// manifest is a rebuild, not a compatibility shim.
const manifestSchemaVersion = 3

// manifestHeader is the platform-declaring subset of a build manifest. The
// registers themselves live under "tdx" / "snp_variants" and are read by the
// loaders.
type manifestHeader struct {
	Version int `json:"version"`
	Build   struct {
		Platform string `json:"platform"`
	} `json:"build"`
}

// ManifestFamilies reports which TEE families a build manifest declares in its
// "build.platform" field: one family, or both for a "multi" image built for
// SNP and TDX from one source tree. A multi manifest lists TDX first.
//
// It reads the declaration, not the measurements: a manifest can name a
// platform whose pins fail to load. A caller that only needs the pins uses
// [LoadImageManifest], which detects the family from the pins themselves and
// works on hand-written manifests with no header at all.
func ManifestFamilies(path string) ([]teetypes.Family, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read image manifest: %w", err)
	}
	var h manifestHeader
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("image manifest %s is not a JSON object: %w", path, err)
	}
	if h.Version != manifestSchemaVersion {
		return nil, fmt.Errorf("image manifest %s is schema version %d, want %d — rebuild it with the current builder", path, h.Version, manifestSchemaVersion)
	}
	switch h.Build.Platform {
	case "snp":
		return []teetypes.Family{teetypes.FamilySNP}, nil
	case "tdx":
		return []teetypes.Family{teetypes.FamilyTDX}, nil
	case "multi":
		return []teetypes.Family{teetypes.FamilyTDX, teetypes.FamilySNP}, nil
	default:
		return nil, fmt.Errorf("image manifest %s has platform %q, want \"snp\", \"tdx\" or \"multi\"", path, h.Build.Platform)
	}
}

// LoadImageManifest loads whichever image pin a manifest carries, so a caller
// pinning "the image this node should be running" need not know its platform.
// The manifest's shape decides: a TDX build publishes the mrtd/rtmr1/rtmr2
// tuple, an SNP build publishes the per-SMP launch digests.
//
// A "multi" manifest carries both, and TDX is tried first, so a multi manifest
// loads as TDX and a file that is neither reports why it is not a TDX pin. Load
// the SNP half of a multi image explicitly with [LoadImageManifestFor].
func LoadImageManifest(path string) (ImageIdentity, error) {
	pins, tdxErr := loadTDXImageManifest(path)
	if tdxErr == nil {
		return pins, nil
	}
	snpPins, snpErr := loadSNPImageManifest(path)
	if snpErr != nil {
		return nil, tdxErr
	}
	return snpPins, nil
}

// LoadImageManifestFor loads the half of a manifest that family names, for a
// caller that already knows which family it is pinning — the SNP half of a
// "multi" build, say, which [LoadImageManifest] reads as TDX.
//
// A family this package has no manifest shape for is an error, so a caller
// never ends up with an empty pin set that reads as "nothing to enforce".
func LoadImageManifestFor(path string, family teetypes.Family) (ImageIdentity, error) {
	switch family {
	case teetypes.FamilySNP:
		return loadSNPImageManifest(path)
	case teetypes.FamilyTDX:
		return loadTDXImageManifest(path)
	default:
		return nil, fmt.Errorf("image manifest %s: tee family %q has no manifest shape, want %q or %q",
			path, family, teetypes.FamilySNP, teetypes.FamilyTDX)
	}
}
