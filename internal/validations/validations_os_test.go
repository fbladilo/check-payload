package validations

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/openshift/check-payload/internal/types"
)

func TestValidateOS(t *testing.T) {
	certified := []string{"Red Hat Enterprise Linux release 9.6 (Plow)"}

	cfgWith := func(distributions []string) *types.Config {
		return &types.Config{
			ConfigFile: types.ConfigFile{
				CertifiedDistributions: distributions,
			},
		}
	}

	writeReleaseFile := func(t *testing.T, root, content string) {
		t.Helper()
		etc := filepath.Join(root, "etc")
		if err := os.MkdirAll(etc, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(etc, "redhat-release"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name          string
		setup         func(t *testing.T, root string)
		distributions []string
		wantErr       error
		wantWarning   bool
		wantCertified bool
	}{
		{
			name:          "missing release file classified as ErrDistributionFileMissing",
			setup:         func(*testing.T, string) {},
			distributions: certified,
			wantErr:       types.ErrDistributionFileMissing,
		},
		{
			name: "dangling symlink classified as ErrDistributionFileMissing",
			setup: func(t *testing.T, root string) {
				etc := filepath.Join(root, "etc")
				if err := os.MkdirAll(etc, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/usr/lib/system-release", filepath.Join(etc, "redhat-release")); err != nil {
					t.Fatal(err)
				}
			},
			distributions: certified,
			wantErr:       types.ErrDistributionFileMissing,
		},
		{
			name: "certified distribution",
			setup: func(t *testing.T, root string) {
				writeReleaseFile(t, root, "Red Hat Enterprise Linux release 9.6 (Plow)")
			},
			distributions: certified,
			wantCertified: true,
		},
		{
			name: "uncertified distribution",
			setup: func(t *testing.T, root string) {
				writeReleaseFile(t, root, "Fedora release 42 (Adams)")
			},
			distributions: certified,
		},
		{
			name:          "empty certified distributions warns",
			setup:         func(*testing.T, string) {},
			distributions: nil,
			wantErr:       types.ErrCertifiedDistributionsEmpty,
			wantWarning:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tc.setup(t, root)

			info := ValidateOS(cfgWith(tc.distributions), root)

			if tc.wantErr != nil {
				if info.Error == nil {
					t.Fatalf("expected error %v, got nil", tc.wantErr)
				}
				if !errors.Is(info.Error.GetError(), tc.wantErr) {
					t.Errorf("expected error %v, got %v", tc.wantErr, info.Error.GetError())
				}
				if gotWarning := info.Error.Level == types.Warning; gotWarning != tc.wantWarning {
					t.Errorf("expected warning=%v, got level %v", tc.wantWarning, info.Error.Level)
				}
				return
			}
			if info.Error != nil {
				t.Fatalf("expected no error, got %v", info.Error)
			}
			if info.Certified != tc.wantCertified {
				t.Errorf("expected certified=%v, got %v", tc.wantCertified, info.Certified)
			}
		})
	}
}

func TestValidateModuleArtifacts(t *testing.T) {
	ctx := context.Background()

	baseCfg := func(modules []types.FipsModule) *types.Config {
		return &types.Config{
			ConfigFile: types.ConfigFile{
				FIPSCertifiedModules: modules,
			},
		}
	}

	t.Run("no modules in use returns nil", func(t *testing.T) {
		dir := t.TempDir()
		cfg := baseCfg([]types.FipsModule{
			{Module: "openssl", CertifiedArtifact: "openssl-fips-provider"},
		})
		if ve := ValidateModuleArtifacts(ctx, cfg, dir, nil); ve != nil {
			t.Errorf("expected nil, got %v", ve)
		}
	})

	t.Run("module matched + RPM missing", func(t *testing.T) {
		dir := t.TempDir()
		cfg := baseCfg([]types.FipsModule{
			{Module: "openssl", CertifiedArtifact: "openssl-fips-provider"},
		})
		ve := ValidateModuleArtifacts(ctx, cfg, dir, []string{"openssl"})
		if ve == nil {
			t.Error("expected error when RPM missing")
		}
	})

	t.Run("unmatched module returns nil", func(t *testing.T) {
		dir := t.TempDir()
		cfg := baseCfg([]types.FipsModule{
			{Module: "go", CertifiedArtifact: "go-std"},
		})
		if ve := ValidateModuleArtifacts(ctx, cfg, dir, []string{"openssl"}); ve != nil {
			t.Errorf("expected nil when no config module matches, got %v", ve)
		}
	})
}

func TestValidateModule(t *testing.T) {
	ctx := context.Background()

	baseCfg := func(modules []types.FipsModule) *types.Config {
		return &types.Config{
			ConfigFile: types.ConfigFile{
				FIPSCertifiedModules: modules,
			},
		}
	}

	t.Run("binary source skips image check", func(t *testing.T) {
		dir := t.TempDir()
		cfg := baseCfg([]types.FipsModule{
			{Module: "go", ArtifactSource: "binary", CertifiedArtifact: "crypto/fips140"},
		})
		if ve := ValidateModule(ctx, cfg, dir, "go"); ve != nil {
			t.Errorf("expected nil for binary source, got %v", ve)
		}
	})

	t.Run("no artifact and no host lib fails", func(t *testing.T) {
		dir := t.TempDir()
		cfg := baseCfg([]types.FipsModule{
			{
				Module:            "openssl",
				ArtifactSource:    "image",
				CertifiedArtifact: "openssl-fips-provider",
			},
		})
		if ve := ValidateModule(ctx, cfg, dir, "openssl"); ve == nil {
			t.Error("expected error when no artifact and no host lib")
		}
	})

	t.Run("anyPathExists gates CheckArtifact", func(t *testing.T) {
		dir := t.TempDir()
		paths := []string{"/usr/lib64/ossl-modules/fips.so"}

		if anyPathExists(dir, paths) {
			t.Error("expected false when fips.so absent")
		}
		createDirAndFile(t, filepath.Join(dir, "usr", "lib64", "ossl-modules"))
		if !anyPathExists(dir, paths) {
			t.Error("expected true when fips.so present")
		}
	})
}
