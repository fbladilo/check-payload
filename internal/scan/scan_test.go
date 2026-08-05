package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/openshift/api/image/v1"
	"github.com/openshift/check-payload/internal/types"
)

var (
	baseConfig = &types.Config{
		OutputFormat: "table",
		Parallelism:  1,
		TimeLimit:    30 * time.Second,
		Verbose:      true,
		ConfigFile: types.ConfigFile{
			PayloadIgnores:         make(map[string]types.IgnoreLists),
			TagIgnores:             make(map[string]types.IgnoreLists),
			RPMIgnores:             make(map[string]types.IgnoreLists),
			CertifiedDistributions: []string{"Red Hat Enterprise Linux release 9.2 (Plow)", "Red Hat Enterprise Linux CoreOS release 4.12"},
		},
	}
	moduleConfig94 = &types.Config{
		OutputFormat: "table",
		Parallelism:  1,
		TimeLimit:    30 * time.Second,
		Verbose:      true,
		ConfigFile: types.ConfigFile{
			PayloadIgnores:         make(map[string]types.IgnoreLists),
			TagIgnores:             make(map[string]types.IgnoreLists),
			RPMIgnores:             make(map[string]types.IgnoreLists),
			CertifiedDistributions: []string{"Red Hat Enterprise Linux release 9.4 (Plow)"},
			FIPSCertifiedModules: []types.FipsModule{
				{
					Module:            "openssl",
					ArtifactSource:    "image",
					CertifiedArtifact: "openssl-fips-provider",
					CertifiedArtifactPaths: []string{
						"/usr/lib64/ossl-modules/fips.so",
						"/usr/lib/ossl-modules/fips.so",
					},
				},
				{
					Module:                      "go",
					ArtifactSource:              "binary",
					CertifiedArtifact:           "crypto/fips140",
					CertifiedArtifactMinVersion: "v1.0.0",
				},
			},
		},
	}
	nativeFIPSConfig = &types.Config{
		OutputFormat: "table",
		Parallelism:  1,
		TimeLimit:    30 * time.Second,
		Verbose:      true,
		ConfigFile: types.ConfigFile{
			PayloadIgnores:         make(map[string]types.IgnoreLists),
			TagIgnores:             make(map[string]types.IgnoreLists),
			RPMIgnores:             make(map[string]types.IgnoreLists),
			CertifiedDistributions: []string{"Red Hat Enterprise Linux release 9.6 (Plow)"},
			FIPSCertifiedModules: []types.FipsModule{
				{
					Module:            "openssl",
					ArtifactSource:    "image",
					CertifiedArtifact: "openssl-fips-provider",
					CertifiedArtifactPaths: []string{
						"/usr/lib64/ossl-modules/fips.so",
						"/usr/lib/ossl-modules/fips.so",
					},
				},
				{
					Module:                      "go",
					ArtifactSource:              "binary",
					CertifiedArtifact:           "crypto/fips140",
					CertifiedArtifactMinVersion: "v1.0.0",
				},
			},
		},
	}
	ignoredOsConfig = &types.Config{
		OutputFormat: "table",
		Parallelism:  1,
		TimeLimit:    30 * time.Second,
		Verbose:      true,
		Components:   []string{"UnsupportedOperatingSystemIgnored"},
		ConfigFile: types.ConfigFile{
			PayloadIgnores: map[string]types.IgnoreLists{
				"UnsupportedOperatingSystemIgnored": {
					FilterFiles: make([]string, 0),
					FilterDirs:  make([]string, 0),
					ErrIgnores: types.ErrIgnoreList{{
						Error: types.KnownError{Err: types.ErrOSNotCertified},
						Files: make([]string, 0),
						Dirs:  make([]string, 0),
						// see scan.go line 193: the mock creates a Tag.Name = ""
						Tags: []string{""},
					}},
				},
			},
			RPMIgnores:             make(map[string]types.IgnoreLists),
			CertifiedDistributions: []string{"Red Hat Enterprise Linux release 12388.3 (Plow)"},
		},
	}
)

// TestRunLocalScan tests the RunLocalScan function with mock unpacked directories.
func TestRunLocalScan(t *testing.T) {
	// Define test cases
	testCases := []struct {
		name                string
		mockUnpackedDirPath string
		mockConfig          *types.Config
		expectedResult      bool // true if scan should pass, false if it should fail
	}{
		{"GoodMockUnpackedDir", "../../test/resources/mock_unpacked_dir-1", baseConfig, true},
		{"BadMockUnpackedDir", "../../test/resources/mock_unpacked_dir-2", baseConfig, false},
		{"BadMockUnsupportedOperatingSystem", "../../test/resources/mock_unsupported_os", baseConfig, false},
		{"UnsupportedOperatingSystemIgnored", "../../test/resources/mock_unsupported_os", ignoredOsConfig, true},
		{"SymlinkedOsRelease", "../../test/resources/mock_os_symlinked", baseConfig, true},
		{"ModuleModeRHEL94WithProvider", "../../test/resources/mock_unpacked_dir_9_4", moduleConfig94, true},
		{"PIE_Go126_s390x", "../../test/resources/mock_unpacked_dir_pie_s390x", baseConfig, true},
		{"NativeFIPSBinary", "../../test/resources/mock_native_fips", nativeFIPSConfig, true},
	}
	// Iterate over test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup context and config
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Run the local scan.
			results := RunLocalScan(ctx, tc.mockConfig, tc.mockUnpackedDirPath)

			// Check if results meet expected criteria
			passed := !IsFailed(results)
			if passed != tc.expectedResult {
				t.Errorf("Test %s: expected pass = %t, got pass = %t", tc.name, tc.expectedResult, passed)
			}
		})
	}
}

// TestRunLocalScanDataOnlyImage covers FROM-scratch data-only images (no OS
// layer, no binaries): without tag identity the scan fails with
// ErrDistributionFileMissing; with --tag and a matching tag ignore the OS
// validation is skipped.
func TestRunLocalScanDataOnlyImage(t *testing.T) {
	tagIgnoredOsConfig := func(localTag string) *types.Config {
		return &types.Config{
			OutputFormat: "table",
			Parallelism:  1,
			TimeLimit:    30 * time.Second,
			LocalTag:     localTag,
			ConfigFile: types.ConfigFile{
				PayloadIgnores: make(map[string]types.IgnoreLists),
				TagIgnores: map[string]types.IgnoreLists{
					"agentic-skills": {
						ErrIgnores: types.ErrIgnoreList{{
							Error: types.KnownError{Err: types.ErrOSNotCertified},
							Tags:  []string{"agentic-skills"},
						}},
					},
				},
				RPMIgnores:             make(map[string]types.IgnoreLists),
				CertifiedDistributions: []string{"Red Hat Enterprise Linux release 9.2 (Plow)"},
			},
		}
	}

	t.Run("no tag fails with ErrDistributionFileMissing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		results := RunLocalScan(ctx, tagIgnoredOsConfig(""), t.TempDir())
		if !IsFailed(results) {
			t.Fatal("expected scan to fail without tag identity")
		}
		var found bool
		for _, run := range results {
			for _, res := range run.Items {
				if res.Error != nil && errors.Is(res.Error.GetError(), types.ErrDistributionFileMissing) {
					found = true
				}
			}
		}
		if !found {
			t.Error("expected ErrDistributionFileMissing in results")
		}
	})

	t.Run("matching tag ignore skips OS validation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		results := RunLocalScan(ctx, tagIgnoredOsConfig("agentic-skills"), t.TempDir())
		if IsFailed(results) {
			t.Error("expected scan to pass with matching tag ignore")
		}
	})

	t.Run("non-matching tag still fails", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		results := RunLocalScan(ctx, tagIgnoredOsConfig("other-tag"), t.TempDir())
		if !IsFailed(results) {
			t.Error("expected scan to fail for non-matching tag")
		}
	})
}

// TestRunLocalScanTagDoesNotChangeScanRoot pins the --tag semantics: the tag
// carries identity only. The scan root stays --path; it is never resolved to
// a <path>/<tag> subdirectory.
func TestRunLocalScanTagDoesNotChangeScanRoot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	release := []byte("Red Hat Enterprise Linux release 9.2 (Plow)")
	if err := os.WriteFile(filepath.Join(root, "etc", "redhat-release"), release, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &types.Config{
		OutputFormat: "table",
		Parallelism:  1,
		TimeLimit:    30 * time.Second,
		LocalTag:     "some-tag",
		ConfigFile: types.ConfigFile{
			PayloadIgnores:         make(map[string]types.IgnoreLists),
			TagIgnores:             make(map[string]types.IgnoreLists),
			RPMIgnores:             make(map[string]types.IgnoreLists),
			CertifiedDistributions: []string{string(release)},
		},
	}

	// No <root>/some-tag subdirectory exists: if the tag were joined into
	// the scan root, the scan would fail on a missing directory.
	results := RunLocalScan(ctx, cfg, root)
	if IsFailed(results) {
		t.Error("expected scan rooted at --path to pass; a failure suggests the tag was joined into the scan root")
	}
}

func TestShouldSkipOSValidation(t *testing.T) {
	testCases := []struct {
		name      string
		config    *types.Config
		tag       *v1.TagReference
		component *types.OpenshiftComponent
		expected  bool
	}{
		{
			name:   "no tag should not skip",
			config: baseConfig,
			tag:    nil,
			component: &types.OpenshiftComponent{
				Component: "test-component",
			},
			expected: false,
		},
		{
			name:   "tag with no ignores should not skip",
			config: baseConfig,
			tag: &v1.TagReference{
				Name: "regular-tag",
			},
			component: &types.OpenshiftComponent{
				Component: "test-component",
			},
			expected: false,
		},
		{
			name: "rhel-coreos tag with tag-based ignore should skip",
			config: &types.Config{
				ConfigFile: types.ConfigFile{
					TagIgnores: map[string]types.IgnoreLists{
						"rhel-coreos": {
							ErrIgnores: types.ErrIgnoreList{{
								Error: types.KnownError{Err: types.ErrOSNotCertified},
								Tags:  []string{"rhel-coreos"},
							}},
						},
					},
					PayloadIgnores: make(map[string]types.IgnoreLists),
				},
			},
			tag: &v1.TagReference{
				Name: "rhel-coreos",
			},
			component: nil, // rhel-coreos has no component metadata
			expected:  true,
		},
		{
			name: "component with payload ignore should skip",
			config: &types.Config{
				ConfigFile: types.ConfigFile{
					PayloadIgnores: map[string]types.IgnoreLists{
						"test-component": {
							ErrIgnores: types.ErrIgnoreList{{
								Error: types.KnownError{Err: types.ErrOSNotCertified},
								Tags:  []string{"test-tag"},
							}},
						},
					},
					TagIgnores: make(map[string]types.IgnoreLists),
				},
			},
			tag: &v1.TagReference{
				Name: "test-tag",
			},
			component: &types.OpenshiftComponent{
				Component: "test-component",
			},
			expected: true,
		},
		{
			name: "component ignore with wrong tag should not skip",
			config: &types.Config{
				ConfigFile: types.ConfigFile{
					PayloadIgnores: map[string]types.IgnoreLists{
						"test-component": {
							ErrIgnores: types.ErrIgnoreList{{
								Error: types.KnownError{Err: types.ErrOSNotCertified},
								Tags:  []string{"different-tag"},
							}},
						},
					},
					TagIgnores: make(map[string]types.IgnoreLists),
				},
			},
			tag: &v1.TagReference{
				Name: "test-tag",
			},
			component: &types.OpenshiftComponent{
				Component: "test-component",
			},
			expected: false,
		},
		{
			name: "component ignore with wrong error should not skip",
			config: &types.Config{
				ConfigFile: types.ConfigFile{
					PayloadIgnores: map[string]types.IgnoreLists{
						"test-component": {
							ErrIgnores: types.ErrIgnoreList{{
								Error: types.KnownError{Err: types.ErrGoMissingTag}, // different error
								Tags:  []string{"test-tag"},
							}},
						},
					},
					TagIgnores: make(map[string]types.IgnoreLists),
				},
			},
			tag: &v1.TagReference{
				Name: "test-tag",
			},
			component: &types.OpenshiftComponent{
				Component: "test-component",
			},
			expected: false,
		},
		{
			name: "both component and tag ignores - component takes precedence",
			config: &types.Config{
				ConfigFile: types.ConfigFile{
					PayloadIgnores: map[string]types.IgnoreLists{
						"test-component": {
							ErrIgnores: types.ErrIgnoreList{{
								Error: types.KnownError{Err: types.ErrOSNotCertified},
								Tags:  []string{"test-tag"},
							}},
						},
					},
					TagIgnores: map[string]types.IgnoreLists{
						"test-tag": {
							ErrIgnores: types.ErrIgnoreList{{
								Error: types.KnownError{Err: types.ErrOSNotCertified},
								Tags:  []string{"test-tag"},
							}},
						},
					},
				},
			},
			tag: &v1.TagReference{
				Name: "test-tag",
			},
			component: &types.OpenshiftComponent{
				Component: "test-component",
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.config.ShouldIgnoreOSValidation(tc.tag, tc.component, types.ErrOSNotCertified)
			if result != tc.expected {
				t.Errorf("shouldSkipOSValidation() = %v, expected %v", result, tc.expected)
			}
		})
	}
}
