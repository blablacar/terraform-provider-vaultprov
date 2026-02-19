package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const keypairResourceName = "vaultprov_keypair_secret.test"

func TestAccCurve25519Secret(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccExampleCurve25519ResourceConfig("/secret/curve", Curve25519KeyPairType, "my_team", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keypairResourceName, "base_path", "/secret/curve"),
					resource.TestCheckResourceAttr(keypairResourceName, "type", Curve25519KeyPairType),
					resource.TestCheckResourceAttr(keypairResourceName, "force_destroy", "false"),
					resource.TestCheckResourceAttr(keypairResourceName, "metadata.owner", "my_team"),
					resource.TestCheckResourceAttr(keypairResourceName, "metadata.foo", "bar"),
				),
			},
			// Metadata update testing
			{
				Config: testAccExampleCurve25519ResourceConfig("/secret/curve", Curve25519KeyPairType, "some_other_team", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keypairResourceName, "base_path", "/secret/curve"),
					resource.TestCheckResourceAttr(keypairResourceName, "type", Curve25519KeyPairType),
					resource.TestCheckResourceAttr(keypairResourceName, "force_destroy", "false"),
					resource.TestCheckResourceAttr(keypairResourceName, "metadata.owner", "some_other_team"),
					resource.TestCheckResourceAttr(keypairResourceName, "metadata.foo", "bar")),
			},
			// ImportState testing
			{
				ResourceName:      keypairResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateId:     "/secret/curve",

				// keypair use the 'base_path' attribute as identifier while Terraform insist on default on 'id'
				ImportStateVerifyIgnore:              []string{"id"},
				ImportStateVerifyIdentifierAttribute: "base_path",
			},
			// ForceDestroy testing (also needed at the end so the resource can be automatically deleted)
			{
				Config: testAccExampleCurve25519ResourceConfig("/secret/curve", Curve25519KeyPairType, "some_other_team", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keypairResourceName, "base_path", "/secret/curve"),
					resource.TestCheckResourceAttr(keypairResourceName, "type", Curve25519KeyPairType),
					resource.TestCheckResourceAttr(keypairResourceName, "force_destroy", "true"),
					resource.TestCheckResourceAttr(keypairResourceName, "metadata.owner", "some_other_team"),
					resource.TestCheckResourceAttr(keypairResourceName, "metadata.foo", "bar")),
			},
			//// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccCurve25519Secret_ErrorCases(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create initial resource
			{
				Config: testAccExampleCurve25519ResourceConfig("/secret/curve-errtest", Curve25519KeyPairType, "my_team", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keypairResourceName, "base_path", "/secret/curve-errtest"),
					resource.TestCheckResourceAttr(keypairResourceName, "type", Curve25519KeyPairType),
				),
			},
			// Test: attempting to change base_path (should trigger replacement)
			// The RequiresReplace plan modifier will force a destroy-then-create operation
			{
				Config: testAccExampleCurve25519ResourceConfig("/secret/curve-errtest2", Curve25519KeyPairType, "my_team", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keypairResourceName, "base_path", "/secret/curve-errtest2"),
				),
			},
			// Test: unsupported type is rejected at plan time by stringvalidator.OneOf.
			// The error originates from the framework validator, not from Create().
			{
				Config:      testAccExampleCurve25519ResourceConfig("/secret/curve-errtest", "ed25519", "my_team", true),
				ExpectError: regexp.MustCompile(`value must be one of.*curve25519`),
			},
			// Restore a valid config so the framework can cleanly destroy the resource.
			// After the ExpectError step the state still holds curve-errtest2; applying
			// this config is a no-op but leaves a valid, plannable config on disk.
			{
				Config: testAccExampleCurve25519ResourceConfig("/secret/curve-errtest2", Curve25519KeyPairType, "my_team", true),
			},
		},
	})
}

func TestAccCurve25519Secret_DeleteWithoutForceDestroy(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create resource without force_destroy
			{
				Config: testAccExampleCurve25519ResourceConfig("/secret/curve-nodelete", Curve25519KeyPairType, "my_team", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keypairResourceName, "base_path", "/secret/curve-nodelete"),
					resource.TestCheckResourceAttr(keypairResourceName, "force_destroy", "false"),
				),
			},
			// Verify that removing the resource without force_destroy=true is blocked.
			// A resource-free config causes Terraform to destroy the orphaned resource;
			// with force_destroy=false the Delete function returns an error before
			// touching Vault. An empty string is rejected by the test framework, so we
			// use a HCL comment as the minimal valid resource-free config.
			{
				Config:      `# no resources`,
				ExpectError: regexp.MustCompile(`force_destroy.*must be set to.*true`),
			},
			// Enable force_destroy for proper cleanup at the end of the test.
			{
				Config: testAccExampleCurve25519ResourceConfig("/secret/curve-nodelete", Curve25519KeyPairType, "my_team", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keypairResourceName, "base_path", "/secret/curve-nodelete"),
					resource.TestCheckResourceAttr(keypairResourceName, "force_destroy", "true"),
				),
			},
		},
	})
}

// TestAccCurve25519Secret_TrailingSlashBasePath verifies that a base_path with a
// trailing slash is normalised correctly and doesn't produce double-slash Vault paths.
func TestAccCurve25519Secret_TrailingSlashBasePath(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with trailing slash — keypairPaths() must strip it so the Vault
			// secrets land at secret/curve-slash/private and secret/curve-slash/public,
			// not secret/curve-slash//private.
			{
				Config: testAccExampleCurve25519ResourceConfig("/secret/curve-slash/", Curve25519KeyPairType, "my_team", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keypairResourceName, "base_path", "/secret/curve-slash/"),
					resource.TestCheckResourceAttr(keypairResourceName, "type", Curve25519KeyPairType),
				),
			},
			// Read-back after creation must not drift (proves Read() uses keypairPaths too).
			// force_destroy must match the create step so PlanOnly sees no diff.
			{
				Config:   testAccExampleCurve25519ResourceConfig("/secret/curve-slash/", Curve25519KeyPairType, "my_team", false),
				PlanOnly: true,
			},
			// Enable force_destroy for cleanup during post-test destroy.
			{
				Config: testAccExampleCurve25519ResourceConfig("/secret/curve-slash/", Curve25519KeyPairType, "my_team", true),
			},
		},
	})
}

// TestAccCurve25519Secret_NoMetadata verifies the full lifecycle when the optional
// metadata attribute is never set.
func TestAccCurve25519Secret_NoMetadata(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create without metadata
			{
				Config: testAccExampleCurve25519ResourceConfigNoMetadata("/secret/curve-nometa", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keypairResourceName, "base_path", "/secret/curve-nometa"),
					resource.TestCheckResourceAttr(keypairResourceName, "type", Curve25519KeyPairType),
					resource.TestCheckNoResourceAttr(keypairResourceName, "metadata.%"),
				),
			},
			// Import state must round-trip without drift.
			// force_destroy is a Terraform-only lifecycle flag not stored in Vault,
			// so it always resets to false after import and must be excluded from
			// verification.
			{
				ResourceName:                         keypairResourceName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateId:                        "/secret/curve-nometa",
				ImportStateVerifyIgnore:              []string{"id", "force_destroy"},
				ImportStateVerifyIdentifierAttribute: "base_path",
			},
		},
	})
}

// TestAccCurve25519Secret_MetadataRemoval verifies that removing all user metadata
// from a resource is reflected in state without drift. This exercises the Read()
// code path that unconditionally updates data.Metadata even when the vault secret
// carries no user-defined custom metadata.
func TestAccCurve25519Secret_MetadataRemoval(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with metadata
			{
				Config: testAccExampleCurve25519ResourceConfig("/secret/curve-metaremove", Curve25519KeyPairType, "my_team", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(keypairResourceName, "metadata.owner", "my_team"),
				),
			},
			// Remove metadata entirely — Read() must return an empty map, not stale values
			{
				Config: testAccExampleCurve25519ResourceConfigNoMetadata("/secret/curve-metaremove", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(keypairResourceName, "metadata.%"),
				),
			},
			// Confirm no drift after the metadata removal
			{
				Config:             testAccExampleCurve25519ResourceConfigNoMetadata("/secret/curve-metaremove", false),
				ExpectNonEmptyPlan: false,
				PlanOnly:           true,
			},
			// Enable force_destroy for cleanup
			{
				Config: testAccExampleCurve25519ResourceConfigNoMetadata("/secret/curve-metaremove", true),
			},
		},
	})
}

func testAccExampleCurve25519ResourceConfig(basepath, keyType, team string, forceDestroy bool) string {
	return fmt.Sprintf(`
resource "vaultprov_keypair_secret" "test" {
  base_path     = "%s"
  type	        = "%s"
  metadata      = {
    owner = "%s"
    foo   = "bar"
  }
  force_destroy = %t
}
`, basepath, keyType, team, forceDestroy)
}

func testAccExampleCurve25519ResourceConfigNoMetadata(basepath string, forceDestroy bool) string {
	return fmt.Sprintf(`
resource "vaultprov_keypair_secret" "test" {
  base_path     = "%s"
  force_destroy = %t
}
`, basepath, forceDestroy)
}
