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
			// Test: attempting to change type (should trigger replacement)
			// Note: This will fail because ed25519 is not a supported type, but it tests the behavior
			{
				Config:      testAccExampleCurve25519ResourceConfig("/secret/curve-errtest", "ed25519", "my_team", true),
				ExpectError: regexp.MustCompile(`.*Unsupported secret type.*ed25519.*`),
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
			// Update to enable force_destroy so we can properly clean up
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
