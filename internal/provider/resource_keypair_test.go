package provider

import (
	"fmt"
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
				Config: testAccExampleCurve25519ResourceConfig("my_team", false),
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
				Config: testAccExampleCurve25519ResourceConfig("some_other_team", false),
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
				Config: testAccExampleCurve25519ResourceConfig("some_other_team", true),
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

func testAccExampleCurve25519ResourceConfig(team string, forceDestroy bool) string {
	return fmt.Sprintf(`
resource "vaultprov_keypair_secret" "test" {
  base_path     = "/secret/curve"
  type	        = "curve25519"
  metadata      = {
    owner = "%s"
    foo   = "bar"
  }
  force_destroy = %t
}
`, team, forceDestroy)
}
