package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const resourceName = "vaultprov_random_secret.test"

func TestAccRandomSecret(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccExampleResourceConfig("my_team", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", "/secret/foo/bar"),
					resource.TestCheckResourceAttr(resourceName, "length", "32"),
					resource.TestCheckResourceAttr(resourceName, "force_destroy", "false"),
					resource.TestCheckResourceAttr(resourceName, "metadata.owner", "my_team"),
					resource.TestCheckResourceAttr(resourceName, "metadata.foo", "bar"),
				),
			},
			// Metadata update testing
			{
				Config: testAccExampleResourceConfig("some_other_team", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", "/secret/foo/bar"),
					resource.TestCheckResourceAttr(resourceName, "length", "32"),
					resource.TestCheckResourceAttr(resourceName, "force_destroy", "false"),
					resource.TestCheckResourceAttr(resourceName, "metadata.owner", "some_other_team"),
					resource.TestCheckResourceAttr(resourceName, "metadata.foo", "bar")),
			},
			// ImportState testing
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateId:     "/secret/foo/bar",

				// random_secret use the 'path' attribute as identifier while Terraform insist on default on 'id'
				ImportStateVerifyIgnore:              []string{"id"},
				ImportStateVerifyIdentifierAttribute: "path",
			},
			// ForceDestroy testing (also needed at the end so the resource can be automatically deleted)
			{
				Config: testAccExampleResourceConfig("some_other_team", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", "/secret/foo/bar"),
					resource.TestCheckResourceAttr(resourceName, "length", "32"),
					resource.TestCheckResourceAttr(resourceName, "force_destroy", "true"),
					resource.TestCheckResourceAttr(resourceName, "metadata.owner", "some_other_team"),
					resource.TestCheckResourceAttr(resourceName, "metadata.foo", "bar")),
			},
			//// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccExampleResourceConfig(team string, forceDestroy bool) string {
	return fmt.Sprintf(`
resource "vaultprov_random_secret" "test" {
  path     = "/secret/foo/bar"
  metadata = {
    owner = "%s"
    foo  = "bar"
  }
  force_destroy = %t
}
`, team, forceDestroy)
}
