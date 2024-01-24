package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"os"
	"testing"
)

const (
	// providerConfig is a shared configuration to combine with the actual
	// test configuration so the Inventory client is properly configured.
	providerConfig = `terraform {
  required_providers {
    vaultprov = {
      source = "blablacar/vaultprov"
    }
  }
}

# Configure the connection details for the Inventory service
provider "vaultprov" {
	address = "http://127.0.0.1:8200"
}
`
)

// testAccProtoV6ProviderFactories are used to instantiate a provider during
// acceptance testing. The factory function will be invoked for every Terraform
// CLI command executed to create a provider server to which the CLI can
// reattach.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"vaultprov": providerserver.NewProtocol6WithError(New()()),
}

func testAccPreCheck(t *testing.T) {
	// You can add code here to run prior to any test case execution, for example assertions
	// about the appropriate environment variables being set are common to see in a pre-check
	// function.

	if v := os.Getenv("VAULT_ADDR"); v == "" {
		t.Fatal("VAULT_ADDR env var must be set for acceptance tests")
	}
}
