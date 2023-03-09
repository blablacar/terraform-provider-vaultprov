package main

import (
	"context"
	"flag"
	"github.com/blablacar/terraform-provider-vaultprov/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Provider documentation generation.
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name vaultsecret

const providerUrl = "registry.terraform.io/blablacar/vaultprov"

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(), providerserver.ServeOpts{
		Address:         providerUrl,
		Debug:           debug,
		ProtocolVersion: 6,
	})

	tflog.Error(context.Background(), "error serving provider", map[string]interface{}{"error": err})

}
