package provider

import (
	"context"
	"fmt"
	vaultapi "github.com/blablacar/terraform-provider-vaultprov/internal/vault"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/kubernetes"
)

const providerName = "vaultprov"

var _ provider.Provider = &vaultSecretProvider{}

type vaultSecretProvider struct {
	vaultApi *vaultapi.VaultApi
}

// Provider schema struct
type providerModel struct {
	Address types.String      `tfsdk:"address"`
	Token   types.String      `tfsdk:"token"`
	Auth    providerAuthModel `tfsdk:"auth"`
}

type providerAuthModel struct {
	Path types.String `tfsdk:"path"`
	Role types.String `tfsdk:"role"`
	Jwt  types.String `tfsdk:"jwt"`
}

func New() func() provider.Provider {
	return func() provider.Provider {
		return &vaultSecretProvider{}
	}
}

func (p *vaultSecretProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultConf := vault.DefaultConfig()
	vaultConf.Address = config.Address.ValueString()

	client, err := vault.NewClient(vaultConf)
	if err != nil {
		tflog.Error(ctx, "Error creating vault client", map[string]interface{}{"address": vaultConf.Address, "error": err})
		resp.Diagnostics.AddError(
			"Error configuring provider",
			fmt.Sprintf("Can't create vault client for %s: %s", vaultConf.Address, err.Error()),
		)
		return
	}

	if !config.Token.IsNull() {
		client.SetToken(config.Token.ValueString()) //DEBUG
		tflog.Warn(ctx, "Auth token provided. Ignoring other auth parameters. FOR DEBUG ONLY, DO NOT USE IN PRODUCTION.", nil)

		p.vaultApi = vaultapi.NewVaultApi(client)
		resp.ResourceData = p.vaultApi
		return
	}

	role := config.Auth.Role.ValueString()
	jwt := config.Auth.Jwt.ValueString()

	k8sAuth, err := auth.NewKubernetesAuth(
		role,
		auth.WithServiceAccountToken(jwt),
	)
	if err != nil {
		tflog.Error(ctx, "Error initializing Vault kubernetes auth method", map[string]interface{}{"role": role, "jwt": jwt, "error": err})
		resp.Diagnostics.AddError(
			"Error configuring provider",
			fmt.Sprintf("Unable to initialize Vault Kubernetes authentication with role %s and JWT %s: %s", role, jwt, err.Error()),
		)
		return
	}

	authInfo, err := client.Auth().Login(context.Background(), k8sAuth)
	if err != nil {
		tflog.Error(ctx, "Error login in with Vault kubernetes auth method", map[string]interface{}{"role": role, "jwt": jwt, "error": err})
		resp.Diagnostics.AddError(
			"Error configuring provider",
			fmt.Sprintf("Unable to log in with Vault Kubernetes authentication with role %s and JWT %s: %s", role, jwt, err.Error()),
		)
		return
	}

	if authInfo == nil {
		tflog.Error(ctx, "Not auth info returned for kubernetes auth", map[string]interface{}{"role": role, "jwt": jwt})
		resp.Diagnostics.AddError(
			"Error configuring provider",
			fmt.Sprintf("Not auth info returned for kubernetes auth with role %s and JWT %s: %s", role, jwt, err.Error()),
		)
		return
	}

	p.vaultApi = vaultapi.NewVaultApi(client)
	resp.ResourceData = p.vaultApi
}

func (p *vaultSecretProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = providerName
}

func (p *vaultSecretProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *vaultSecretProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewRandomSecret,
	}
}

func (p *vaultSecretProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Origin URL of the Vault server. This is a URL with a scheme, a hostname and a port but with no path.",
			},
			"token": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Vault token that will be used by Terraform to authenticate. For debug purpose only. For production, use the `auth` attributes",
			},
			"auth": schema.SingleNestedAttribute{
				Attributes: map[string]schema.Attribute{
					"path": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "The login path of the auth Kubernetes backend. For example, `auth/kubernetes/gke-tools-1/login`",
					},
					"role": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "The name of the role against which the login is being attempted.",
					},
					"jwt": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "The JWT of the Kubernetes Service Account against which the login is being attempted.",
					},
				},
				Optional: true,
			},
		},
		MarkdownDescription: "A provider to generate secrets and have them stored directly into Vault without any copy in the Terraform State.  Once the secret has been generated, its value only exist into Vault. Terraform will not track any change in the value, only in the secret attribute (`metadata`, etc.`).",
	}
}