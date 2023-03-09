package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/blablacar/terraform-provider-vaultprov/internal/planmodifiers"
	"github.com/blablacar/terraform-provider-vaultprov/internal/secrets"
	"github.com/blablacar/terraform-provider-vaultprov/internal/vault"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	_ "github.com/hashicorp/terraform-plugin-go/tftypes"
)

const (
	SecretTypeMetadata        = "secret_type"
	SecretLengthMetadata      = "secret_length"
	RandomSecretType          = "random_secret"
	SecretDataKey             = "secret"
	DefaultRandomSecretLength = 32
)

// Ensure provider defined types fully satisfy framework interfaces
var _ resource.Resource = &RandomSecret{}
var _ resource.ResourceWithImportState = &RandomSecret{}

type RandomSecret struct {
	vaultApi *vault.VaultApi
}

type randomSecretModel struct {
	Path     types.String `tfsdk:"path"`
	Length   types.Int64  `tfsdk:"length"`
	Metadata types.Map    `tfsdk:"metadata"`
}

func NewRandomSecret() resource.Resource {
	return &RandomSecret{}
}

func (s *RandomSecret) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	vaultApi, ok := req.ProviderData.(*vault.VaultApi)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *http.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	s.vaultApi = vaultApi
}

func (s *RandomSecret) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("path"), request, response)
}

func (s *RandomSecret) Metadata(ctx context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_random_secret"
}

func (s *RandomSecret) Schema(ctx context.Context, request resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"path": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				MarkdownDescription: "Full name of the Vault secret. For a nested secret the name is the nested path excluding the mount and data prefix. For example, for a secret at `keys/data/foo/bar/baz` the name is `foo/bar/baz`. Serves as the secret id.",
			},
			"length": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Int64{
					planmodifiers.Int64DefaultValue(types.Int64Value(DefaultRandomSecretLength)),
					int64planmodifier.RequiresReplace(),
				},
				Validators: []validator.Int64{
					int64validator.AtLeast(1),
				},
				MarkdownDescription: "The length (in bytes) of the secret. Default is 32. This information will be stored as a custom metadata under the key `secret_length` ",
			},
			"metadata": schema.MapAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "A map of key/value strings that will be stored along the secret as custom metadata",
			},
		},
		MarkdownDescription: "A cryptographic randomly generated secret stored as bytes in a Vault secret. The resulting Vault secret will have a custom metadata `secret_type` with the value `random_secret` and a custom metadata `secret_length` with the same value as the `length` attribute.",
	}
}

func (s *RandomSecret) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan *randomSecretModel

	// Retrieve values from plan
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	var key []byte

	secretType := RandomSecretType
	secretLength := int(plan.Length.ValueInt64())

	key, err := secrets.GenerateRandomSecret(secretLength)
	if err != nil {
		response.Diagnostics.AddError("Error creating random key", fmt.Sprintf("Could generate random bytes, unexpected error: %s", err.Error()))
		return
	}

	// Prepare metadata
	customMetadata := make(map[string]string)
	if !plan.Metadata.IsNull() {
		for k, v := range plan.Metadata.Elements() {
			customMetadata[k] = v.(types.String).ValueString()
		}
	}
	customMetadata[SecretTypeMetadata] = secretType
	customMetadata[SecretLengthMetadata] = fmt.Sprintf("%d", secretLength)

	data := map[string]string{
		SecretDataKey: base64.StdEncoding.EncodeToString(key),
	}

	secret := vault.Secret{
		Path:     plan.Path.ValueString(),
		Data:     data,
		Metadata: customMetadata,
	}

	err = s.vaultApi.CreateSecret(secret)
	if err != nil {
		response.Diagnostics.AddError("Error creating random key", fmt.Sprintf("Couldn't create Vault secret: %s", err.Error()))
		return
	}

	diags = response.State.Set(ctx, &plan)
	response.Diagnostics.Append(diags...)
}

func (s *RandomSecret) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get current state
	var data randomSecretModel
	diags := req.State.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	secretPath := data.Path.ValueString()

	secret, err := s.vaultApi.ReadSecret(secretPath)
	if err != nil {
		resp.Diagnostics.AddError("Error reading secret", fmt.Sprintf("Error while reading secret %s: %s", secretPath, err.Error()))
		return
	}

	if secret == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	customMetadata := secret.Metadata

	if len(customMetadata) > 0 {
		additionalMetadata := make(map[string]attr.Value)
		for k, v := range customMetadata {
			additionalMetadata[k] = types.StringValue(v)
		}
		data.Metadata, _ = types.MapValue(types.StringType, additionalMetadata)
	}

	// Set state
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
}

func (s *RandomSecret) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan randomSecretModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get current state
	var state randomSecretModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check that path, length and type haven't changed
	if state.Path.ValueString() != plan.Path.ValueString() {
		resp.Diagnostics.AddError("Error updating random key", fmt.Sprintf("Invalid path change. Random key can't have their path changed (old: %s, new: %s). Only metadata changes are authorized. Delete and recreate the key instead.", state.Path.ValueString(), plan.Path.ValueString()))
		return
	}

	secretPath := state.Path.ValueString()

	metadata := make(map[string]string)
	for k, v := range plan.Metadata.Elements() {
		metadata[k] = v.(types.String).ValueString()
	}

	err := s.vaultApi.UpdateSecretMetadata(secretPath, metadata)
	if err != nil {
		resp.Diagnostics.AddError("Error updating secret", fmt.Sprintf("Error while updating metadata for secret %s: %s", secretPath, err.Error()))
		return
	}

	state.Metadata = plan.Metadata

	// Set state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (s *RandomSecret) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state randomSecretModel

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	secretPath := state.Path.ValueString()

	err := s.vaultApi.DeleteSecret(secretPath)
	if err != nil {
		resp.Diagnostics.AddError("Error deleting secret", fmt.Sprintf("Error while deleting secret %s: %s", secretPath, err.Error()))
		return
	}

}
