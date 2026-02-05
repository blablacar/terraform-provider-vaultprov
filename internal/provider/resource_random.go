package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/blablacar/terraform-provider-vaultprov/internal/secrets"
	"github.com/blablacar/terraform-provider-vaultprov/internal/vault"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	_ "github.com/hashicorp/terraform-plugin-go/tftypes"
)

const (
	SecretTypeMetadata             = "secret_type"
	SecretLengthMetadata           = "secret_length"
	RandomBytesType                = "random_secret"
	Curse25519KeypairType          = "curve25519_keypair"
	SecretDataKey                  = "secret"
	DefaultRandomBytesLength       = 32
	DefaultCurve25519KeypairLength = 64
)

// Ensure provider defined types fully satisfy framework interfaces
var _ resource.Resource = &RandomSecret{}
var _ resource.ResourceWithImportState = &RandomSecret{}

type RandomSecret struct {
	vaultApi *vault.VaultApi
}

type randomSecretModel struct {
	Path         types.String `tfsdk:"path"`
	Type         types.String `tfsdk:"type"`
	Length       types.Int64  `tfsdk:"length"`
	Metadata     types.Map    `tfsdk:"metadata"`
	ForceDestroy types.Bool   `tfsdk:"force_destroy"`
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
			"type": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(RandomBytesType),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				MarkdownDescription: "Type of secret to create. Possible values are `random_secret`, `curve25519_keypair`.",
			},
			"length": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				//Default:  int64default.StaticInt64(DefaultRandomBytesLength),
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
				Validators: []validator.Int64{
					int64validator.AtLeast(1),
				},
				MarkdownDescription: "The length (in bytes) of the secret. Default is 32 for `random_secret`. For `curve25519_keypair`, this attribute not supported (keypair are always 64 bytes long). This information will be stored as a custom metadata under the key `secret_length`.",
			},
			"metadata": schema.MapAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "A map of key/value strings that will be stored along the secret as custom metadata",
			},
			"force_destroy": schema.BoolAttribute{
				Optional:            true,
				Required:            false,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "If set to `true`, removing the resource will delete the secret and all versions in Vault. If set to `false` or not defined, removing the resource will fail.",
			},
		},
		MarkdownDescription: "A cryptographic randomly generated secret stored as bytes in a Vault secret. Secret can be either a random bytes (`random_secret`) array or a Curve25519 keypair (`curve25519_keypair`). The resulting Vault secret will have a custom metadata `secret_type` with the type of the secret and a custom metadata `secret_length` with the same value as the `length` attribute.",
	}
}

func (s *RandomSecret) ModifyPlan(ctx context.Context, request resource.ModifyPlanRequest, response *resource.ModifyPlanResponse) {
	// If the entire plan is null, the resource is planned for destruction.
	if request.Plan.Raw.IsNull() {
		return
	}

	var plan *randomSecretModel
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	if plan.Type.ValueString() == RandomBytesType {
		if plan.Length.IsUnknown() {
			response.Plan.SetAttribute(
				ctx,
				path.Root("length"),
				types.Int64Value(DefaultRandomBytesLength),
			)
		}
	} else if plan.Type.ValueString() == Curse25519KeypairType {
		if !plan.Length.IsUnknown() && plan.Length.ValueInt64() != DefaultCurve25519KeypairLength {
			response.Diagnostics.AddError("Error creating Curve25519 keypair", fmt.Sprintf("Length attribute is not supported for Curve25519 keypair type (value: %d)", plan.Length.ValueInt64()))
			return
		}
		response.Plan.SetAttribute(
			ctx,
			path.Root("length"),
			types.Int64Value(DefaultCurve25519KeypairLength),
		)
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

	var err error
	var key []byte
	var secretLength int

	secretType := plan.Type.ValueString()

	if secretType == RandomBytesType {
		secretLength = int(plan.Length.ValueInt64())
		key, err = secrets.GenerateRandomSecret(secretLength)
		if err != nil {
			response.Diagnostics.AddError("Error creating random key", fmt.Sprintf("Could generate random bytes, unexpected error: %s", err.Error()))
			return
		}
	} else if secretType == Curse25519KeypairType {
		privateKey, publicKey, err := secrets.GenerateCurve25519Keypair()
		if err != nil {
			response.Diagnostics.AddError("Error creating Curve25519 keypair", fmt.Sprintf("Could not generate Curve25519 keypair, unexpected error: %s", err.Error()))
			return
		}
		key = append(publicKey, privateKey...) // Concat public and private keys
		secretLength = len(key)
		plan.Length = types.Int64Value(int64(secretLength))
	} else {
		response.Diagnostics.AddError("Error creating secret", fmt.Sprintf("Unsupported secret type: %s. Supported types are: %s, %s", secretType, RandomBytesType, Curse25519KeypairType))
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

	data := map[string]interface{}{
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
			if k == SecretTypeMetadata {
				data.Type = types.StringValue(v)
				continue
			}
			if k == SecretLengthMetadata {
				len, err := strconv.Atoi(v)
				if err != nil {
					resp.Diagnostics.AddError("Error reading secret length: "+v, fmt.Sprintf("Error while reading secret %s: %s", secretPath, err.Error()))
					return
				}
				data.Length = types.Int64Value(int64(len))
				continue
			}
			additionalMetadata[k] = types.StringValue(v)
		}
		data.Metadata, _ = types.MapValue(types.StringType, additionalMetadata)
	}

	// ForceDestroy may be null in state when importing an existing resource
	if data.ForceDestroy.IsNull() {
		data.ForceDestroy = types.BoolValue(false)
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

	// Check that path, hasn't changed
	if state.Path.ValueString() != plan.Path.ValueString() {
		resp.Diagnostics.AddError("Error updating random key", fmt.Sprintf("Invalid path change. Random key can't have their path changed (old: %s, new: %s). Only metadata changes are authorized. Delete and recreate the key instead.", state.Path.ValueString(), plan.Path.ValueString()))
		return
	}

	secretPath := state.Path.ValueString()

	metadata := make(map[string]string)
	for k, v := range plan.Metadata.Elements() {
		metadata[k] = v.(types.String).ValueString()
	}

	metadata[SecretTypeMetadata] = plan.Type.ValueString()
	metadata[SecretLengthMetadata] = plan.Length.String()

	err := s.vaultApi.UpdateSecretMetadata(secretPath, metadata)
	if err != nil {
		resp.Diagnostics.AddError("Error updating secret", fmt.Sprintf("Error while updating metadata for secret %s: %s", secretPath, err.Error()))
		return
	}

	state.Metadata = plan.Metadata
	state.ForceDestroy = plan.ForceDestroy

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

	if !state.ForceDestroy.ValueBool() {
		resp.Diagnostics.AddError("Error deleting secret", "Can't delete resource for Vault secret '"+state.Path.ValueString()+"': 'force_destroy' must be set to 'true'")
		return
	}

	secretPath := state.Path.ValueString()

	err := s.vaultApi.DeleteSecret(secretPath)
	if err != nil {
		resp.Diagnostics.AddError("Error deleting secret", fmt.Sprintf("Error while deleting secret %s: %s", secretPath, err.Error()))
		return
	}

}
