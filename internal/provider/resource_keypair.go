package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/blablacar/terraform-provider-vaultprov/internal/secrets"
	"github.com/blablacar/terraform-provider-vaultprov/internal/vault"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	_ "github.com/hashicorp/terraform-plugin-go/tftypes"
)

const (
	Curve25519KeyPairType       = "curve25519"
	Curve25519KeySize           = 32
	KeyPairLinkedSecretMetadata = "keypair_linked_secret_path"
	KeyPairPartMetadata         = "keypair_part"
	PrivateKeyPart              = "private"
	PublicKeyPart               = "public"
)

// Ensure provider defined types fully satisfy framework interfaces
var _ resource.Resource = &KeyPairSecret{}
var _ resource.ResourceWithImportState = &KeyPairSecret{}

type KeyPairSecret struct {
	vaultApi *vault.VaultApi
}

type keyPairSecretModel struct {
	BasePath     types.String `tfsdk:"base_path"`
	Type         types.String `tfsdk:"type"`
	Metadata     types.Map    `tfsdk:"metadata"`
	ForceDestroy types.Bool   `tfsdk:"force_destroy"`
}

func NewKeyPairSecret() resource.Resource {
	return &KeyPairSecret{}
}

func (s *KeyPairSecret) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	vaultApi, ok := req.ProviderData.(*vault.VaultApi)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *vault.VaultApi, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	s.vaultApi = vaultApi
}

func (s *KeyPairSecret) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("base_path"), request, response)
}

func (s *KeyPairSecret) Metadata(ctx context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_keypair_secret"
}

func (s *KeyPairSecret) Schema(ctx context.Context, request resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"base_path": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				MarkdownDescription: "Base path of the keypair secrets in Vault. Two Vault secrets will be created at this path: one for the private key (`private`) and one for the public one (`public`) . For example, for a `base_path` `foo/bar`, the keypair secrets will be `foo/bar/private` and `foo/bar/public`. Serves as the secret id.",
			},
			"type": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(Curve25519KeyPairType),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf(Curve25519KeyPairType),
				},
				MarkdownDescription: "Type of keypair to create. Only supported value for now is `curve25519`.",
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
		MarkdownDescription: "A cryptographic keypair stored as two Vault secrets (one for the private key and one for the public one). Only support Curve25519 keypair for now. The resulting Vault secrets will have a custom metadata `secret_type` with the type of the secret (`keypair_curve25519`) and a custom metadata `secret_length` with the length of the keypair.",
	}
}

func (s *KeyPairSecret) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan *keyPairSecretModel

	// Retrieve values from plan
	diags := request.Plan.Get(ctx, &plan)
	response.Diagnostics.Append(diags...)
	if response.Diagnostics.HasError() {
		return
	}

	var err error
	var privateKey, publicKey []byte

	secretType := plan.Type.ValueString()

	if secretType == Curve25519KeyPairType {
		privateKey, publicKey, err = secrets.GenerateCurve25519Keypair()
		if err != nil {
			response.Diagnostics.AddError("Error creating Curve25519 keypair", fmt.Sprintf("Could not generate Curve25519 keypair, unexpected error: %s", err.Error()))
			return
		}
	} else {
		response.Diagnostics.AddError("Error creating secret", fmt.Sprintf("Unsupported secret type: %s. Supported types are: %s", secretType, Curve25519KeyPairType))
		return
	}

	basePath := plan.BasePath.ValueString()
	privateKeyPath, publicKeyPath := s.keypairPaths(basePath)

	// Prepare metadata
	customMetadata := make(map[string]string)
	if !plan.Metadata.IsNull() {
		for k, v := range plan.Metadata.Elements() {
			customMetadata[k] = v.(types.String).ValueString()
		}
	}
	customMetadata[SecretTypeMetadata] = secretType
	customMetadata[SecretLengthMetadata] = strconv.Itoa(Curve25519KeySize)

	// Store private key
	customMetadata[KeyPairLinkedSecretMetadata] = publicKeyPath
	customMetadata[KeyPairPartMetadata] = PrivateKeyPart

	data := map[string]interface{}{
		SecretDataKey: base64.StdEncoding.EncodeToString(privateKey),
	}

	secret := vault.Secret{
		Path:     privateKeyPath,
		Data:     data,
		Metadata: customMetadata,
	}

	err = s.vaultApi.CreateSecret(secret)
	if err != nil {
		response.Diagnostics.AddError("Error creating private key", fmt.Sprintf("Couldn't create Vault secret for private key: %s", err.Error()))
		return
	}

	// Store public key
	customMetadata[KeyPairLinkedSecretMetadata] = privateKeyPath
	customMetadata[KeyPairPartMetadata] = PublicKeyPart

	data = map[string]interface{}{
		SecretDataKey: base64.StdEncoding.EncodeToString(publicKey),
	}

	secret = vault.Secret{
		Path:     publicKeyPath,
		Data:     data,
		Metadata: customMetadata,
	}

	err = s.vaultApi.CreateSecret(secret)
	if err != nil {
		response.Diagnostics.AddError("Error creating public key", fmt.Sprintf("Couldn't create Vault secret for public key: %s", err.Error()))

		// Roll back previously created private key to avoid leaving an orphaned secret
		if rollbackErr := s.vaultApi.DeleteSecret(privateKeyPath); rollbackErr != nil {
			response.Diagnostics.AddWarning(
				"Rollback failed after public key creation error",
				fmt.Sprintf("Failed to delete previously created private key at %s: %s", privateKeyPath, rollbackErr.Error()),
			)
		}
		return
	}

	diags = response.State.Set(ctx, &plan)
	response.Diagnostics.Append(diags...)
}

func (s *KeyPairSecret) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get current state
	var data keyPairSecretModel
	diags := req.State.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	privateKeyPath, _ := s.keypairPaths(data.BasePath.ValueString())

	secret, err := s.vaultApi.ReadSecret(privateKeyPath)
	if err != nil {
		resp.Diagnostics.AddError("Error reading secret", fmt.Sprintf("Error while reading secret %s: %s", privateKeyPath, err.Error()))
		return
	}

	if secret == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	customMetadata := secret.Metadata

	additionalMetadata := make(map[string]attr.Value)
	for k, v := range customMetadata {
		if k == SecretTypeMetadata {
			data.Type = types.StringValue(v)
			continue
		}
		if k == SecretLengthMetadata || k == KeyPairLinkedSecretMetadata || k == KeyPairPartMetadata {
			continue
		}
		additionalMetadata[k] = types.StringValue(v)
	}
	mapVal, mapDiags := types.MapValue(types.StringType, additionalMetadata)
	resp.Diagnostics.Append(mapDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Metadata = mapVal

	// ForceDestroy may be null in state when importing an existing resource
	if data.ForceDestroy.IsNull() {
		data.ForceDestroy = types.BoolValue(false)
	}

	// Set state
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
}

func (s *KeyPairSecret) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan keyPairSecretModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get current state
	var state keyPairSecretModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// base_path and type have RequiresReplace plan modifiers, so Update is only
	// ever called for metadata/force_destroy changes.
	privateKeyPath, publicKeyPath := s.keypairPaths(state.BasePath.ValueString())

	// Build base user metadata.
	userMetadata := make(map[string]string)
	for k, v := range plan.Metadata.Elements() {
		userMetadata[k] = v.(types.String).ValueString()
	}

	// Build separate metadata maps for each key to avoid shared-map mutation.
	privateMetadata := make(map[string]string, len(userMetadata)+4)
	for k, v := range userMetadata {
		privateMetadata[k] = v
	}
	privateMetadata[SecretTypeMetadata] = state.Type.ValueString()
	privateMetadata[SecretLengthMetadata] = strconv.Itoa(Curve25519KeySize)
	privateMetadata[KeyPairLinkedSecretMetadata] = publicKeyPath
	privateMetadata[KeyPairPartMetadata] = PrivateKeyPart

	publicMetadata := make(map[string]string, len(userMetadata)+4)
	for k, v := range userMetadata {
		publicMetadata[k] = v
	}
	publicMetadata[SecretTypeMetadata] = state.Type.ValueString()
	publicMetadata[SecretLengthMetadata] = strconv.Itoa(Curve25519KeySize)
	publicMetadata[KeyPairLinkedSecretMetadata] = privateKeyPath
	publicMetadata[KeyPairPartMetadata] = PublicKeyPart

	err := s.vaultApi.UpdateSecretMetadata(privateKeyPath, privateMetadata)
	if err != nil {
		resp.Diagnostics.AddError("Error updating secret", fmt.Sprintf("Error while updating metadata for secret %s: %s", privateKeyPath, err.Error()))
		return
	}

	err = s.vaultApi.UpdateSecretMetadata(publicKeyPath, publicMetadata)
	if err != nil {
		resp.Diagnostics.AddError("Error updating secret", fmt.Sprintf("Error while updating metadata for secret %s: %s", publicKeyPath, err.Error()))
		return
	}

	state.Metadata = plan.Metadata
	state.ForceDestroy = plan.ForceDestroy

	// Set state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (s *KeyPairSecret) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state keyPairSecretModel

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !state.ForceDestroy.ValueBool() {
		resp.Diagnostics.AddError("Error deleting key pair", "Can't delete resource for Vault secret '"+state.BasePath.ValueString()+"': 'force_destroy' must be set to 'true'")
		return
	}

	basePath := state.BasePath.ValueString()
	privateKeyPath, publicKeyPath := s.keypairPaths(basePath)

	err := s.vaultApi.DeleteSecret(privateKeyPath)
	if err != nil {
		resp.Diagnostics.AddError("Error deleting private key", fmt.Sprintf("Error while deleting secret %s: %s", privateKeyPath, err.Error()))
		return
	}

	err = s.vaultApi.DeleteSecret(publicKeyPath)
	if err != nil {
		resp.Diagnostics.AddError("Error deleting public key", fmt.Sprintf("Error while deleting secret %s: %s", publicKeyPath, err.Error()))
		resp.Diagnostics.AddWarning(
			"Partial deletion: private key already deleted",
			fmt.Sprintf("Private key at %s was successfully deleted, but the public key at %s could not be deleted and requires manual cleanup in Vault.", privateKeyPath, publicKeyPath),
		)
		return
	}
}

func (s *KeyPairSecret) keypairPaths(basePath string) (string, string) {
	basePath = strings.TrimRight(basePath, "/") + "/"
	return basePath + PrivateKeyPart, basePath + PublicKeyPart
}
