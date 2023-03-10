package vault

import (
	"fmt"
	vaultinternals "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"strconv"
)

const (
	SecretDataField       = "data"
	SecretCustomDataField = "custom_metadata"
)

type Secret struct {
	Path     string
	Data     map[string]interface{}
	Metadata map[string]string
}

type VaultApi struct {
	client *vaultinternals.Client
}

func NewVaultApi(client *vaultinternals.Client) *VaultApi {
	return &VaultApi{client: client}
}

func (c *VaultApi) CreateSecret(secret Secret) error {
	// Get data path for target Vault secret
	dataPath, err := secretDataPath(secret.Path, c.client)
	if err != nil {
		return fmt.Errorf("invalid path for data: %w", err)
	}

	// Check if secret already exists in Vault
	s, err := c.client.Logical().Read(dataPath)
	if err != nil {
		return fmt.Errorf("unable to read secret's data: %w", err)
	}

	if s != nil {
		return fmt.Errorf("secret %s already exists", secret.Path)
	}

	// Get metadata path for secret in Vault
	metadataPath, err := secretMetadataPath(secret.Path, c.client)
	if err != nil {
		return fmt.Errorf("invalid path for metadata: %w", err)
	}

	// Write secret's data in Vault
	secretData := map[string]interface{}{
		SecretDataField: secret.Data,
	}

	_, err = c.client.Logical().Write(dataPath, secretData)
	if err != nil {
		return fmt.Errorf("unable to write secret's data: %w", err)
	}

	// Write secret's metadata in Vault
	fullMetadata := map[string]interface{}{
		SecretCustomDataField: secret.Metadata,
	}

	_, err = c.client.Logical().Write(metadataPath, fullMetadata)
	if err != nil {
		return fmt.Errorf("unable to write secret's metadata: %w", err)
	}

	return nil
}

func (c *VaultApi) ReadSecret(secretPath string) (*Secret, error) {

	// Get data path for secret in Vault
	dataPath, err := secretDataPath(secretPath, c.client)
	if err != nil {
		return nil, fmt.Errorf("invalid path for data: %w", err)
	}

	// Check if secret exists or is deleted
	secret, err := c.client.Logical().Read(dataPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read secret's data: %w", err)
	}
	if secret == nil {
		return nil, nil
	}

	isDeleted, err := isSecretDeleted(secret)
	if err != nil {
		return nil, fmt.Errorf("unable to check secret's deletion status: %w", err)
	}

	if isDeleted {
		return nil, fmt.Errorf("secret is marked deleted")
	}

	// Get metadata path for secret in Vault
	metadataPath, err := secretMetadataPath(secretPath, c.client)
	if err != nil {
		return nil, fmt.Errorf("invalid path for metadata: %w", err)
	}

	// Fetch secret's metadata from Vault
	secretMetadata, err := c.client.Logical().Read(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read secret's metadata: %w", err)
	}

	if secretMetadata.Data[SecretCustomDataField] == nil {
		return nil, fmt.Errorf("missing custom metadata")

	}
	customMetadata := make(map[string]string)
	for k, v := range secretMetadata.Data[SecretCustomDataField].(map[string]interface{}) {
		customMetadata[k] = v.(string)
	}

	data := secret.Data[SecretDataField].(map[string]interface{})

	vaultSecret := &Secret{
		Path:     secretPath,
		Data:     data,
		Metadata: customMetadata,
	}

	return vaultSecret, nil
}

func (c *VaultApi) UpdateSecretMetadata(secretPath string, metadata map[string]string) error {
	// Get metadata path for secret in Vault
	metadataPath, err := secretMetadataPath(secretPath, c.client)
	if err != nil {
		return fmt.Errorf("invalid path for metadata: %w", err)
	}

	// Get secret's metadata from Vault
	secretMetadata, err := c.client.Logical().Read(metadataPath)
	if err != nil {
		return fmt.Errorf("unable to read secret's metadata: %w", err)
	}

	if secretMetadata.Data[SecretCustomDataField] == nil {
		return fmt.Errorf("missing custom metadata")
	}

	// Update secret's metadata from plan (only metadata can be changed)
	updatedMetadata := make(map[string]string)

	for k, v := range metadata {
		updatedMetadata[k] = v
	}

	fullMetadata := map[string]interface{}{
		SecretCustomDataField: updatedMetadata,
	}

	_, err = c.client.Logical().Write(metadataPath, fullMetadata)
	if err != nil {
		return fmt.Errorf("unable to write secret's metadata: %w", err)
	}
	return nil
}

func (c *VaultApi) DeleteSecret(secretPath string) error {
	// Get metadata path for secret in Vault
	metadataPath, err := secretMetadataPath(secretPath, c.client)
	if err != nil {
		return fmt.Errorf("invalid path for metadata: %w", err)
	}

	// Retrieve secret's metadata from Vault
	secret, err := c.client.Logical().Read(metadataPath)
	if err != nil {
		return fmt.Errorf("unable to read secret's metadata: %w", err)

	}
	if secret == nil {
		return fmt.Errorf("no metadata for secret")
	}

	var metadata secretV2Metadata
	err = mapstructure.Decode(secret.Data, &metadata)
	if err != nil {
		return fmt.Errorf("unable to read secret's metadata: %w", err)
	}

	// List all secret's version to be deleted
	versionsToDelete := make([]int, 0)
	for k, v := range metadata.Versions {
		if v.DeletionTime != "" {
			continue
		}
		version, err := strconv.Atoi(k)
		if err != nil {
			return fmt.Errorf("unable to read secret version: %w", err)
		}
		versionsToDelete = append(versionsToDelete, version)
	}

	// Get delete path for secret in Vault
	deletePath, err := secretMetadataPath(secretPath, c.client)
	if err != nil {
		return fmt.Errorf("invalid path for deletion: %w", err)
	}

	// Delete all active secret's versions in Vault (just flag, nothing will be lost)
	_, err = c.client.Logical().Delete(deletePath)
	if err != nil {
		return fmt.Errorf("unable to mark secret's versions as deleted: %w", err)
	}

	return nil
}
