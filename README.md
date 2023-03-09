# Terraform Provider vaultprov

`blablacar/vaultprov` is a custom provider to generate and store random secrets directly into Vault without storing any sensitive value into Terraform state. Secrets metadata are still stored into Terraform state as for any other resources, only the secret itself isn't.

## Resources
There's only one resource: `vaultprov_random_secret`. It will generate a fully random bytes array that can be used for symmetric cryptography operation (encryption, MAC).

```hcl
resource "vaultprov_random_secret" "my_key" {
    path     = "/secrets/foo/bar"
    length   = 32
    metadata = {
        owner    = "my_team"
        some-key = "some-value"
    }
}
```
`vaultprov_random_secret` attributes:
- `path`: path of the generated Secret into Vault. Must be a path to a [KV v2 mount](https://www.vaultproject.io/docs/secrets/kv/kv-v2). Used as ID for the resource
- `length`: length of the secret (default: `32`)
- `metadata`: Key/value (`string` only) custom metadata that will be added to the Vault Secret 

The resulting Vault secret will have 2 additional metadata:
- `secret_type`:`random_secret` value
- `secret_length`: secret length as defined in Terraform

Once created, only metadata can be updated without deleting the secret. `path` can't be changed afterward. Changing `length` will cause the secret to be deleted and re-created.

:warning: When deleting a `vaultprov_random_secret` resource, every secret's versions and metadata will be **permanently deleted**.

## Provider configuration
In order to communicate with a Vault cluster, the provider needs to be configured accordingly. Only [Kubernetes authentication](https://www.vaultproject.io/docs/auth/kubernetes) is supported.

```hcl
terraform {
  required_providers {
    vaultprov = {
      source  = "blablacar/vaultprov"
      version = "0.2.0"
    }
  }
}

provider "vaultprov" {
  address = "https://some.vault.com:8200"

  auth = {
    path     = "auth/kubernetes/login"
    role     = "some-role"
    jwt      = file("/var/run/secrets/kubernetes.io/serviceaccount/token")
  }
}
```
Provider attributes:
- `address`: Vault address
- `auth`
  - `path`: Authentication endpoint to use with Vault
  - `role`: Vault Kubernetes authentication role to use
  - `jwt`: Path of the local Kubernetes service account to be used for authentication

## Build

To build for current or specific arch:
```shell
make build
# or
OS_ARCH="linux_amd64" make build
```

To build & install on locally
```shell
make install
# or
OS_ARCH="linux_amd64" make install
```

To build for release:
```shell
make release
```

To generate documentation:
```shell
make docs
```
