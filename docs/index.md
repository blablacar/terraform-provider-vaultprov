---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "vaultprov Provider"
subcategory: ""
description: |-
  A provider to generate secrets and have them stored directly into Vault without any copy in the Terraform State.  Once the secret has been generated, its value only exist into Vault. Terraform will not track any change in the value, only in the secret attribute (metadata, etc.`).
---

# vaultprov Provider

A provider to generate secrets and have them stored directly into Vault without any copy in the Terraform State.  Once the secret has been generated, its value only exist into Vault. Terraform will not track any change in the value, only in the secret attribute (`metadata`, etc.`).

## Example Usage

```terraform
provider "vaultprov" {
  address = "http://some.vault:8200"
  auth    = {
    path = "auth/kubernetes/login"
    role = "some role"
    jwt  = file("/var/run/secrets/kubernetes.io/serviceaccount/token")
  }

  #token   = "ROOT_TOKEN"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `address` (String) Origin URL of the Vault server. This is a URL with a scheme, a hostname and a port but with no path.
- `auth` (Attributes) (see [below for nested schema](#nestedatt--auth))
- `token` (String) Vault token that will be used by Terraform to authenticate. For debug purpose only. For production, use the `auth` attributes

<a id="nestedatt--auth"></a>
### Nested Schema for `auth`

Required:

- `jwt` (String) The JWT of the Kubernetes Service Account against which the login is being attempted.
- `path` (String) The login path of the auth Kubernetes backend. For example, `auth/kubernetes/gke-tools-1/login`
- `role` (String) The name of the role against which the login is being attempted.
