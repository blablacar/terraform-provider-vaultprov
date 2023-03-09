provider "vaultprov" {
  address = "http://some.vault:8200"
  auth    = {
    path = "auth/kubernetes/login"
    role = "some role"
    jwt  = file("/var/run/secrets/kubernetes.io/serviceaccount/token")
  }

  #token   = "ROOT_TOKEN"
}
