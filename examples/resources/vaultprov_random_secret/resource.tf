resource "vaultprov_random_secret" "example_bytes" {
  path   = "/secret/foo/bar"
  type   = "random_secret"
  length = 32
  metadata = {
    owner    = "my_team"
    some-key = "some-value"
  }
}

resource "vaultprov_random_secret" "example_keypair" {
  path = "/secret/bar/foo"
  type = "curve25519_keypair"
  metadata = {
    owner    = "my_team"
    some-key = "some-value"
  }
}
