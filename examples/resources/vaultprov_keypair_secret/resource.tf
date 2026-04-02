resource "vaultprov_keypair_secret" "example_keypair" {
  base_path = "/secret/bar/foo"
  type = "curve25519"
  metadata = {
    owner    = "my_team"
    some-key = "some-value"
  }
}
