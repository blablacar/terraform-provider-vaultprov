resource "vaultprov_random_secret" "example" {
  path     = "/secret/foo/bar"
  length   = 32
  metadata = {
    owner    = "my_team"
    some-key = "some-value"
  }
}
