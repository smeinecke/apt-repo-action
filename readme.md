# Github pages APT repo

This action will setup and manage a simple APT repo on your github pages

## Inputs

### `github_token`

**Required** Personal access token with commit and push scope granted.

### `repo_supported_arch`

**Required** Newline-delimited list of supported architecture

### `repo_supported_version`

**Required** Newline-delimited list of supported (linux) version

### `file`

**Required** .deb file(s) to be included - accepts wildcards

### `file_target_version`

**Required** Version target of supplied .deb file

### `private_key`

**Required** GPG private key for signing APT repo

### `public_key`

GPG public key for APT repo

### `key_passphrase`

Passphrase of GPG private key

### `page_branch`

Branch of Github pages. Defaults to `gh-pages`

### `repo_folder`

Location of APT repo folder relative to root of Github pages. Defaults to `repo`

### `github_repository`

Target repository of the Github pages. Defaults to current repository.

## Example usage

```yaml
uses: smeinecke/apt-repo-action@v2.1.2
with:
  github_token: ${{ secrets.PAT }}
  arch: |
    amd64
    i386
  version: |
    focal
    jammy
  file: my_program_jammy.deb
  file_target_version: jammy
  public_key: ${{ secrets.PUBLIC }}
  private_key: ${{ secrets.PRIVATE }}
  key_passphrase: ${{ secrets.SECRET }}
```
