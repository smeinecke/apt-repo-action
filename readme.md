# Github pages APT repo

This action will setup and manage a simple APT repo on your github pages

## Inputs

### `github_token`

**Required** Personal access token with commit and push scope granted. Can be set by using the github.token environment variable in your workflow.

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

jobs:
  add_repo:
    runs-on: ubuntu-latest
    needs: build-debs
    strategy:
      max-parallel: 1
      matrix:
        os-version: ["buster", "bullseye", "bookworm"]
        arch: ["amd64", "arm64"]
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: "packages-${{ matrix.os-version }}-${{ matrix.arch }}"
      - name: Add ${{ matrix.arch }}/${{ matrix.os-version }} release
        uses: smeinecke/apt-repo-action@v2.1.4
        with:
          github_token: ${{ github.token }}
          repo_supported_arch: |
            amd64
            arm64
          repo_supported_version: |
            buster
            bullseye
            bookworm
          file: |
            *~${{ matrix.os-version }}*.deb
          file_target_version: ${{ matrix.os-version }}
          private_key: ${{ secrets.APT_SIGNING_KEY }}
          key_passphrase: ""
```
