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

**Required** .deb file(s) to be included. Accepts a newline-delimited list; each entry may be a path or a glob pattern (e.g. `dist/*.deb`). Matches that do not end in `.deb` are ignored.

### `file_target_version`

Version target of supplied .deb file. **Required** unless `version_by_filename` is enabled.

### `private_key`

**Required** GPG private key for signing APT repo

### `public_key`

GPG public key for APT repo, not needed if public.key file found in repository

### `key_passphrase`

Passphrase of GPG private key

### `page_branch`

Branch of Github pages. Defaults to `gh-pages`

### `repo_folder`

Location of APT repo folder relative to root of Github pages. Defaults to `repo`

### `github_repository`

Target repository of the Github pages. Defaults to current repository.

### `skip_duplicates`

Skip already added packages if same version already exists (regardless of checksum), instead of failing. Default is `false`

### `version_by_filename`

Get `file_target_version` from the filename of each .deb file instead of `file_target_version`. The filename must contain `~<codename>` followed by `.`, `_`, `-` or a digit, e.g. `mypackage_1.0~bookworm_amd64.deb`. Default is `false`

## Notes

- The action publishes the signing key as `public.key` (ASCII-armored) and `public.gpg` (binary) at the root of the pages branch. `public_key` is optional — when omitted, an existing `public.key`/`public.gpg` on the branch is reused, otherwise the public part is derived from `private_key`.
- Concurrent runs against the same `page_branch` are not supported — the last push wins. Serialize concurrent jobs (e.g. matrix builds with `max-parallel: 1` as in the example below).
- Without `skip_duplicates`, re-adding an unchanged package version succeeds (idempotent), but re-adding the same version with *different content* fails. Set `skip_duplicates: true` to silently skip already added packages instead.

## Example usage

```yaml

jobs:
  add_repo:
    runs-on: ubuntu-latest
    needs: build-debs
    strategy:
      max-parallel: 1
      matrix:
        os-version: ["buster", "bullseye", "bookworm", "noble", "jammy", "focal"]
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
            noble
            jammy
            focal
          file: |
            *~${{ matrix.os-version }}*.deb
          file_target_version: ${{ matrix.os-version }}
          private_key: ${{ secrets.APT_SIGNING_KEY }}
          public_key: ${{ secrets.APT_SIGNING_PUBKEY }}
          key_passphrase: ${{ secrets.APT_SIGNING_KEY_PASSPHRASE }}
```
