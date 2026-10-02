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

**Required** .deb file(s) to be included. Accepts a newline-delimited list; each entry may be a path or a glob pattern (e.g. `dist/*.deb`; `**` recurses into subdirectories). Matches that do not end in `.deb` are ignored.

### `file_target_version`

Version target of supplied .deb file. **Required** unless `version_by_filename` is enabled.

### `private_key`

**Required** GPG private key for signing APT repo

### `public_key`

GPG public key for APT repo, not needed if public.key file found in repository

### `key_passphrase`

Passphrase of GPG private key

### `page_branch`

Branch of Github pages (whitespace is not allowed). Defaults to `gh-pages`

### `repo_folder`

Location of APT repo folder relative to root of Github pages (`..` components are rejected). Defaults to `repo`

### `github_repository`

Target repository of the Github pages in `owner/repository` form. Defaults to current repository.

### `skip_duplicates`

Skip already added packages if same version already exists (regardless of checksum), instead of failing. Default is `false`

### `version_by_filename`

Get `file_target_version` from the filename of each .deb file instead of `file_target_version`. The codename is read from the version segment of the Debian filename (`<name>_<version>_<arch>.deb`): it must contain `~<codename>` followed by `.`, `_`, `-`, a digit, or the end of the version segment — e.g. `mypackage_1.0~bookworm_amd64.deb`. Default is `false`

## Notes

- The action publishes the signing key as `public.key` (ASCII-armored) and `public.gpg` (binary) at the root of the pages branch; both are always regenerated from `private_key`. `public_key` (or existing `public.key`/`public.gpg` files) are only imported into the keyring and are not required.
- If a push is rejected because another run already pushed to `page_branch`, the action fetches, rebases onto the latest remote state, and retries once. Concurrent runs that touch the same files can still conflict — serialize concurrent jobs when in doubt (e.g. matrix builds with `max-parallel: 1` as in the example below).
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
        uses: smeinecke/apt-repo-action@v2.2.1
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
