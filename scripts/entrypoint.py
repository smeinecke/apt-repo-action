from typing import Dict, Optional, List
import os
import sys
import logging
import gnupg
import git
import glob
import shutil
import re
import json
import hashlib
import subprocess

from debian.debfile import DebFile

log_level = logging.DEBUG if os.getenv("INPUT_DEBUG", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
} else logging.INFO
logging.basicConfig(format="%(levelname)s: %(message)s", level=log_level)
METADATA_RE = re.compile(r"apt-action-metadata:?\s*({.+})$", re.MULTILINE)


class _SecretRedactFormatter(logging.Formatter):
    """Log formatter that redacts secret values from all output, including tracebacks."""

    def __init__(self, fmt: str, secrets: List[Optional[str]]) -> None:
        super().__init__(fmt)
        self.secrets = [secret for secret in secrets if secret]

    def format(self, record: logging.LogRecord) -> str:
        output = super().format(record)
        for secret in self.secrets:
            output = output.replace(secret, "***")
        return output


class DebRepositoryBuilder:
    """
    Attributes:
        gpg (gnupg.GPG): A GPG instance used for signing the repository.
        git_repo (git.Repo): A Git repository instance used for managing the repository.
        config (dict): A dictionary containing configuration options for the repository.
        supported_versions (list): A list of supported Debian versions.
        supported_archs (list): A list of supported CPU architectures.
        deb_files (list): A list of .deb package files to include in the repository.
        private_key_id (str): The ID of the private key to use for signing the repository.
        deb_files_hashes (dict): A dictionary mapping package file names to their SHA256 hashes.
        deb_files_metadata (dict): A dictionary mapping package file names to their metadata.
        apt_dir (str): The path to the top-level directory of the repository.
    """

    gpg: gnupg.GPG
    git_repo: Optional[git.Repo]
    config: Dict[str, Optional[str]]
    supported_versions: List[str]
    supported_archs: List[str]
    deb_files: List[str]
    private_key_id: str
    deb_files_hashes: Dict[str, str]
    deb_files_versions: Dict[str, str]
    deb_files_metadata: Dict[str, Dict[str, object]]
    apt_dir: str
    git_working_folder: str
    gh_branch_exists: bool

    def __init__(self) -> None:
        """Init all variables"""
        self.config = {
            "github_repo": os.getenv("GITHUB_REPOSITORY"),
            "github_token": None,
            "supported_arch": None,
            "supported_version": None,
            "key_private": None,
        }
        self.supported_versions = []
        self.supported_archs = []
        self.deb_files = []
        self.git_repo = None
        self.gpg = gnupg.GPG()
        self.private_key_id = ""
        self.deb_files_hashes = {}
        self.deb_files_versions = {}
        self.deb_files_metadata = {}
        self.apt_dir = ""
        self.gh_branch_exists = False

    @staticmethod
    def parse_bool(value: Optional[str]) -> bool:
        """Parse a GitHub Action boolean-style input."""
        if value is None:
            return False
        return value.strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def split_multiline(value: str) -> List[str]:
        """Split a multiline input into stripped, non-empty lines."""
        return [line.strip() for line in value.splitlines() if line.strip()]

    @staticmethod
    def import_public_key(
        gpg: gnupg.GPG,
        armored_key_path: str,
        binary_key_path: str,
        pub_key: Optional[str] = None,
    ) -> None:
        """Import a public key from input or repository files when available.

        Args:
            gpg: A GPG object used for importing the public key.
            armored_key_path: Path of the ASCII-armored public key.
            binary_key_path: Path of the binary exported public key.
            pub_key: An optional string representing the public key.

        Raises:
            RuntimeError: If the public key is invalid.
        """
        if pub_key:
            logging.debug("Trying to import key")
            res = gpg.import_keys(pub_key)
            if res.count < 1:
                raise RuntimeError("Invalid public key provided, please provide a valid key")
            logging.info("Public key valid")
            return

        if os.path.isfile(armored_key_path):
            with open(armored_key_path, "r", encoding="utf-8") as f:
                key_data = f.read()
                logging.debug("Trying to import key")
                res = gpg.import_keys(key_data)
                if res.count < 1:
                    raise RuntimeError("Invalid public key provided, please provide a valid key")
            logging.info("Public key valid")
            return

        if os.path.isfile(binary_key_path):
            with open(binary_key_path, "rb") as f:
                key_data = f.read()
                logging.debug("Trying to import binary key")
                res = gpg.import_keys(key_data)
                if res.count < 1:
                    raise RuntimeError("Invalid public key provided, please provide a valid key")
            logging.info("Public key valid")
            return

        logging.info(
            "Directory doesn't contain %s or %s key, continuing with private key only",
            armored_key_path,
            binary_key_path,
        )

    @staticmethod
    def import_private_key(gpg: gnupg.GPG, sign_key: str) -> str:
        """
        Import private key into GPG object.

        Args:
            gpg (gnupg.GPG): The GPG object to import the key into.
            sign_key (str): The string representation of the private key.

        Returns:
            str: The fingerprint of the imported key.

        Raises:
            RuntimeError: If the private key provided is invalid.
            TypeError: If the key provided is not a secret key.
        """
        logging.info("Importing private key")
        res = gpg.import_keys(sign_key)

        # Check if the key is valid
        if res.count != 1:
            raise RuntimeError("Invalid private key provided, please provide 1 valid key")

        # Check if the key is a secret key (IMPORT_OK flag 0x10 = secret key imported)
        has_secret = any(int(data.get("ok") or 0) & 16 for data in res.results)
        if not has_secret:
            raise TypeError("Key provided is not a secret key")

        private_key_id = res.results[0]["fingerprint"]

        # Log success message and key id
        logging.debug("Key id: %s", private_key_id)
        logging.info("Done importing private key")

        return private_key_id

    def parse_inputs(self, options: Dict[str, str]) -> None:
        """Parse all given arguments and validate syntax

        Args:
            options (Dict[str, str]): Options to validate

        Raises:
            ValueError: Key or Value missing / has invalid syntax
            RuntimeError: Missing required parameter: file / Missing required parameter: {ky}
        """

        # Parse and validate required parameters
        logging.info("Parsing input")
        if options.get("INPUT_GITHUB_REPOSITORY"):
            self.config["github_repo"] = options.get("INPUT_GITHUB_REPOSITORY")
        self.config["github_token"] = options.get("INPUT_GITHUB_TOKEN")
        self.config["supported_arch"] = options.get("INPUT_REPO_SUPPORTED_ARCH")
        self.config["supported_version"] = options.get("INPUT_REPO_SUPPORTED_VERSION")
        self.config["key_private"] = options.get("INPUT_PRIVATE_KEY")

        for ky, vl in self.config.items():
            if not vl or not vl.strip():
                raise RuntimeError(f"Missing required parameter: {ky}")
            self.config[ky] = vl.strip()

        # Redact secrets from all subsequent log output (including tracebacks)
        redacting_formatter = _SecretRedactFormatter(
            "%(levelname)s: %(message)s",
            [
                self.config["github_token"],
                self.config["key_private"],
                options.get("INPUT_KEY_PASSPHRASE"),
            ],
        )
        for handler in logging.getLogger().handlers:
            handler.setFormatter(redacting_formatter)

        if "/" not in self.config["github_repo"]:
            raise RuntimeError(
                f'Invalid github_repository format "{self.config["github_repo"]}", '
                "expected owner/repository"
            )

        # Parse and validate optional parameters
        self.config["deb_file_target_version"] = options.get("INPUT_FILE_TARGET_VERSION")
        self.config["gh_branch"] = (
            options.get("INPUT_PAGE_BRANCH") or "gh-pages"
        ).strip() or "gh-pages"
        self.config["apt_folder"] = (
            options.get("INPUT_REPO_FOLDER") or "repo"
        ).strip().strip("/") or "repo"
        self.config["key_passphrase"] = options.get("INPUT_KEY_PASSPHRASE")
        self.config["key_public"] = options.get("INPUT_PUBLIC_KEY")
        self.config["skip_duplicates"] = self.parse_bool(options.get("INPUT_SKIP_DUPLICATES"))
        self.config["version_by_filename"] = self.parse_bool(
            options.get("INPUT_VERSION_BY_FILENAME")
        )

        if not self.config["deb_file_target_version"] and not self.config["version_by_filename"]:
            raise RuntimeError(
                "Missing required parameter: deb_file_target_version or version_by_filename"
            )


        # Parse deb files and validate their existence
        deb_file_path = options.get("INPUT_FILE", "").strip()
        if not deb_file_path:
            raise RuntimeError("Missing required parameter: file")

        file_list = set()
        for line in deb_file_path.split("\n"):
            for deb_file in glob.glob(line.strip('" ')):
                if not deb_file.endswith(".deb"):
                    logging.warning("Ignoring non-deb file match: %s", deb_file)
                    continue
                file_list.add(os.path.normpath(deb_file))

        self.deb_files = sorted(file_list)
        if not self.deb_files:
            raise RuntimeError(f"No deb file(s) found for: {deb_file_path}")

        # Parse supported architectures and versions (deduplicated, order preserved)
        self.supported_archs = list(
            dict.fromkeys(self.split_multiline(self.config["supported_arch"]))
        )
        self.supported_versions = list(
            dict.fromkeys(self.split_multiline(self.config["supported_version"]))
        )
        if not self.supported_archs or not self.supported_versions:
            raise RuntimeError(
                "Parameters supported_arch and supported_version must not be empty"
            )

        if self.config["version_by_filename"]:
            # Escape versions and match longest first so that e.g.
            # "bookworm-backports" is not shadowed by "bookworm"
            escaped_versions = sorted(
                (re.escape(version) for version in self.supported_versions),
                key=len,
                reverse=True,
            )
            version_re = re.compile(r"~(" + "|".join(escaped_versions) + r")[\d_.-]")
            for deb_file in self.deb_files:
                f = version_re.search(deb_file)
                if not f:
                    raise ValueError(f"File {deb_file} has no valid version in filename")
                self.deb_files_versions[deb_file] = f.group(1)
            self.config["deb_file_version"] = None
        else:
            self.config["deb_file_version"] = self.config["deb_file_target_version"]

            # Validate if deb file version is supported
            if self.config["deb_file_version"] not in self.supported_versions:
                raise ValueError(
                    f'File version "{self.config["deb_file_version"]}" is not listed in repo supported version list'
                )

        logging.debug(
            {
                key: (
                    "***"
                    if key in {"github_token", "key_private", "key_passphrase"}
                    else value
                )
                for key, value in self.config.items()
            }
        )
        logging.info("Done parsing input")

    def clone_repo(self) -> None:
        """Clone the current Github repository into the container.

        :raises git.GitCommandError: If the repository cannot be cloned.
        """
        logging.info("Cloning current Github page")

        # Extract repository slug from the URL
        github_slug = self.config["github_repo"].split("/")[1]

        # Set working folder name and delete any existing folder
        self.git_working_folder = f"{github_slug}-{self.config['gh_branch']}"
        if os.path.exists(self.git_working_folder):
            shutil.rmtree(self.git_working_folder)

        # Clone repository using access token and working folder
        logging.debug(f"cwd: {os.getcwd()}")
        logging.debug(os.listdir())
        try:
            self.git_repo = git.Repo.clone_from(
                f'https://x-access-token:{self.config["github_token"]}@github.com/'
                f'{self.config["github_repo"]}.git',
                self.git_working_folder,
            )
        except git.GitCommandError as e:
            raise git.GitCommandError(
                "Unable to clone repository. Please ensure that the Github repository URL "
                f"and access token are valid. Details: {e}"
            ) from e

        # Check if the specified branch exists in the repository
        git_refs = self.git_repo.remotes.origin.refs
        git_refs_name = [ref.remote_head for ref in git_refs]
        logging.debug(git_refs_name)

        if self.config["gh_branch"] not in git_refs_name:
            # Create a new branch if the specified branch does not exist
            self.gh_branch_exists = False
            self.git_repo.git.checkout("--orphan", self.config["gh_branch"])
            self.git_repo.git.rm("-rf", "--ignore-unmatch", ".")
            for entry in os.listdir(self.git_working_folder):
                if entry == ".git":
                    continue
                entry_path = os.path.join(self.git_working_folder, entry)
                if os.path.isdir(entry_path):
                    shutil.rmtree(entry_path)
                else:
                    os.unlink(entry_path)
        else:
            # Checkout the specified branch if it exists
            self.gh_branch_exists = True
            self.git_repo.git.checkout(self.config["gh_branch"])

    def generate_metadata(self) -> None:
        """Generate metadata for all given .deb files

        Raises:
            RuntimeError: If an error occurs while reading a .deb control file
        """
        logging.debug(f"cwd: {os.getcwd()}")
        logging.debug(os.listdir())

        for deb_file in self.deb_files:
            deb_file_handle = DebFile(filename=deb_file)
            try:
                deb_file_control = deb_file_handle.debcontrol()
                self.deb_files_metadata[deb_file] = {
                    "format_version": 2,
                    "package": deb_file_control["Package"],
                    "sw_version": deb_file_control["Version"],
                    "sw_architecture": deb_file_control["Architecture"],
                    "linux_version": self.deb_files_versions.get(
                        deb_file, self.config["deb_file_version"]
                    ),
                }
            except (ValueError, KeyError) as e:
                raise RuntimeError(f"Error reading debcontrol file of {deb_file}") from e

            logging.debug(
                "Metadata %s: %s", deb_file, json.dumps(self.deb_files_metadata[deb_file])
            )

    def fetch_repository_metadata(self) -> None:
        """Fetch metadata of repository and skip packages that were already added

        The function iterates through all commits on the branch and filters out commits
        that contain metadata in the commit message. Each .deb file is checked
        individually: files whose metadata (package name, version, architecture and
        linux version) was already committed are removed from the list of files to
        add. This check only applies when ``skip_duplicates`` is enabled.

        Raises:
            SystemExit: All specified packages have already been added to the repository
        """
        logging.info("Fetching repository metadata")

        if not self.gh_branch_exists:
            logging.info("Target branch does not exist yet, skipping metadata lookup")
            return

        if not self.config["skip_duplicates"]:
            logging.info("skip_duplicates disabled, skipping metadata lookup")
            return

        # Collect metadata from all previous apt-action commits
        apt_action_metadata = []
        for commit in self.git_repo.iter_commits(self.config["gh_branch"]):
            if not commit.message.startswith("[apt-action]"):
                continue
            for match in METADATA_RE.findall(commit.message):
                try:
                    apt_action_metadata.append(json.loads(match))
                except json.JSONDecodeError:
                    logging.warning(
                        "Ignoring malformed metadata in commit %s", commit.hexsha
                    )

        # Drop files that were already added to the repository
        remaining_files = []
        for deb_file in self.deb_files:
            if self.deb_files_metadata[deb_file] in apt_action_metadata:
                logging.info("%s was already added to the repository - skipped", deb_file)
            else:
                remaining_files.append(deb_file)

        self.deb_files = remaining_files
        if not self.deb_files:
            logging.info("All specified packages have already been added to the repository.")
            sys.exit(0)

        logging.info("Done fetching repository metadata")

    def import_key(self) -> None:
        """Import private/public key and create missing folders.

        This function imports the public key and the private key into the GnuPG
        keyring and sets `self.private_key_id` to the ID of the imported private key.

        Raises:
            ValueError: If the public key file doesn't exist or is empty.
        """
        logging.info("Importing keys")

        # Prepare public key path
        public_key_path = os.path.join(self.git_working_folder, "public.key")
        public_gpg_path = os.path.join(self.git_working_folder, "public.gpg")

        # Import keys
        self.private_key_id = self.import_private_key(self.gpg, self.config["key_private"])
        self.import_public_key(
            self.gpg,
            public_key_path,
            public_gpg_path,
            self.config["key_public"],
        )

        armored_public_key = self.gpg.export_keys(self.private_key_id, armor=True)
        if not armored_public_key:
            raise RuntimeError("Unable to export armored public key")
        with open(public_key_path, "w", encoding="utf-8") as f:
            f.write(armored_public_key)

        binary_public_key = self.gpg.export_keys(self.private_key_id, armor=False)
        if not binary_public_key:
            raise RuntimeError("Unable to export binary public key")
        if isinstance(binary_public_key, str):
            binary_public_key = binary_public_key.encode("utf-8")
        with open(public_gpg_path, "wb") as f:
            f.write(binary_public_key)

        logging.info("Done importing keys")

    def prepare(self) -> None:
        """
        Import key and prepare repo directory.
        """
        # Import key
        self.import_key()

        # Prepare repo
        logging.info("Preparing repo directory")
        self.apt_dir = os.path.join(self.git_working_folder, self.config["apt_folder"])
        apt_conf_dir = os.path.join(self.apt_dir, "conf")

        # Create apt directory and apt conf directory if they do not exist
        if not os.path.isdir(self.apt_dir):
            logging.info("Existing repo not detected, creating new repo")
        os.makedirs(apt_conf_dir, exist_ok=True)

        logging.debug("Creating repo config")
        repo_config_fn = os.path.join(apt_conf_dir, "distributions")

        existing_stanzas = []
        if os.path.isfile(repo_config_fn):
            with open(repo_config_fn, "r", encoding="utf-8") as df:
                existing_stanzas = self._parse_stanzas(df.read())

        # Index existing stanzas by codename, keep stanzas without codename as-is
        stanzas_by_codename = {}
        passthrough_stanzas = []
        for stanza in existing_stanzas:
            codename = self._stanza_field(stanza, "Codename")
            if codename and codename not in stanzas_by_codename:
                stanzas_by_codename[codename] = stanza
            else:
                passthrough_stanzas.append(stanza)

        out_stanzas = []
        for codename in self.supported_versions:
            existing = stanzas_by_codename.pop(codename, None)
            if existing is not None:
                out_stanzas.append(self._merge_stanza(existing, codename))
            else:
                out_stanzas.append(
                    [
                        f"Description: {self.config['github_repo']}",
                        f"Codename: {codename}",
                        f"Architectures: {' '.join(self.supported_archs)}",
                        "Components: main",
                        f"SignWith: {self.private_key_id}",
                    ]
                )

        # Keep stanzas for codenames that are no longer in the supported list,
        # but refresh their SignWith so reprepro can sign them with the
        # currently imported key. Stanzas without a codename pass through.
        for stanza in stanzas_by_codename.values():
            out_stanzas.append(self._merge_stanza(stanza))
        out_stanzas.extend(passthrough_stanzas)

        with open(repo_config_fn, "w", encoding="utf-8") as df:
            for stanza in out_stanzas:
                df.write("\n".join(stanza))
                df.write("\n\n")

        logging.info("Done preparing repo directory")

    @staticmethod
    def _parse_stanzas(text: str) -> List[List[str]]:
        """Split a reprepro distributions file into stanzas (lists of lines)."""
        stanzas = []
        stanza = []
        for line in text.splitlines():
            if line.strip():
                stanza.append(line)
            elif stanza:
                stanzas.append(stanza)
                stanza = []
        if stanza:
            stanzas.append(stanza)
        return stanzas

    @staticmethod
    def _stanza_field(stanza: List[str], name: str) -> Optional[str]:
        """Return the value of the first occurrence of a field in a stanza."""
        for line in stanza:
            if line[:1] in (" ", "\t"):
                continue
            field, sep, value = line.partition(":")
            if sep and field.strip() == name:
                return value.strip()
        return None

    def _merge_stanza(self, stanza: List[str], codename: Optional[str] = None) -> List[str]:
        """Update managed fields of an existing stanza, preserving custom fields.

        SignWith is always refreshed to the currently imported key. When
        ``codename`` is given, Codename and Architectures are also refreshed
        and Description/Components are added when missing.
        """
        managed = {"SignWith": self.private_key_id}
        forced = {"SignWith"}
        if codename is not None:
            managed.update(
                {
                    "Description": self.config["github_repo"],
                    "Codename": codename,
                    "Architectures": " ".join(self.supported_archs),
                    "Components": "main",
                }
            )
            forced |= {"Codename", "Architectures"}
        merged = []
        emitted = set()
        drop_continuation = False
        for line in stanza:
            if line[:1] in (" ", "\t"):
                if not drop_continuation:
                    merged.append(line)
                continue
            field_name, sep, _ = line.partition(":")
            field_name = field_name.strip()
            drop_continuation = False
            if sep and field_name in managed:
                if field_name in emitted:
                    drop_continuation = True
                    continue
                if field_name in forced:
                    merged.append(f"{field_name}: {managed[field_name]}")
                    drop_continuation = True
                else:
                    merged.append(line)
                emitted.add(field_name)
            else:
                merged.append(line)
        for field_name, value in managed.items():
            if field_name not in emitted:
                merged.append(f"{field_name}: {value}")
        return merged

    @staticmethod
    def generate_deb_hash(filename: str, hash_type: str) -> str:
        """Generates the hash for a given file using the specified hash algorithm.

        Args:
            filename (str): The name of the file to hash.
            hash_type (str): The hash algorithm to use.

        Returns:
            str: The hexdigest of the generated hash.
        """
        # Initialize hash object with the specified algorithm
        h = hashlib.new(hash_type)

        # Define buffer size
        buffer_size = 128 * 1024

        # Use memoryview to read the file in chunks to optimize memory usage
        with open(filename, "rb", buffering=0) as f:
            while True:
                buffer = f.read(buffer_size)
                if not buffer:
                    break
                mv = memoryview(buffer)
                h.update(mv)

        # Return the hexdigest of the generated hash
        return h.hexdigest()

    def add_files(self) -> None:
        """Add all deb files to the repository and sign them"""
        logging.info("Adding deb files to repo")

        for deb_file in self.deb_files:
            logging.info("* %s", deb_file)
            try:
                res = subprocess.run(
                    [
                        "reprepro",
                        "-b",
                        self.apt_dir,
                        "--keepunusednewfiles",
                        "--ignore=undefinedtarget",
                        "--export=silent-never",
                        "includedeb",
                        self.deb_files_versions.get(deb_file, self.config["deb_file_version"]),
                        deb_file,
                    ],
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                if self.config["skip_duplicates"] and b'Already existing files can only be included again' in e.stderr:
                    logging.info("Skipping %s", deb_file)
                    continue
                logging.error("Failed to add %s to repo", deb_file)
                logging.error(e.stderr)
                raise e

            self.deb_files_hashes[deb_file] = self.generate_deb_hash(deb_file, "sha256")

        # Unlock key on gpg agent
        sign_result = self.gpg.sign(
            "test",
            keyid=self.private_key_id,
            passphrase=self.config["key_passphrase"],
        )
        if not sign_result:
            raise RuntimeError(
                "Unable to sign with private key - check private_key and key_passphrase"
            )

        # Export and sign repo
        subprocess.run(["reprepro", "-b", self.apt_dir, "--ignore=undefinedtarget", "export"], check=True)

        logging.info("Done adding package to repo")

    def finish(self) -> None:
        """Commit changes to Git repository and push to GitHub

        Uses gitpython to add and commit changes to the local git repository
        and push them to the specified branch of the GitHub repository.

        """
        if not self.deb_files_hashes:
            return

        # Commit and push changes
        logging.info("Saving changes")

        # Set user email to avoid git errors
        github_user = self.config["github_repo"].split("/")[0]
        with self.git_repo.config_writer() as config_writer:
            config_writer.set_value("user", "name", github_user)
            config_writer.set_value("user", "email", f"{github_user}@users.noreply.github.com")

        # Add all files to commit
        self.git_repo.git.add("*")

        # Abort if there is nothing to commit (e.g. identical re-run).
        # On a fresh orphan branch there is no HEAD yet, so the check is skipped.
        if self.gh_branch_exists and not self.git_repo.index.diff("HEAD"):
            logging.info("No changes to commit")
            return

        # Create commit message with added/updated files and metadata
        commit_msg = "[apt-action] Update apt repo\n\n\nAdded/updated file(s):\n"
        for deb_file in self.deb_files:
            if deb_file in self.deb_files_hashes:
                commit_msg += f"{self.deb_files_hashes[deb_file]}  {deb_file}\n"

        commit_msg += "\n"
        for deb_file in self.deb_files:
            if deb_file in self.deb_files_hashes:
                commit_msg += (
                    f"apt-action-metadata: "
                    f"{json.dumps(self.deb_files_metadata[deb_file])}\n"
                )
        commit_msg += f'deploying: {os.getenv("GITHUB_SHA")}'

        # Commit changes
        self.git_repo.index.commit(commit_msg)

        # Push changes to GitHub repository
        if self.gh_branch_exists:
            self.git_repo.git.push("origin", self.config["gh_branch"])
        else:
            self.git_repo.git.push("--set-upstream", "origin", self.config["gh_branch"])

        logging.info("Done saving changes")

    def run(self, options: Dict[str, str]) -> None:
        """Process the request and create/update the APT repository.

        Args:
            options (Dict[str, str]): The options passed to the action.

        Raises:
            Exception: If any error occurs during the execution of the methods.
        """
        try:
            self.parse_inputs(options)
            self.clone_repo()
            self.generate_metadata()
            self.fetch_repository_metadata()
            self.prepare()
            self.add_files()
            self.finish()
        except Exception as e:
            # Log the exception and exit with non-zero status code
            logging.exception(e)
            sys.exit(1)


if __name__ == "__main__":
    dpb = DebRepositoryBuilder()
    dpb.run(dict(os.environ))
