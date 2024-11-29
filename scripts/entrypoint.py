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

log_level = logging.DEBUG if os.getenv("INPUT_DEBUG", False) else logging.INFO
logging.basicConfig(format="%(levelname)s: %(message)s", level=log_level)
METADATA_RE = re.compile(r"apt-action-metadata:?\s*({.+})$")


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
        apt_dir (str): The path to the top-level directory of the repository.
    """

    gpg: gnupg.GPG
    git_repo: git.Repo
    config: Dict[str, Optional[str]]
    supported_versions: List[str]
    supported_archs: List[str]
    deb_files: List[str]
    private_key_id: str
    deb_files_hashes: Dict[str, str]
    apt_dir: str
    git_working_folder: str

    def __init__(self) -> None:
        """Init all variables"""
        self.config = {
            "github_repo": os.getenv("GITHUB_REPOSITORY"),
            "github_token": None,
            "supported_arch": None,
            "supported_version": None,
            "deb_file_target_version": None,
            "key_private": None,
        }
        self.supported_versions = []
        self.supported_archs = []
        self.deb_files = []
        self.git_repo = None
        self.gpg = gnupg.GPG()
        self.private_key_id = ""
        self.deb_files_hashes = {}
        self.apt_dir = ""

    @staticmethod
    def detect_public_key(gpg: gnupg.GPG, key_filename: str, pub_key: Optional[str] = None):
        """Check if public key file exists in repository, and import if necessary.

        Args:
            gpg: A GPG object used for importing the public key.
            key_filename: A string representing the filename of the public key.
            pub_key: An optional string representing the public key.

        Raises:
            KeyError: If the public key file is not found and no pub_key is provided.
            RuntimeError: If the public key is invalid.

        Returns:
            None.
        """
        has_key_file = os.path.isfile(key_filename)
        if pub_key:
            logging.debug("Trying to import key")
            res = gpg.import_keys(pub_key)
            if res.count != 1:
                raise RuntimeError("Invalid public key provided, please provide 1 valid key")
        elif has_key_file:
            with open(key_filename, "r") as f:
                pub_key = f.read()
                logging.debug("Trying to import key")
                res = gpg.import_keys(pub_key)
                if res.count != 1:
                    raise RuntimeError("Invalid public key provided, please provide 1 valid key")
        else:
            logging.info("Directory doesn't contain %s key trying to import", key_filename)
            raise KeyError("Please specify public key for setup")

        if not has_key_file:
            with open(key_filename, "w") as f:
                f.write(pub_key)

        logging.info("Public key valid")

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

        # Check if the key is a secret key
        if all(data["ok"] < "16" for data in res.results):
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
        self.config["deb_file_target_version"] = options.get("INPUT_FILE_TARGET_VERSION")
        self.config["key_private"] = options.get("INPUT_PRIVATE_KEY")

        for ky, vl in self.config.items():
            if not vl or not vl.strip():
                raise RuntimeError(f"Missing required parameter: {ky}")
            self.config[ky] = vl.strip()

        # Parse and validate optional parameters
        self.config["gh_branch"] = options.get("INPUT_PAGE_BRANCH", "gh-pages")
        self.config["apt_folder"] = options.get("INPUT_REPO_FOLDER", "repo")
        self.config["key_passphrase"] = options.get("INPUT_KEY_PASSPHRASE")
        self.config["key_public"] = options.get("INPUT_PUBLIC_KEY")

        # Parse deb files and validate their existence
        deb_file_path = options.get("INPUT_FILE", "").strip()
        if not deb_file_path:
            raise RuntimeError("Missing required parameter: file")

        file_list = set()
        for line in deb_file_path.split("\n"):
            for s in glob.glob(line.strip('" ')):
                file_list.add(s)

        self.deb_files = list(file_list)
        if not self.deb_files:
            raise RuntimeError(f"No deb file(s) found for: {deb_file_path}")

        # Parse supported architectures and versions
        self.supported_archs = self.config["supported_arch"].split("\n")
        self.supported_versions = self.config["supported_version"].split("\n")
        self.config["deb_file_version"] = self.config["deb_file_target_version"]

        # Validate if deb file version is supported
        if self.config["deb_file_version"] not in self.supported_versions:
            raise ValueError(
                f'File version "{self.config["deb_file_version"]}" is not listed in repo supported version list'
            )

        logging.debug(self.config)
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
            raise git.GitCommandError("Unable to clone repository." +
                                      "Please ensure that the Github repository URL and access token are valid.") from e

        # Check if the specified branch exists in the repository
        git_refs = self.git_repo.remotes.origin.refs
        git_refs_name = [str(ref).split("/")[-1] for ref in git_refs]
        logging.debug(git_refs_name)

        if self.config["gh_branch"] not in git_refs_name:
            # Create a new branch if the specified branch does not exist
            self.git_repo.git.checkout(b=self.config["gh_branch"])
        else:
            # Checkout the specified branch if it exists
            self.git_repo.git.checkout(self.config["gh_branch"])

    def generate_metadata(self) -> None:
        """Generate metadata of first given .deb file

        Raises:
            RuntimeError: If no .deb file is found or an error occurs while reading .deb control file
        """
        logging.debug(f"cwd: {os.getcwd()}")
        logging.debug(os.listdir())

        # Extract metadata from first .deb file
        deb_file_handle = DebFile(filename=self.deb_files[0])
        try:
            deb_file_control = deb_file_handle.debcontrol()
        except ValueError as e:
            raise RuntimeError(f"Error reading debcontrol file of {self.deb_files[0]}") from e

        # Store metadata in self.current_metadata dictionary
        self.current_metadata = {
            "format_version": 1,
            "sw_version": deb_file_control["Version"],
            "sw_architecture": deb_file_control["Architecture"],
            "linux_version": self.config["deb_file_version"],
        }

        logging.debug("Metadata %s", json.dumps(self.current_metadata))

    def fetch_repository_metadata(self) -> None:
        """Fetch metadata of repository and check if the package version already exists

        The function iterates through all commits on the branch and filters out commits
        that contain metadata in the commit message. The metadata is then parsed and stored
        as a list of dictionaries. The function checks if the metadata for the current package
        version already exists in the list. If so, the function exits the program.

        Raises:
            SystemExit: The specified version of this package has already been added to the repository
        """
        logging.info("Fetching repository metadata")

        # Get all commits on the branch
        all_commits = self.git_repo.iter_commits(self.config["gh_branch"])

        # Filter out commits that contain "[apt-action]" in the commit message
        apt_action_commits = list(filter(lambda x: x.message.startswith("[apt-action]"), all_commits))

        # Extract metadata from commit messages
        apt_action_metadata_str = list(map(lambda x: METADATA_RE.findall(x.message), apt_action_commits))

        # Filter out metadata strings that don't match the expected pattern
        apt_action_valid_metadata_str = list(filter(lambda x: len(x) > 0, apt_action_metadata_str))

        # Parse metadata strings into a list of dictionaries
        apt_action_metadata = list(map(lambda x: json.loads(x[0]), apt_action_valid_metadata_str))

        # Check if the metadata for the current package version already exists in the list
        for check_metadata in apt_action_metadata:
            if check_metadata == self.current_metadata:
                logging.info("The specified version of this package has already been added to the repository - skipped.")
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

        # Import keys
        self.detect_public_key(self.gpg, public_key_path, self.config["key_public"])
        self.private_key_id = self.import_private_key(self.gpg, self.config["key_private"])

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
            os.mkdir(self.apt_dir)
            os.mkdir(apt_conf_dir)

        logging.debug("Creating repo config")
        repo_config_fn = os.path.join(apt_conf_dir, "distributions")

        # Create repo config file
        with open(repo_config_fn, "w") as df:
            for codename in self.supported_versions:
                df.write(f"Description: {self.config['github_repo']}\n")
                df.write(f"Codename: {codename}\n")
                df.write(f"Architectures: {' '.join(self.supported_archs)}\n")
                df.write("Components: main\n")
                df.write(f"SignWith: {self.private_key_id}\n")
                df.write("\n\n")

        logging.info("Done preparing repo directory")

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
            logging.info(f"* {deb_file}")
            subprocess.run(
                [
                    "reprepro",
                    "-b",
                    self.apt_dir,
                    "--keepunusednewfiles",
                    "--ignore=undefinedtarget",
                    "--export=silent-never",
                    "includedeb",
                    self.config["deb_file_version"],
                    deb_file,
                ],
                check=True,
            )
            self.deb_files_hashes[deb_file] = self.generate_deb_hash(deb_file, "sha1")

        # Unlock key on gpg agent
        self.gpg.sign("test", keyid=self.private_key_id, passphrase=self.config.get("key_passphrase", ""))

        # Export and sign repo
        subprocess.run(["reprepro", "-b", self.apt_dir, "--ignore=undefinedtarget", "export"], check=True)

        logging.info("Done adding package to repo")

    def finish(self) -> None:
        """Commit changes to Git repository and push to GitHub

        Uses gitpython to add and commit changes to the local git repository
        and push them to the specified branch of the GitHub repository.

        """
        # Commit and push changes
        logging.info("Saving changes")

        # Set user email to avoid git errors
        github_user = self.config["github_repo"].split("/")[0]
        self.git_repo.config_writer().set_value(
            "user", "email", f"{github_user}@users.noreply.github.com"
        )

        # Add all files to commit
        self.git_repo.git.add("*")

        # Create commit message with added/updated files and metadata
        commit_msg = "[apt-action] Update apt repo\n\n\nAdded/updated file(s):\n"
        for deb_file in self.deb_files:
            commit_msg += f"{self.deb_files_hashes[deb_file]}  {deb_file}\n"

        commit_msg += (
            f'\n\napt-action-metadata: {json.dumps(self.current_metadata)}'
            f'\ndeploying: {os.getenv("GITHUB_SHA")}'
        )

        # Commit changes
        self.git_repo.index.commit(commit_msg)

        # Push changes to GitHub repository
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
