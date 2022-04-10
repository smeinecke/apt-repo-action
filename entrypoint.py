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
from key import detectPublicKey, importPrivateKey

log_level = logging.INFO
if os.environ.get("INPUT_DEBUG", False):
    log_level = logging.DEBUG

logging.basicConfig(format="%(levelname)s: %(message)s", level=log_level)



class DebRepositoryBuilder:
    metadata_re = re.compile(r"apt-action-metadata:?\s*({.+})$")

    """Init process
    """
    def __init__(
        self,
    ) -> None:
        self.config = {
            "github_repo": None,
            "github_token": None,
            "supported_arch": None,
            "supported_version": None,
            "deb_file_target_version": None,
            "gh_branch": None,
            "apt_folder": None,
            "key_public": None,
            "key_private": None,
        }
        self.supported_versions = []
        self.supported_archs = []
        self.deb_files = []
        self.git_repo = None
        self.gpg = gnupg.GPG()
        self.private_key_id = ''
        self.deb_files_hashes = {}
        self.apt_dir = ''

    def run(self, options) -> None:
        """Process request and create/update repository

        :param options: list of options for this call
        :type options: dict
        """
        try:
            self.parseInputs(options)
            self.cloneRepo()
            self.generateMetadata()
            self.fetchRepositoryMetadata()
            self.prepare()
            self.addFiles()
            self.finish()
        except Exception as e:
            logging.exception(e)
            sys.exit(1)

    def parseInputs(self, options) -> None:
        """Parse all given arguments and validate syntax

        :param options: options to validate
        :type options: dict
        :raises ValueError: Key or Value missing / has invalid syntax
        """
        logging.info("-- Parsing input --")
        self.config["github_repo"] = options.get("GITHUB_REPOSITORY")
        self.config["github_token"] = options.get("INPUT_GITHUB_TOKEN")
        self.config["supported_arch"] = options.get("INPUT_REPO_SUPPORTED_ARCH")
        self.config["supported_version"] = options.get("INPUT_REPO_SUPPORTED_VERSION")
        self.config["deb_file_target_version"] = options.get(
            "INPUT_FILE_TARGET_VERSION"
        )
        self.config["gh_branch"] = options.get("INPUT_PAGE_BRANCH", "gh-pages")
        self.config["apt_folder"] = options.get("INPUT_REPO_FOLDER", "repo")
        self.config["key_public"] = options.get("INPUT_PUBLIC_KEY")
        self.config["key_private"] = options.get("INPUT_PRIVATE_KEY")

        for ky, vl in self.config.items():
            if not vl:
                raise ValueError(f"Missing required parameter {ky}")
            self.config[ky] = vl.strip()

        deb_file_path = options.get("INPUT_FILE", "")
        file_list = set()
        for line in deb_file_path.strip().split("\n"):
            for s in glob.glob(line.strip('" ')):
                file_list.add(s)

        self.deb_files = list(file_list)
        if not self.deb_files:
            raise ValueError("Missing required parameter files")

        self.supported_archs = self.config["supported_arch"].split("\n")
        self.supported_versions = self.config["supported_version"].split("\n")
        self.config["deb_file_version"] = self.config["deb_file_target_version"]

        # optional parameter
        self.config["key_passphrase"] = options.get("INPUT_KEY_PASSPHRASE")

        logging.debug(self.config)

        if self.config["deb_file_version"] not in self.supported_versions:
            raise ValueError(
                f'File version "{self.config["deb_file_version"]}" is not listed in repo supported version list'
            )

        logging.info("-- Done parsing input --")

    def cloneRepo(self) -> None:
        """Clone current repository into container
        """
        logging.info("-- Cloning current Github page --")
        github_slug = self.config["github_repo"].split("/")[1]

        self.git_working_folder = f"{github_slug}-{self.config['gh_branch']}"

        # cleanup current folder
        if os.path.exists(self.git_working_folder):
            shutil.rmtree(self.git_working_folder)

        logging.debug(f"cwd: {os.getcwd()}")
        logging.debug(os.listdir())

        self.git_repo = git.Repo.clone_from(
            f'https://x-access-token:{self.config["github_token"]}@github.com/{self.config["github_repo"]}.git',
            self.git_working_folder,
        )

        git_refs = self.git_repo.remotes.origin.refs
        git_refs_name = list(map(lambda x: str(x).split("/")[-1], git_refs))
        logging.debug(git_refs_name)

        if self.config["gh_branch"] not in git_refs_name:
            self.git_repo.git.checkout(b=self.config["gh_branch"])
        else:
            self.git_repo.git.checkout(self.config["gh_branch"])

    def generateMetadata(self) -> None:
        """get metadata of first given .deb file
        """
        # Generate metadata
        logging.debug(f"cwd: {os.getcwd()}")
        logging.debug(os.listdir())

        deb_file_handle = DebFile(filename=self.deb_files[0])
        deb_file_control = deb_file_handle.debcontrol()

        self.current_metadata = {
            "format_version": 1,
            "sw_version": deb_file_control["Version"],
            "sw_architecture": deb_file_control["Architecture"],
            "linux_version": self.config["deb_file_version"],
        }

        logging.debug(f"Metadata {json.dumps(self.current_metadata)}")

    def fetchRepositoryMetadata(self) -> None:
        """fetch metadata of repository
        """
        # Get metadata
        all_commit = self.git_repo.iter_commits(self.config["gh_branch"])
        all_apt_action_commit = list(
            filter(lambda x: (x.message[:12] == "[apt-action]"), all_commit)
        )
        apt_action_metadata_str = list(
            map(lambda x: self.metadata_re.findall(x.message), all_apt_action_commit)
        )
        apt_action_valid_metadata_str = list(
            filter(lambda x: len(x) > 0, apt_action_metadata_str)
        )
        apt_action_metadata = list(
            map(lambda x: json.loads(x[0]), apt_action_valid_metadata_str)
        )

        logging.debug(all_apt_action_commit)
        logging.debug(apt_action_valid_metadata_str)

        for check_metadata in apt_action_metadata:
            if check_metadata == self.current_metadata:
                logging.info(
                    "The specified version of this package has already been added to the repository - skipped."
                )
                sys.exit(0)

        logging.info("-- Done cloning current Github page --")

    def prepare(self) -> None:
        """Import private/public key + create missing folders
        """
        # Prepare key
        logging.info("-- Importing key --")
        key_file = os.path.join(self.git_working_folder, "public.key")

        detectPublicKey(self.gpg, key_file, self.config["key_public"])
        self.private_key_id = importPrivateKey(self.gpg, self.config["key_private"])
        logging.info("-- Done importing key --")

        # Prepare repo
        logging.info("-- Preparing repo directory --")

        self.apt_dir = os.path.join(self.git_working_folder, self.config["apt_folder"])
        apt_conf_dir = os.path.join(self.apt_dir, "conf")

        if not os.path.isdir(self.apt_dir):
            logging.info("Existing repo not detected, creating new repo")
            os.mkdir(self.apt_dir)
            os.mkdir(apt_conf_dir)

        logging.debug("Creating repo config")

        with open(
            os.path.join(apt_conf_dir, "distributions"), "w"
        ) as distributions_file:
            for codename in self.supported_versions:
                distributions_file.write(f"Description: {self.config['github_repo']}\n")
                distributions_file.write(f"Codename: {codename}\n")
                distributions_file.write(
                    "Architectures: {}\n".format(" ".join(self.supported_archs))
                )
                distributions_file.write("Components: main\n")
                distributions_file.write(f"SignWith: {self.private_key_id}\n")
                distributions_file.write("\n\n")

        logging.info("-- Done preparing repo directory --")

    def addFiles(self) -> None:
        """Add all files to repository
        """
        # Fill repo
        logging.info("-- Adding package(s) to repo --")

        for deb_file in self.deb_files:
            logging.info(f"Adding {deb_file}")
            subprocess.run(
                [
                    "reprepro",
                    "-b",
                    self.apt_dir,
                    "--export=silent-never",
                    "includedeb",
                    self.config["deb_file_version"],
                    deb_file,
                ],
                check=True,
            )
            self.deb_files_hashes[deb_file] = self.generateHash(deb_file, "sha1")

        logging.debug("Signing to unlock key on gpg agent")
        self.gpg.sign(
            "test",
            keyid=self.private_key_id,
            passphrase=self.config.get("key_passphrase", ""),
        )

        logging.debug("Export and sign repo")
        subprocess.run(["reprepro", "-b", self.apt_dir, "export"], check=True)

        logging.info("-- Done adding package to repo --")

    @staticmethod
    def generateHash(filename, hash_type) -> str:
        """Generate hash for given file

        :param filename: path + filename of file to analyze
        :type filename: str
        :param hash_type: type of hash (ex. sha1)
        :type hash_type: str
        :return: hex encoded hash
        :rtype: str
        """
        h = hashlib.new(hash_type)
        b = bytearray(128 * 1024)
        mv = memoryview(b)
        with open(filename, "rb", buffering=0) as f:
            for n in iter(lambda: f.readinto(mv), 0):
                h.update(mv[:n])
        return h.hexdigest()

    def finish(self) -> None:
        """Commit changes
        """
        # Commiting and push changes
        logging.info("-- Saving changes --")

        github_user = self.config["github_repo"].split("/")[0]
        self.git_repo.config_writer().set_value(
            "user", "email", f"{github_user}@users.noreply.github.com"
        )

        self.git_repo.git.add("*")

        commit_msg = "[apt-action] Update apt repo\n\n\nAdded/updated file(s):\n"
        for deb_file in self.deb_files:
            commit_msg += "{}  {}\n".format(self.deb_files_hashes[deb_file], deb_file)

        commit_msg += "\n\napt-action-metadata: {}".format(
            json.dumps(self.current_metadata)
        )
        self.git_repo.index.commit(commit_msg)
        self.git_repo.git.push("--set-upstream", "origin", self.config["gh_branch"])

        logging.info("-- Done saving changes --")

if __name__ == "__main__":
    dpb = DebRepositoryBuilder()
    dpb.run(os.environ)
