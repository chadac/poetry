from pathlib import Path
from typing import TYPE_CHECKING
from typing import List
from typing import Optional

import boto3
from cachy import CacheManager

from poetry.config.config import Config
from poetry.core.packages.dependency import Dependency
from poetry.core.packages.package import Package
from poetry.repositories.exceptions import PackageNotFound
from poetry.repositories.exceptions import RepositoryError
from poetry.repositories.legacy_repository import LegacyRepository
from poetry.utils.helpers import canonicalize_name


class CodeArtifactRepository(LegacyRepository):
    def __init__(
            self,
            name: str,
            domain: str,
            domain_owner: str,
            repository: str,
            region: str,
            aws_profile: Optional[str] = None,
            config: Optional[Config] = None,
            disable_cache: bool = False,
            cert: Optional[Path] = None,
            client_cert: Optional[Path] = None,
    ) -> None:
        url = f'amazon-{domain_owner}.d.codeartifact.{region}.amazonaws.com/pypi/{repository}'
        super().__init__(name, url, config, disable_cache, cert, client_cert)
        self.ca_domain = domain
        self.ca_domain_owner = domain_owner
        self.ca_repository = repository
        self.ca_region = region
        self.aws_profile = aws_profile

    @property
    def ca_client(self):
        if self.aws_profile:
            session = boto3.Session(profile_name=self.aws_profile)
        else:
            session = boto3.Session()
        return session.client('codeartifact')

    def _ca_get_links(self, name: str, version: str) -> dict:
        ca = self.ca_client
        links = {}
        nextToken = ''
        while nextToken is not None:
            r = ca.list_package_version_assets(
                domain=self.ca_domain,
                domainOwner=self.ca_domain_owner,
                repository=self.ca_repository,
                format='pypi',
                package=name,
                packageVersion=version,
                maxResults=10
            )
            nextToken = r.get('nextToken', None)
            for asset in r['assets']:
                links[asset['name']] = asset['hashes']
        return links

    def _get_release_info(self, name: str, version: str) -> dict:
        page = self._get_page(f"/{canonicalize_name(name).replace('.', '-')}/")
        if page is None:
            raise PackageNotFound(f'No package named "{name}"')

        data = PackageInfo(
            name=name,
            version=version,
            summary="",
            platform=None,
            requires_dist=[],
            requires_python=None,
            files=[],
            cache_version=str(self.CACHE_VERSION),
        )

        links = list(page.links_for_version(Version.parse(version)))
        links_hash = self._ca_get_links(name, version)
        if not links:
            raise PackageNotFound(
                f'No valid distribution links found for package: "{name}" version:'
                f' "{version}"'
            )
        urls = defaultdict(list)
        files = []
        for link in links:
            if link.is_wheel:
                urls["bdist_wheel"].append(link.url)
            elif link.filename.endswith(
                (".tar.gz", ".zip", ".bz2", ".xz", ".Z", ".tar")
            ):
                urls["sdist"].append(link.url)

            file_hash = f"{link.hash_name}:{link.hash}" if link.hash else None

            if not link.hash or (
                link.hash_name not in ("sha256", "sha384", "sha512")
                and hasattr(hashlib, link.hash_name)
            ):
                file_hash = f"sha256:{links_hash[link.filename]['SHA-256']}"

            files.append({"file": link.filename, "hash": file_hash})

        data.files = files

        info = self._get_info_from_urls(urls)

        data.summary = info.summary
        data.requires_dist = info.requires_dist
        data.requires_python = info.requires_python

        return data.asdict()
