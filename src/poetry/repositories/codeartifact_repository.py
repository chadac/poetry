import hashlib
from pathlib import Path
from typing import TYPE_CHECKING
from typing import List
from typing import Optional
from typing import Any
from dataclasses import dataclass, field

import boto3
import re
import requests
from cachy import CacheManager
from collections import defaultdict

from poetry.config.config import Config
from poetry.core.packages.dependency import Dependency
from poetry.core.packages.package import Package
from poetry.core.semver.version import Version
from poetry.inspection.info import PackageInfo
from poetry.repositories.exceptions import PackageNotFound
from poetry.repositories.exceptions import RepositoryError
from poetry.repositories.legacy_repository import LegacyRepository
from poetry.utils.helpers import canonicalize_name


@dataclass()
class CAParams:
    domain: str
    domain_owner: str
    region: str
    repository: str
    aws_profile: Optional[str] = None
    _client: Any = field(init=False)

    def __post_init__(self):
        if self.aws_profile:
            session = boto3.Session(profile_name=self.aws_profile)
        else:
            session = boto3.Session()
        self._client = session.client('codeartifact', region_name=self.region)

    @property
    def client(self):
        return self._client

    @property
    def token(self) -> str:
        # TODO: Cache this until expiration
        return self.client.get_authorization_token(
            domain=self.domain,
            domainOwner=self.domain_owner,
            durationSeconds=0
        )['authorizationToken']

    @property
    def url(self):
        return f'https://{self.domain}-{self.domain_owner}.d.codeartifact.{self.region}.amazonaws.com/pypi/{self.repository}'

    @property
    def simple_url(self):
        return f'{self.url}/simple'


def parse_ca_url(url: str) -> CAParams:
    ca_regex = r'codeartifact://(?:([a-zA-Z0-9\-_]+)@)?([a-zA-Z-0-9_]+)\-([0-9]+)\.d\.codeartifact\.([a-z0-9\-]+)\.amazonaws\.com/pypi/([a-zA-Z0-9\-]+)/?(?:simple)?/?'
    m = re.match(ca_regex, url)
    if m:
        return CAParams(
            domain=m.group(2),
            domain_owner=m.group(3),
            region=m.group(4),
            repository=m.group(5),
            aws_profile=m.group(1)
        )
    else:
        raise RepositoryError(
            f"Codeartifact URL incorrectly formatted: {url}"
        )


class CodeArtifactRepository(LegacyRepository):
    def __init__(
            self,
            name: str,
            url: str,
            config: Optional[Config] = None,
            disable_cache: bool = False,
            cert: Optional[Path] = None,
            client_cert: Optional[Path] = None,
    ) -> None:
        ca_params = parse_ca_url(url)
        config.merge({
            'repositories': {
                name: {
                    'url': ca_params.simple_url
                }
            },
            'http-basic': {
                name: {
                    'username': 'aws',
                    'password': ca_params.token
                }
            }
        })
        super().__init__(
            name, ca_params.simple_url, config, disable_cache, cert, client_cert)
        self.ca = ca_params
        # self._authenticator.session.auth = requests.auth.HTTPBasicAuth(
        #     'aws', self.ca.token
        # )

    def _ca_get_links(self, name: str, version: str) -> dict:
        links = {}
        nextToken = ''
        while nextToken is not None:
            r = self.ca.client.list_package_version_assets(
                domain=self.ca.domain,
                domainOwner=self.ca.domain_owner,
                repository=self.ca.repository,
                format='pypi',
                package=name,
                packageVersion=version,
                maxResults=10
            )
            newToken = r.get('nextToken', None)
            for asset in r['assets']:
                links[asset['name']] = asset['hashes']
            if newToken == nextToken:
                break
            nextToken = newToken
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

        # Make a request to cache results from upstream
        print(links[0])
        self._session.head(links[0])

        links_hash = self._ca_get_links(name, version)
        if not links:
            raise PackageNotFound(
                f'No valid distribution links found for package: "{name}" version:'
                f' "{version}"'
            )
        urls = defaultdict(lambda: list())
        files = []
        for link in links:
            if link.is_wheel:
                urls["bdist_wheel"] += [link.url]
            elif link.filename.endswith(
                (".tar.gz", ".zip", ".bz2", ".xz", ".Z", ".tar")
            ):
                urls["sdist"] += [link.url]

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
