"""Docker Hub API discovery (subset of appsec_dockerscout clients)."""

from dataclasses import dataclass
from typing import List, Optional

import requests

from docker_scout_api.models import ImageRef

HUB_BASE = "https://hub.docker.com/v2"
HUB_REPO_STATUS_ACTIVE = 1


class DockerHubClientError(Exception):
    """Docker Hub API or auth error."""


@dataclass
class Org:
    name: str
    org_id: str = ""


@dataclass
class Repo:
    name: str
    namespace: str
    repo_id: str = ""


def _handle_http(response: requests.Response, url: str) -> None:
    status = response.status_code
    if status == 401:
        raise DockerHubClientError(
            f"401 Unauthorized: Invalid or expired credentials for URL {url}"
        )
    if status == 403:
        raise DockerHubClientError(f"403 Forbidden: Access denied for URL {url}")
    if status == 429:
        retry_after = int(response.headers.get("Retry-After", 1))
        raise DockerHubClientError(f"429 Too Many Requests: Retry after {retry_after}s")
    if 500 <= status < 600:
        raise DockerHubClientError(f"{status} Server error: {response.text}")
    response.raise_for_status()


class DockerHubClient:
    def __init__(self, username: str, password: str, timeout: int = 30) -> None:
        self.username = username
        self.password = password
        self.timeout = timeout
        self._token: Optional[str] = None

    def login(self) -> str:
        login_url = f"{HUB_BASE}/users/login/"
        login_request_body = {"username": self.username, "password": self.password}
        try:
            response = requests.post(
                login_url,
                json=login_request_body,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )
            _handle_http(response, login_url)
            login_response = response.json()
            self._token = login_response.get("token")
            if not self._token:
                raise DockerHubClientError("Login response missing token")
            return self._token
        except DockerHubClientError:
            raise
        except requests.RequestException as e:
            raise DockerHubClientError(f"Docker Hub login failed: {e}") from e

    def _ensure_token(self) -> str:
        if not self._token:
            return self.login()
        return self._token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._ensure_token()}",
            "Content-Type": "application/json",
        }

    def get_orgs(self) -> List[Org]:
        next_page_url = f"{HUB_BASE}/user/orgs/"
        organizations: List[Org] = []
        while next_page_url:
            try:
                response = requests.get(
                    next_page_url,
                    headers=self._headers(),
                    timeout=self.timeout,
                )
                _handle_http(response, next_page_url)
                page_body = response.json()
                for org_record in page_body.get("results", []):
                    organization_name = org_record.get(
                        "orgname",
                        org_record.get("name", ""),
                    )
                    organizations.append(
                        Org(
                            name=organization_name,
                            org_id=str(org_record.get("id", "")),
                        )
                    )
                next_page_url = page_body.get("next")
            except DockerHubClientError:
                raise
            except requests.RequestException as e:
                raise DockerHubClientError(f"get_orgs failed: {e}") from e
        return organizations

    def get_repositories(self, namespace: str, page_size: int = 100) -> List[Repo]:
        next_page_url = f"{HUB_BASE}/namespaces/{namespace}/repositories"
        scout_active_repositories: List[Repo] = []
        page_params: dict = {"page_size": page_size}
        while next_page_url:
            try:
                response = requests.get(
                    next_page_url,
                    headers=self._headers(),
                    params=page_params,
                    timeout=self.timeout,
                )
                _handle_http(response, next_page_url)
                page_body = response.json()
                for repo_record in page_body.get("results", []):
                    repository_name = repo_record.get("name", "")
                    if not repository_name:
                        continue
                    if repo_record.get("status") != HUB_REPO_STATUS_ACTIVE:
                        continue
                    scout_active_repositories.append(
                        Repo(
                            name=repository_name,
                            namespace=namespace,
                            repo_id=str(repo_record.get("id", "")),
                        )
                    )
                next_page_url = page_body.get("next")
                page_params = {}
            except DockerHubClientError:
                raise
            except requests.RequestException as e:
                raise DockerHubClientError(f"get_repositories failed: {e}") from e
        return scout_active_repositories

    def get_tags(self, org: str, repo: str, page_size: int = 100) -> List[str]:
        next_page_url = f"{HUB_BASE}/repositories/{org}/{repo}/tags"
        tag_names: List[str] = []
        page_params: dict = {"page_size": page_size}
        while next_page_url:
            try:
                response = requests.get(
                    next_page_url,
                    headers=self._headers(),
                    params=page_params,
                    timeout=self.timeout,
                )
                _handle_http(response, next_page_url)
                page_body = response.json()
                for tag_record in page_body.get("results", []):
                    tag_name = tag_record.get("name", "")
                    if tag_name:
                        tag_names.append(tag_name)
                next_page_url = page_body.get("next")
                page_params = {}
            except DockerHubClientError:
                raise
            except requests.RequestException as e:
                raise DockerHubClientError(f"get_tags failed: {e}") from e
        return tag_names

    def discover_images(self, org_filter: Optional[List[str]] = None) -> List[ImageRef]:
        images: List[ImageRef] = []
        organizations = self.get_orgs()
        if org_filter:
            namespace_names = {
                organization.name
                for organization in organizations
                if organization.name in org_filter
            }
        else:
            namespace_names = {organization.name for organization in organizations}
        for namespace in namespace_names:
            repositories = self.get_repositories(namespace)
            for repository in repositories:
                for tag_name in self.get_tags(namespace, repository.name):
                    images.append(
                        ImageRef(org=namespace, repo=repository.name, tag=tag_name)
                    )
        return images
