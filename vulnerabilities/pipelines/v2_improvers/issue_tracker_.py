from abc import ABC
from abc import abstractmethod
from typing import Dict
from typing import List
from typing import Optional

import requests


class IssueTrackerClient(ABC):
    @abstractmethod
    def get_issues(self, project: str, **kwargs) -> List[Dict]:
        pass

    @abstractmethod
    def get_pull_requests(self, project: str, **kwargs) -> List[Dict]:
        pass

    @abstractmethod
    def get_comments(self, project: str, **kwargs) -> List[Dict]:
        pass


class IssueTrackerFactory:
    @staticmethod
    def create_client(platform: str, token: Optional[str] = None, **kwargs) -> IssueTrackerClient:
        platform = platform.lower()

        GIT_PLATFORM_CLIENT = {
            "github": GitHubClient,
        }

        if platform not in GIT_PLATFORM_CLIENT:
            raise ValueError(f"Unsupported platform: {platform}")

        return GIT_PLATFORM_CLIENT[platform](token=token, **kwargs)


class GitHubClient(IssueTrackerClient):
    API_BASE = "https://api.github.com"

    def __init__(self, token: Optional[str] = None):
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/vnd.github.v3+json"})
        if token:
            self.session.headers["Authorization"] = f"token {token}"

    def _paginate(self, url: str, params: dict = None) -> List[Dict]:
        results, page = [], 1
        params = params or {}
        while True:
            params.update({"per_page": 100, "page": page})
            response = self.session.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            if not data:
                break
            results.extend(data)
            page += 1
        return results

    def get_issues(self, project: str, state: str = "all") -> List[Dict]:
        owner, repo = project.split("/")
        url = f"{self.API_BASE}/repos/{owner}/{repo}/issues"
        issues = self._paginate(url, {"state": state})
        return [i for i in issues if "pull_request" not in i]

    def get_pull_requests(self, project: str, state: str = "all") -> List[Dict]:
        owner, repo = project.split("/")
        url = f"{self.API_BASE}/repos/{owner}/{repo}/pulls"
        return self._paginate(url, {"state": state})

    def get_comments(self, project: str, issue_num: int) -> List[Dict]:
        owner, repo = project.split("/")
        url = f"{self.API_BASE}/repos/{owner}/{repo}/issues/{issue_num}/comments"
        return self._paginate(url)
