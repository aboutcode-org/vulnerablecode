import bisect
import json
import os
import re
from collections import defaultdict
from typing import List
from typing import Optional
from typing import Tuple

from git import Commit
from git import Repo


def clone_repo(repo_url: str, clone_dir: str) -> str:
    os.makedirs(clone_dir, exist_ok=True)
    try:
        print(f"Cloning {repo_url} into {clone_dir}...")
        repo = Repo.clone_from(repo_url, clone_dir)
        print("Clone successful.")
        return repo.working_tree_dir
    except Exception as e:
        print(f"Failed to clone repository: {e}")
        return ""


def classify_commit_type(commit) -> str:
    num_parents = len(commit.parents)
    if num_parents == 0:
        return "root"  # never a fix
    elif num_parents == 1:
        return "normal"  # main source of fixes
    else:
        return "merge"  # usually not a fix


def detect_fix_commit(commit) -> str:
    """
    Detect whether a commit is a bug-fix or vulnerability-fix commit.
    Returns: "vulnerability_fix", "other"
    """
    msg = commit.message.lower()

    security_patterns = [
        # CVE identifiers
        r"\bcve-\d{4}-\d{4,}\b",
        # Explicitly marked security fixes
        r"\bsecurity fix\b",
        r"\bfix security issue\b",
        r"\bfix(?:es)? for security\b",
        # Permission / privilege escalation
        r"\bprivilege escalation\b",
        r"\bprivesc\b",
        r"\bescalat(?:e|ion) of privilege\b",
        # No New Privileges / unsafe exec
        r"\bno[- ]new[- ]privs\b",
        r"\bunsafe exec\b",
        # Refcount / UAF (classic kernel vulns, almost always security)
        r"\buse[- ]after[- ]free\b",
        r"\buaf\b",
        r"\brefcount (?:leak|error|overflow|underflow)\b",
        r"\bdouble free\b",
        # Out-of-bounds (OOB)
        r"\bout[- ]of[- ]bounds\b",
        r"\boob\b",
        # Info leaks (security-relevant, not generic leaks)
        r"\binformation leak\b",
        r"\binfo leak\b",
        r"\bleak (?:kernel|userns|credentials?|mnt_idmap)\b",
        # Bypass
        r"\bsecurity bypass\b",
        r"\baccess control bypass\b",
        r"\bpermission check (?:bug|fix|error)\b",
    ]

    SECURITY_REGEX = re.compile("|".join(security_patterns), re.IGNORECASE)

    if SECURITY_REGEX.search(msg):
        return "vulnerability_fix"
    return "other"


def extract_cves(text: str) -> List[str]:
    if not text:
        return []
    cves = re.findall(r"cve-[0-9]{4}-[0-9]{4,19}", text, flags=re.IGNORECASE)
    return list({cve.upper() for cve in cves})


def get_previous_releases(
    release_tags_sorted: List[Tuple[str, int]], dates: List[int], commit_date: int
) -> List[str]:
    """
    Get all release tags with commit dates strictly before the given commit date.
    release_tags_sorted: list of (tag_name, committed_date), sorted by committed_date
    dates: list of commit dates (parallel to release_tags_sorted, sorted ascending)
    """
    index = bisect.bisect_left(dates, commit_date)
    return [tag for tag, _ in release_tags_sorted[:index]]


def get_current_or_next_release(
    release_tags_sorted: List[Tuple[str, int]], dates: List[int], commit_date: int
) -> Optional[str]:
    """
    Get the current release if commit matches a release date,
    otherwise return the next release after the commit date.
    """
    index = bisect.bisect_left(dates, commit_date)

    # Exact match → this commit is tagged
    if index < len(dates) and dates[index] == commit_date:
        return release_tags_sorted[index][0]

    # Otherwise, next release after this commit
    if index < len(dates):
        return release_tags_sorted[index][0]

    # No next release available
    return None


def get_current_release(repo: Repo, commit: Commit, prev_release_by_date: Optional[str]) -> str:
    """
    Return a non-null release tag for the given commit:
      1) exact tag if commit is tagged
      2) nearest reachable tag (fast, first-parent)
      3) latest prior tag by date (fallback)
      4) "NO_TAGS_AVAILABLE" if repo has no tags at all
    """
    # 1) Exact tag at this commit
    try:
        return repo.git.describe("--tags", "--exact-match", commit.hexsha)
    except Exception:
        pass

    # 2) Nearest reachable tag along first-parent
    try:
        return repo.git.describe("--tags", "--abbrev=0", "--first-parent", commit.hexsha)
    except Exception:
        pass

    # 3) Fallback: latest prior tag by date
    if prev_release_by_date:
        return prev_release_by_date

    # 4) No tags at all
    return "NO_TAGS_AVAILABLE"


if __name__ == "__main__":
    repo_url = "https://github.com/torvalds/linux"
    repo_path = "/home/ziad-hany/PycharmProjects/linux"

    repo = Repo(repo_path)
    commits_data = []
    cve_list = defaultdict(set)

    # Precompute and sort release tags by commit date
    release_tags = []
    for tag in repo.tags:
        try:
            release_tags.append((tag.name, tag.commit, tag.commit.committed_date))
        except Exception:
            continue

    release_tags_sorted = sorted(release_tags, key=lambda x: x[2])

    # For previous releases lookup (by date)
    release_tags_for_previous = [(tag_name, date) for tag_name, _, date in release_tags_sorted]
    dates_array = [date for _, date in release_tags_for_previous]

    for commit in repo.iter_commits("--all"):
        commit_type = classify_commit_type(commit)
        fix_type = detect_fix_commit(commit)

        if fix_type == "vulnerability_fix" and commit_type in ["normal", "merge"]:
            # Compute "previous by date" first so we can feed it as a fallback
            prev_release_list = get_previous_releases(
                release_tags_for_previous, dates_array, commit.committed_date
            )
            prev_release_by_date = prev_release_list[-1] if prev_release_list else None

            curr_release = get_current_release(repo, commit, prev_release_by_date)

            commit_info = {
                "hash": commit.hexsha,
                "url": repo_url + "/commit/" + commit.hexsha,
                "message": commit.message.strip(),
                "curr_release": curr_release,
                "prev_release": prev_release_list,
                "fix_type": fix_type,
            }
            print(commit_info)
            commits_data.append(commit_info)

            # Optional CVE collection
            for cve_id in extract_cves(commit.message.strip()):
                cve_list[cve_id].add(repo_url + "/commit/" + commit.hexsha)

    result = {cve: list(commits) for cve, commits in cve_list.items()}
    print(f"Found {len(result)} unique CVEs")
    print(json.dumps(result, indent=2))
