import dataclasses


@dataclasses.dataclass
class ScoringSystem:

    # a short identifier for the scoring system.
    identifier: str
    # a name which represents the scoring system such as `RedHat bug severity`.
    # This is for human understanding
    name: str
    # a url to documentation about that sscoring system
    url: str
    # notes about that scoring system
    notes: str = ""

    def as_score(self, value):
        """
        Return a normalized numeric score for this scoring system  given a raw
        value. For instance htis can be used to convert a CVSS vector to a base
        score.
        """
        raise NotImplementedError


scoring_systems = {
    "cvssv2": ScoringSystem(
        identifier="cvssv2",
        name="CVSSv2",
        url="https://www.first.org/cvss/v2/",
        notes="We store the vector as value and compute scores from that.",
    ),
    "cvssv3": ScoringSystem(
        identifier="cvssv3",
        name="CVSSv3",
        url="https://www.first.org/cvss/v3-0/",
        notes="We store the vector as value and compute scores from that.",
    ),
    "rhbs": ScoringSystem(
        identifier="rhbs",
        name="RedHat Bugzilla severity",
        url="https://bugzilla.redhat.com/page.cgi?id=fields.html#bug_severity",
    ),
    "rhas": ScoringSystem(
        identifier="rhas",
        name="RedHat Aggregate severity",
        url="https://access.redhat.com/security/updates/classification/",
    ),
    "rh_cvssv3": ScoringSystem(
        identifier="rh_cvssv3",
        name="RedHat CVSSv3",
        url="https://access.redhat.com/security/updates/classification/",
    ),
}
