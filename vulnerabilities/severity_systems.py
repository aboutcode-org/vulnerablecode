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
        value. For instance this can be used to convert a CVSS vector to a base
        score.
        """
        raise NotImplementedError


scoring_systems = {
    "cvssv2": ScoringSystem(
        identifier="cvssv2",
        name="CVSSv2 Base Score",
        url="https://www.first.org/cvss/v2/",
        notes="cvssv2 base score",
    ),
    "cvssv2_vector": ScoringSystem(
        identifier="cvssv2_vector",
        name="CVSSv2 Vector",
        url="https://www.first.org/cvss/v2/",
        notes="cvssv2 vector, used to get additional info about nature and severity of vulnerability",  # nopep8
    ),
    "cvssv3": ScoringSystem(
        identifier="cvssv3",
        name="CVSSv3 Base Score",
        url="https://www.first.org/cvss/v3-0/",
        notes="cvssv3 base score",
    ),
    "cvssv3_vector": ScoringSystem(
        identifier="cvssv3_vector",
        name="CVSSv3 Vector",
        url="https://www.first.org/cvss/v3-0/",
        notes="cvssv3 vector, used to get additional info about nature and severity of vulnerability",  # nopep8
    ),
    "cvssv3.1": ScoringSystem(
        identifier="cvssv3.1",
        name="CVSSv3.1 Base Score",
        url="https://www.first.org/cvss/v3-1/",
        notes="cvssv3.1 base score",
    ),
    "cvssv3.1_vector": ScoringSystem(
        identifier="cvssv3.1_vector",
        name="CVSSv3.1 Vector",
        url="https://www.first.org/cvss/v3-1/",
        notes="cvssv3.1 vector, used to get additional info about nature and severity of vulnerability",  # nopep8
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
}
