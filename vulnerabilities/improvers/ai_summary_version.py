from typing import Iterable
from typing import List

from django.db.models import QuerySet
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider
from univers.version_range import RANGE_CLASS_BY_SCHEMES

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.improvers.default import get_exact_purls
from vulnerabilities.models import Advisory
from vulnerablecode.settings import env
from packageurl import PackageURL
from pydantic.functional_validators import field_validator

class Purl(BaseModel):
    string: str

    @field_validator('string')
    def check_valid_purl(cls, v: str) -> str:
        try:
            PackageURL.from_string(v)
        except Exception as e:
            raise ValueError(f"Invalid PURL '{v}': {e}")
        return v

class Versions(BaseModel):
    affected_versions: List[str]
    fixed_versions:   List[str]


prompt_purl_extraction = f"""
You are a highly specialized Vulnerability Analysis Assistant. Your task is to analyze the provided vulnerability summary or package name and extract a single valid Package URL (PURL) that conforms to the official PURL specification:

**Component Definitions (Required by PURL Specification):**
- **scheme**: Constant value `pkg`
- **type**: Package type or protocol (e.g., maven, npm, nuget, gem, pypi, rpm, etc.) — must be a known valid type
- **namespace**: A name prefix such as a Maven groupId, Docker image owner, or GitHub user/org (optional and type-specific)
- **name**: Package name (required)
- **version**: Version of the package (optional)
- **qualifiers**: Extra data like OS, arch, etc. (optional and type-specific)
- **subpath**: Subpath within the package (optional)

**Examples of Valid PURLs:**
- pkg:maven/org.apache.apr/apr-util@1.3.5
- pkg:github/apache/apr-util@1.3.5
- pkg:rpm/redhat/apr-util@1.3.5
- pkg:deb/debian/apr-util@1.3.5

**Output Instructions:**
- Identify the most appropriate and valid PURL type for the package if possible.
- If a valid and complete PURL can be constructed, return only:
  `{{ "string": "pkg:type/namespace/name@version?qualifiers#subpath" }}`
- If no valid PURL can be constructed or the type is unknown, return:
  `{{}}`
- Do not include any other output (no explanation, formatting, or markdown).
"""

prompt_version_extraction = f"""
        You are a highly specialized Vulnerability Analysis Assistant. Your task is to analyze the following vulnerability summary and accurately extract the affected and fixed versions of the software.
        
        Instructions:
        - Affected Version: Use one of the following formats:
          - >= <version>, <= <version>, > <version>, < <version>
          - A specific range like <version1> - <version2>
        - Fixed Version: Use one of the following formats:
          - >= <version>, <= <version>, > <version>, < <version>
          - "Not Fixed" if no fixed version is mentioned.
        - Ensure accuracy by considering different ways affected and fixed versions might be described in the summary.
        - Extract only version-related details without adding any extra information.
        
        Output Format:
        ```json
        {{
            "affected_versions": ["<version_condition>", "<version_condition>"],
            "fixed_versions": ["<version_condition>", "<version_condition>"]
        }}
        ```
        Example:
        {{
            "affected_versions": [">=1.2.3", "<2.0.0"],
            "fixed_versions": ["2.0.0"]
        }}
        
        Return only the JSON object without any additional text.
        """

class AISummaryImprover(Improver):
    """
    A pipeline for improving vulnerability version extraction using AI.
    This pipeline analyzes vulnerability summaries and extracts affected and fixed versions.
    """

    openai_model = OpenAIModel('gpt-4o-mini', provider=OpenAIProvider(api_key=env.str("OPENAI_API_KEY")))

    # ollama_model = OpenAIModel(
    #     model_name=env.str("OLLAMA_MODEL_NAME"), provider=OpenAIProvider(openai_client=env.str("OLLAMA_BASE_URL"))
    # )

    purl_agent = Agent(openai_model,
                       system_prompt=prompt_purl_extraction,
                       output_type=Purl)

    versions_agent = Agent(openai_model,
                           system_prompt=prompt_version_extraction,
                           output_type=Versions)


    @property
    def interesting_advisories(self) -> QuerySet:
        return (
            Advisory.objects.all().paginated()
        )

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        if not advisory_data:
            return []

        if advisory_data.summary:
            purl = self.handler_purl(advisory_data.summary)

            affected_version_range, fixed_version = self.handler_version_ranges(
                summary=advisory_data.summary,
                supported_ecosystem=purl.type
            )

            affected_package = AffectedPackage(
                package=PackageURL(type=purl.type, namespace=purl.namespace, name=purl.name),
                affected_version_range=affected_version_range,
                fixed_version=fixed_version,
            )

            affected_purls, fixed_purls = get_exact_purls(affected_package)
            for fixed_purl in fixed_purls:
                yield Inference(
                    aliases=advisory_data.aliases,
                    confidence=MAX_CONFIDENCE,
                    summary=advisory_data.summary,
                    affected_purls=affected_purls,
                    fixed_purl=fixed_purl,
                    references=advisory_data.references,
                    weaknesses=advisory_data.weaknesses,
                )


    def handler_version_ranges(self, summary, supported_ecosystem):
        """Extract affected and fixed version ranges from a vulnerability summary."""
        result = self.versions_agent.run_sync(user_prompt=f"""
        **Vulnerability Summary:**
        {summary}
        """)

        affected_version_ranges = result.output.affected_versions
        fixed_version_ranges = result.output.fixed_versions

        affected_version_objs = [RANGE_CLASS_BY_SCHEMES[supported_ecosystem].from_string(f"vers:{supported_ecosystem}/" + affected_version_range) for affected_version_range in affected_version_ranges]
        fixed_version_objs = [RANGE_CLASS_BY_SCHEMES[supported_ecosystem].from_string(f"vers:{supported_ecosystem}/" + fixed_version_version_range) for fixed_version_version_range in fixed_version_ranges]
        return affected_version_objs, fixed_version_objs


    def handler_purl(self, summary):
        """
        Analyze the vulnerability summary and extract a valid Package URL (PURL).
        Returns the extracted PURL string or None if not found.
        """
        result = self.purl_agent.run_sync(user_prompt=f"""
        **Vulnerability Summary:**
        {summary}
        """)
        return PackageURL.from_string(result.output.string)