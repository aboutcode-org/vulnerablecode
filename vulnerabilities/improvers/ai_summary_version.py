import json
import re
from pathlib import Path
from typing import Iterable

import chromadb
from django.db.models import QuerySet
from langchain_chroma import Chroma
from langchain_ollama import OllamaLLM

from univers.version_range import RANGE_CLASS_BY_SCHEMES

from vulnerabilities.importer import AffectedPackage, AdvisoryData
from vulnerabilities.improver import Inference, MAX_CONFIDENCE, Improver
from vulnerabilities.improvers.default import get_exact_purls
from vulnerabilities.models import Advisory
from vulnerablecode.settings import env
from langchain.prompts import PromptTemplate
from packageurl import PackageURL
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.document_loaders import UnstructuredMarkdownLoader
from tqdm import tqdm

class AISummaryImprover(Improver):
    """
    A pipeline for improving vulnerability version extraction using AI.
    This pipeline analyzes vulnerability summaries and extracts affected and fixed versions.
    """

    llm = OllamaLLM(
        model=env.str("OLLAMA_MODEL_NAME"),
        base_url=env.str("OLLAMA_BASE_URL")
    )

    # Initialize embeddings
    embeddings = HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True},
    )

    # Initialize ChromaDB Client (do this once)
    chroma_client = chromadb.PersistentClient(path="purl_index")

    # Create the vector store using LangChain's Chroma integration
    vector_db = Chroma(
        client=chroma_client,
        collection_name="purl_embeddings",
        embedding_function=embeddings,
    )

    # Check if collection exists and contains documents
    existing_docs = vector_db.get()
    if existing_docs and existing_docs.get("documents"):
        print(f"✅ ChromaDB collection loaded successfully! {len(existing_docs['documents'])} documents found.")
    else:
        print(f"⚠️ Collection not found or empty. Initializing ChromaDB.")

        # Load documents
        markdown_path = "/agent/purl_db/PURL.rst"
        loader = UnstructuredMarkdownLoader(markdown_path)
        docs = loader.load()  # This returns a list of Documents

        if not docs:
            print("❌ No documents loaded. Please check the file path and format.")
        else:
            print(f"✅ Loaded {len(docs)} documents.")
            collection = chroma_client.get_or_create_collection(name="purl_embeddings")

            # Index each document by its file name
            for i, doc in enumerate(tqdm(docs, desc="Indexing documents")):
                file = doc.metadata.get("source", "unknown")
                file_name = Path(file).stem
                collection.add(
                    ids=[file_name],
                    documents=[doc.page_content],
                    metadatas=[{"file_name": file_name}],
                )

            print("✅ Documents indexed in ChromaDB.")

    @property
    def interesting_advisories(self) -> QuerySet:
        return (
            Advisory.objects.all().paginated()
        )

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        """
        """
        if not advisory_data:
            return []

        if advisory_data.summary:
            purl = self.handler_purl(advisory_data.summary)

            if not purl:
                return

            affected_version_range, fixed_version = self.handler_version_ranges(summary=advisory_data.summary,
                                                                                supported_ecosystem=purl.type)

            affected_package = AffectedPackage(
                package=purl,
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
        """
        """
        version_extraction_prompt = PromptTemplate(
            input_variables=["summary"],
            template="""
            You are a highly specialized Vulnerability Analysis Assistant. Your task is to analyze the following vulnerability summary and accurately extract the affected and fixed versions of the software.

            **Vulnerability Summary:**
            {summary}

            Output Format:
            ```json
            {{
                "affected_versions": ["<version_condition>", "<version_condition>"],
                "fixed_versions": ["<version_condition>", "<version_condition>"]
            }}
            ```
            
            Instructions:
            - Affected Version: Use one of the following formats:
              - >= <version>, <= <version>, > <version>, < <version>
              - A specific range like <version1> - <version2>
            - Fixed Version: Use one of the following formats:
              - >= <version>, <= <version>, > <version>, < <version>
              - "Not Fixed" if no fixed version is mentioned.
            - Ensure accuracy by considering different ways affected and fixed versions might be described in the summary.
            - Extract only version-related details without adding any extra information.

            Return only the JSON object without any additional text.
            """,
        )

        version_extraction_prompt = version_extraction_prompt.format(summary=summary)
        json_text = self.get_llm_result(prompt=version_extraction_prompt)

        try:
            match = re.search(r'```json\n(.*?)\n```', json_text, re.DOTALL).group(1)
            json_data = json.loads(match)
        except json.JSONDecodeError as e:
            print("Invalid JSON:", e)
            json_data = {}

        affected_version_ranges = json_data.get("affected_versions", [])
        fixed_version_ranges = json_data.get("fixed_versions", [])

        affected_version_objs = [RANGE_CLASS_BY_SCHEMES[supported_ecosystem].from_string(f"vers:{supported_ecosystem}/" + affected_version_range) for affected_version_range in affected_version_ranges]
        fixed_version_objs = [RANGE_CLASS_BY_SCHEMES[supported_ecosystem].from_string(f"vers:{supported_ecosystem}/" + fixed_version_version_range) for fixed_version_version_range in fixed_version_ranges]
        return affected_version_objs, fixed_version_objs


    def handler_purl(self, summary):
        """
        """
        purl_extraction_prompt = PromptTemplate(
            input_variables=["summary"],
            template="""
        You are a highly specialized Vulnerability Analysis Assistant. Your task is to analyze the provided vulnerability summary, and extract a single valid Package URL (PURL) that strictly conforms to the following specification:
           
        **Vulnerability Summary:**  
        {summary}
        
        **Component Definitions:**
        - **scheme:** Must be the constant value `pkg` (required).
        - **type:** The package type or protocol (e.g., maven, npm, nuget, gem, pypi, etc.) (required).
        - **namespace:** A name prefix such as a Maven groupId, Docker image owner, or GitHub user/organization (optional and type-specific).
        - **name:** The package name (required).
        - **version:** The version of the package (optional).
        - **qualifiers:** Extra qualifying data such as an OS, architecture, distro, etc. (optional and type-specific).
        - **subpath:** A subpath within the package, relative to the package root (optional).
        
        **Important Requirements:**
        - The components must form a hierarchy from the most significant (left) to the least significant (right).
        - The PURL must NOT contain a URL authority (i.e., no username, password, host, or port).
        - If a namespace segment resembles a host, its interpretation is specific to the package type.
        
        **Output Instructions:**
        - If a valid PURL is extracted, return **only** the PURL (and nothing else).
        - If no valid PURL is found, return nothing.
        Provide the answer strictly based on the above context.
            """,
        )
        # single_doc_content = self.vector_db.get()["documents"][0]
        purl_extraction_prompt = purl_extraction_prompt.format(summary=summary)
                                                               #context=single_doc_content)
        llm_response = self.get_llm_result(prompt=purl_extraction_prompt)
        purl_response = re.search(r'pkg:[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)+', llm_response).group(0)
        return PackageURL.from_string(purl_response)

    def get_llm_result(self, prompt):
        """
        """
        response = self.llm.invoke(prompt)
        cleaned_result = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL).strip()
        print(cleaned_result)
        return cleaned_result
