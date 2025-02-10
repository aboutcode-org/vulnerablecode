import re
from pathlib import Path
from typing import List
from typing import Union

import chromadb
import yaml
from chromadb.utils import embedding_functions
from django.http.response import Http404
from django.shortcuts import render
from django.views import View
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate
from langchain.schema import Document
from langchain_chroma import Chroma
from langchain_community.document_loaders import DirectoryLoader
from langchain_core.document_loaders import BaseLoader
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_ollama import OllamaLLM
from tqdm import tqdm

from agent.forms import VulnerabilityAgentForm


class YAMLLoader(BaseLoader):
    """Load and parse a YAML file into a Document."""

    def __init__(self, file_path: Union[str, Path]):
        """Initialize with the file path."""
        self.file_path = file_path

    def load(self) -> List[Document]:
        # Open the YAML file and load its content
        with open(self.file_path, "r") as file:
            try:
                # Load the YAML content
                data = yaml.safe_load(file)
                # Convert the YAML content to a string (or you can format it differently)
                text = str(data.get("summary", ""))
            except yaml.YAMLError as e:
                print(f"Error loading YAML file {self.file_path}: {e}")
                text = ""  # Set text to empty in case of error

        # Define metadata with file path information
        metadata = {"source": str(self.file_path)}

        # Return the loaded content as a list of Documents
        return [Document(page_content=text, metadata=metadata)]


# Initialize embeddings
embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    model_kwargs={"device": "cpu"},  # Use CPU
    encode_kwargs={"normalize_embeddings": True},  # Normalize embeddings for cosine similarity
)


try:
    # Load ChromaDB Persistent Client
    chroma_client = chromadb.PersistentClient(path="vuln_index")

    # Load the existing collection
    collection = chroma_client.get_collection(name="vuln_embeddings")

    print("✅ ChromaDB collection loaded successfully!")
except Exception as e:
    print(f"⚠️ Collection not found. Initializing ChromaDB. Error: {e}")

    # Load documents from a directory
    loader = DirectoryLoader(
        "vulnerablecode-data",  # ADD THE vulnerablecode-data PATH
        glob="**/*.yaml",
        use_multithreading=True,
        loader_cls=YAMLLoader,
    )
    docs = loader.load()
    print(f"Loaded {len(docs)} documents.")

    # Initialize ChromaDB client
    chroma_client = chromadb.PersistentClient(
        path="vuln_index"
    )  # Chroma persists data automatically

    # Define collection (equivalent to a FAISS index)
    collection = chroma_client.get_or_create_collection(name="vuln_embeddings")

    # Ensure embeddings function is compatible
    embedding_function = embedding_functions.DefaultEmbeddingFunction()

    # Index each document by its file name
    for i, doc in enumerate(tqdm(docs, desc="Indexing documents")):
        file = doc.metadata.get("source", "unknown")
        file_name = Path(file).stem
        package_name = Path(file).parts[8]
        print(file_name, package_name)

        # Add to ChromaDB
        collection.add(
            ids=[file_name],  # Unique identifier (use file name)
            documents=[doc.page_content],  # Document content
            metadatas=[
                {
                    "file_name": file_name,
                    "package_name": package_name,
                    "vulnerability_id": file_name,
                }
            ],
        )

    print("✅ Documents indexed in ChromaDB.")


llm = OllamaLLM(model="deepseek-r1:14b")
vector_db = Chroma(
    client=chroma_client, collection_name="vuln_embeddings", embedding_function=embeddings
)
retriever = vector_db.as_retriever(search_type="mmr", search_kwargs={"k": 1})
qa_chain = RetrievalQA.from_chain_type(llm, retriever=retriever, chain_type="stuff")


class VulnAgent(View):
    template_name = "vuln-agent.html"

    def get(self, request):
        context = {
            "vulnerability_agent_form": VulnerabilityAgentForm(request.GET),
        }
        return render(request=request, template_name=self.template_name, context=context)

    def post(self, request):
        form = VulnerabilityAgentForm(request.POST)
        if form.is_valid():
            question = form.cleaned_data["message"]
            message_data = self.summary_analyzer(question=question)

            context = {
                "vulnerability_agent_form": VulnerabilityAgentForm(initial={"message": question}),
                "message": message_data,
            }
            return render(request=request, template_name=self.template_name, context=context)
        return Http404("Invalid form data")  # FIXME

    def summary_analyzer(self, question):
        prompt = PromptTemplate(
            input_variables=["context", "question"],
            template="""
You are a highly specialized Vulnerability Analysis Assistant. Your task is to analyze the following vulnerability summary and accurately extract the affected and fixed versions of the software.  

Output Format:  
- Affected Version: Use one of the following formats:  
  - >= <version>, <= <version>, > <version>, < <version>  
  - A specific range like <version1> - <version2>  
- Fixed Version: Use one of the following formats:  
  - >= <version>, <= <version>, > <version>, < <version>  
  - "Not Fixed" if no fixed version is mentioned.  

Instructions:  
- Ensure accuracy by considering different ways affected and fixed versions might be described in the summary.  
- Extract only version-related details without adding any extra information.  

Database Context:  
{context}  

Question:
{question}

Provide the answer strictly based on the above context.  
            """,
        )
        vulnerability_id = extract_vulnerability_id(question)
        retriever.search_kwargs["filter"] = {"vulnerability_id": vulnerability_id}
        context = retriever.invoke(question)

        print(context)
        formatted_prompt = prompt.format(context=context, question=question)
        response = qa_chain.invoke(formatted_prompt)

        result = response["result"]
        cleaned_result = re.sub(r"<think>.*?</think>", "", result, flags=re.DOTALL).strip()
        return cleaned_result


def extract_vulnerability_id(query):
    """
    Extracts the vulnerability ID from a user query.
    Assumes the format: 'VCID-xxxx-xxxx-xxxx'.
    """
    match = re.search(r"VCID-[a-zA-Z0-9-]+", query)
    return match.group(0) if match else None
