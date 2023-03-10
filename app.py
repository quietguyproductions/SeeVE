"""
Instructions: 
1) Create enums for the OSV schema.
2) Create dataclasses for OSV schema.
3) Use Weviate as a backend to store OSV data from the Advisory Database
4) Use Weviate to generate the base embeddings for a HypotheticalDocumentEmbedder
"""
# setup default type annotations
from typing import *
from enum import Enum
# override with docarray types as needed
from docarray import dataclass
from docarray.typing import Image, Text, JSON
from docarray import Document, DocumentArray


# 1) Create enums for the OSV schema.
class SeverityType(Enum):
    CVSS_V2 = "CVSS_V2"
    CVSS_V3 = "CVSS_V3"

class AffectedType(Enum):
    GIT = "GIT"
    SEMVER = "SEMVER"
    ECOSYSTEM = "ECOSYSTEM"

class ReferenceType(Enum):
    ADVISORY = "ADVISORY"
    ARTICLE = "ARTICLE"
    REPORT = "REPORT"
    FIX = "FIX"
    GIT = "GIT"
    PACKAGE = "PACKAGE"
    EVIDENCE = "EVIDENCE"
    WEB = "WEB"

class CreditType(Enum):
    FINDER = "FINDER"
    REPORTER = "REPORTER"
    ANALYST = "ANALYST"
    COORDINATOR = "COORDINATOR"
    REMEDIATION_DEVELOPER = "REMEDIATION_DEVELOPER"
    REMEDIATION_REVIEWER = "REMEDIATION_REVIEWER"
    REMEDIATION_VERIFIER = "REMEDIATION_VERIFIER"
    TOOL = "TOOL"
    SPONSOR = "SPONSOR"
    OTHER = "OTHER"

# 2) Create dataclasses for OSV schema.
@dataclass
class Severity:
    type: SeverityType
    score: str

@dataclass
class Package:
    ecosystem: str
    name: str
    purl: str

@dataclass
class Event:
    introduced: str = None
    fixed: str = None
    last_affected: str = None
    limit: str = None

@dataclass
class Range:
    type: AffectedType
    repo: str = None
    events: List[Event]
    database_specific: JSON = None

@dataclass
class Affected:
    package: Package
    severity: List[Severity] = None
    ranges: List[Range] = None
    versions: List[str] = None
    ecosystem_specific: JSON = None
    database_specific: JSON = None

@dataclass
class Reference:
    type: ReferenceType
    url: str

@dataclass
class Credit:
    name: str
    contact: List[str] = None
    type: CreditType = None

@dataclass
class OSV:
    schema_version: str = None
    id: str
    modified: str
    published: str = None
    withdrawn: str = None
    aliases: List[str] = None
    related: List[str] = None
    summary: str = None
    details: str = None
    severity: List[Severity] = None
    affected: List[Affected] = None
    references: List[Reference] = None
    credits: List[Credit] = None
    database_specific: JSON = None


# Load API token - replace with script to load your token, e.g. from your environment variables, via:
import os


def load_advisory_database_into_weviate(uri: str, weviate_url: str, weviate_port: int=8080) -> DocumentArray:
    """
    This function takes the uri of a cloned copy of the Advisory Database and crawls the
    repository, collecting all the OSV formatted json vulnerability files into a DocumentArray.
    """
    def json_loader():
        for root, dirs, files in os.walk(uri):
            for filename in files:
                if filename.endswith(".json"):
                    yield os.path.join(root, filename)
    # Use the Weviate backend for storage
    return DocumentArray.from_files(json_loader(), protocol="jsonschema", storage="weaviate", 
                            config={"name": "Persisted", "host": weviate_url, "port": weviate_port})


OSV_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Open Source Vulnerability",
  "description": "A schema for describing a vulnerability in an open source package.",
  "type": "object",
  "properties": {
    "schema_version": {
      "type": "string"
    },
    "id": {
      "type": "string"
    },
    "modified": {
      "type": "string",
      "format": "date-time"
    },
    "published": {
      "type": "string",
      "format": "date-time"
    },
    "withdrawn": {
      "type": "string",
      "format": "date-time"
    },
    "aliases": {
      "type": ["array", "null"],
      "items": {
        "type": "string"
      }
    },
    "related": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "summary": {
      "type": "string"
    },
    "details": {
      "type": "string"
    },
    "severity": {
      "type": ["array", "null"],
      "items": {
        "type": "object",
        "properties": {
          "type": {
            "type": "string",
            "enum": [
              "CVSS_V2",
              "CVSS_V3"
            ]
          },
          "score": {
            "type": "string"
          }
        },
        "required": [
          "type",
          "score"
        ]
      }
    },
    "affected": {
      "type": ["array", "null"],
      "items": {
        "type": "object",
        "properties": {
          "package": {
            "type": "object",
            "properties": {
              "ecosystem": {
                "type": "string"
              },
              "name": {
                "type": "string"
              },
              "purl": {
                "type": "string"
              }
            },
            "required": [
              "ecosystem",
              "name"
            ]
          },
          "severity": {
            "type": ["array", "null"],
            "items": {
              "type": "object",
              "properties": {
                "type": {
                  "type": "string",
                  "enum": [
                    "CVSS_V2",
                    "CVSS_V3"
                  ]
                },
                "score": {
                  "type": "string"
                }
              },
              "required": [
                "type",
                "score"
              ]
            }
          },
          "ranges": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "type": {
                  "type": "string",
                  "enum": [
                    "GIT",
                    "SEMVER",
                    "ECOSYSTEM"
                  ]
                },
                "repo": {
                  "type": "string"
                },
                "events": {
                  "type": "array",
                  "contains": {
                    "required": [
                      "introduced"
                    ]
                  },
                  "items": {
                    "type": "object",
                    "oneOf": [
                      {
                        "type": "object",
                        "properties": {
                          "introduced": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "introduced"
                        ]
                      },
                      {
                        "type": "object",
                        "properties": {
                          "fixed": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "fixed"
                        ]
                      },
                      {
                        "type": "object",
                        "properties": {
                          "last_affected": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "last_affected"
                        ]
                      },
                      {
                        "type": "object",
                        "properties": {
                          "limit": {
                            "type": "string"
                          }
                        },
                        "required": [
                          "limit"
                        ]
                      }
                    ]
                  },
                  "minItems": 1
                },
                "database_specific": {
                  "type": "object"
                }
              },
              "allOf": [
                {
                  "if": {
                    "properties": {
                      "type": {
                        "const": "GIT"
                      }
                    }
                  },
                  "then": {
                    "required": [
                      "repo"
                    ]
                  }
                },
                {
                  "if": {
                    "properties": {
                      "events": {
                        "contains": {
                          "required": ["last_affected"]
                        }
                      }
                    }
                  },
                  "then": {
                    "not": {
                      "properties": {
                        "events": {
                          "contains": {
                            "required": ["fixed"]
                          }
                        }
                      }
                    }
                  }
                }
              ],
              "required": [
                "type",
                "events"
              ]
            }
          },
          "versions": {
            "type": "array",
            "items": {
              "type": "string"
            }
          },
          "ecosystem_specific": {
            "type": "object"
          },
          "database_specific": {
            "type": "object"
          }
        }
      }
    },
    "references": {
      "type": ["array", "null"],
      "items": {
        "type": "object",
        "properties": {
          "type": {
            "type": "string",
            "enum": [
              "ADVISORY",
              "ARTICLE",
              "REPORT",
              "FIX",
              "GIT",
              "PACKAGE",
              "EVIDENCE",
              "WEB"
            ]
          },
          "url": {
            "type": "string",
            "format": "uri"
          }
        },
        "required": [
          "type",
          "url"
        ]
      }
    },
    "credits": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": {
            "type": "string"
          },
          "contact": {
            "type": "array",
            "items": {
              "type": "string"
            }
          },
          "type": {
            "type": "string",
            "enum": [
              "FINDER",
              "REPORTER",
              "ANALYST",
              "COORDINATOR",
              "REMEDIATION_DEVELOPER",
              "REMEDIATION_REVIEWER",
              "REMEDIATION_VERIFIER",
              "TOOL",
              "SPONSOR",
              "OTHER"
          ]
          }
        },
        "required": [
          "name"
        ]
      }
    },
    "database_specific": {
      "type": "object"
    }
  },
  "required": [
    "id",
    "modified"
  ]
}

REFERENCE_SCHEMA = {
    "classes": [
        {
            "class": "Reference",
            "description": "A written paragraph",
            "vectorizer": "text2vec-openai",
            "moduleConfig": {
                "text2vec-openai": {
                "model": "babbage",
                "type": "text"
                }
            },
            "properties": [
                {
                    "dataType": ["text"],
                    "description": "The content of the paragraph",
                    "moduleConfig": {
                        "text2vec-openai": {
                        "skip": False,
                        "vectorizePropertyName": False
                        }
                    },
                    "name": "content",
                },
            ],
        },
    ]
}

def weviate_osv_schema(schema):
    """
    Update Weviate schema with OSV
    """

DEBUG = True

def instantiante_weviate_client(weviate_url: str, weviate_port: int=8080):
    client = weaviate.Client(
        url=weviate_url,
        additional_headers={
            'X-OpenAI-Api-Key': os.environ["OPENAI_API_KEY"]
        }
    )
    if DEBUG:
        client.schema.delete_all()
    # prime the client
    client.schema.get()
    #
    client.schema.create(OSV_SCHEMA)
    return client


def get_reference_text_from_vulnerability(vuln: Document) -> str:
    raise NotImplementedError()


def enrich_datastore(client: weviate.Client, vulndb: DocumentArray) -> None:
    with client.batch as batch:
        for vuln in vulndb:
            batch.add_data_object({"content": get_reference_text_from_vulnerability(vuln)}, "Reference")

if __name__ == "__main__":
    from langchain.vectorstores.weaviate import Weaviate
    vectorstore = Weaviate(client, "Paragraph", "content")

    # do fast api stuff here
    query = "What did the president say about Ketanji Brown Jackson"
    docs = vectorstore.similarity_search(query)

