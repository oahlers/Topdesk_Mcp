from __future__ import annotations

import html
import os
import re
from typing import Any
from urllib.parse import quote

import requests
from dotenv import load_dotenv
from mcp.server import MCPServer


load_dotenv()

mcp = MCPServer("TOPdesk MCP")

TOPDESK_USER = os.getenv("TOPDESK_USER", "").strip()
TOPDESK_TOKEN = os.getenv("TOPDESK_TOKEN", "").strip()
TOPDESK_HOST = os.getenv(
    "TOPDESK_HOST",
    "https://saether.topdesk.net",
).rstrip("/")

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
KNOWLEDGE_PAGE_SIZE = int(os.getenv("KNOWLEDGE_PAGE_SIZE", "100"))
INCIDENT_SCAN_LIMIT = int(os.getenv("INCIDENT_SCAN_LIMIT", "250"))

KNOWLEDGE_BASE_URL = f"{TOPDESK_HOST}/services/knowledge-base-v1"
INCIDENT_BASE_URL = f"{TOPDESK_HOST}/tas/api"

KNOWLEDGE_FIELDS = (
    "title,description,content,keywords,urls,modificationDate,"
    "availableTranslations"
)

INCIDENT_FIELDS = (
    "id,number,briefDescription,request,action,creationDate,modificationDate,"
    "targetDate,closedDate,status,caller,operator,operatorGroup,category,"
    "subcategory,callType,priority,urgency,impact,branch,location,object"
)


def validate_configuration() -> None:
    missing = []

    if not TOPDESK_USER:
        missing.append("TOPDESK_USER")

    if not TOPDESK_TOKEN:
        missing.append("TOPDESK_TOKEN")

    if missing:
        raise RuntimeError(
            "Missing environment variables: " + ", ".join(missing)
        )


def clean_html(value: Any) -> str:
    if value is None:
        return ""

    text = html.unescape(str(value))
    text = re.sub(r"<\s*br\s*/?\s*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(
        r"</\s*(p|div|li|ol|ul|h[1-6])\s*>",
        "\n",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"<\s*img\b[^>]*>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text)

    return text.strip()


def scalar(value: Any) -> str:
    if isinstance(value, dict):
        return str(
            value.get("name")
            or value.get("value")
            or value.get("id")
            or ""
        )

    return str(value or "")


def tokenize(query: str) -> list[str]:
    return [
        part.lower()
        for part in re.findall(r"[\wæøåÆØÅ-]+", query or "")
        if len(part) > 1
    ]


def topdesk_get(
    base_url: str,
    path: str,
    params: dict[str, Any] | None = None,
    accept: str = "application/json",
) -> Any:
    validate_configuration()

    response = requests.get(
        f"{base_url}{path}",
        params=params,
        auth=(TOPDESK_USER, TOPDESK_TOKEN),
        headers={"Accept": accept},
        timeout=REQUEST_TIMEOUT,
    )

    response.raise_for_status()

    if not response.content:
        return {}

    return response.json()


def knowledge_get(
    path: str,
    params: dict[str, Any] | None = None,
) -> Any:
    return topdesk_get(
        KNOWLEDGE_BASE_URL,
        path,
        params=params,
        accept=(
            "application/x.topdesk-kb-ki-list-v1+json, "
            "application/x.topdesk-kb-ki-v1+json, "
            "application/json"
        ),
    )


def incident_get(
    path: str,
    params: dict[str, Any] | None = None,
) -> Any:
    return topdesk_get(
        INCIDENT_BASE_URL,
        path,
        params=params,
    )


def extract_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("item", "items", "results", "data"):
            value = data.get(key)

            if isinstance(value, list):
                return value

    return []


def transform_knowledge_item(item: dict[str, Any]) -> dict[str, Any]:
    translation = item.get("translation", {})
    content = translation.get("content", {})

    return {
        "id": str(item.get("id") or ""),
        "number": str(item.get("number") or ""),
        "title": clean_html(content.get("title", "")),
        "description": clean_html(content.get("description", "")),
        "content": clean_html(content.get("content", "")),
        "keywords": clean_html(content.get("keywords", "")),
        "modificationDate": str(item.get("modificationDate") or ""),
        "availableTranslations": item.get("availableTranslations") or [],
        "urls": item.get("urls") or {},
    }


def transform_incident(item: dict[str, Any]) -> dict[str, Any]:
    transformed = {
        "id": str(item.get("id") or ""),
        "number": str(item.get("number") or ""),
        "briefDescription": clean_html(item.get("briefDescription", "")),
        "request": clean_html(item.get("request", "")),
        "action": clean_html(item.get("action", "")),
        "creationDate": str(item.get("creationDate") or ""),
        "modificationDate": str(item.get("modificationDate") or ""),
        "targetDate": str(item.get("targetDate") or ""),
        "closedDate": str(item.get("closedDate") or ""),
    }

    for name in (
        "status",
        "caller",
        "operator",
        "operatorGroup",
        "category",
        "subcategory",
        "callType",
        "priority",
        "urgency",
        "impact",
        "branch",
        "location",
        "object",
    ):
        transformed[name] = scalar(item.get(name))

    return transformed


def knowledge_score(
    item: dict[str, Any],
    terms: list[str],
) -> int:
    weighted_fields = (
        (item.get("number", "").lower(), 100),
        (item.get("title", "").lower(), 25),
        (item.get("keywords", "").lower(), 20),
        (item.get("description", "").lower(), 12),
        (item.get("content", "").lower(), 8),
    )

    return sum(
        weight
        for term in terms
        for text, weight in weighted_fields
        if term in text
    )


def incident_score(
    item: dict[str, Any],
    terms: list[str],
) -> int:
    weighted_fields = (
        (item.get("number", "").lower(), 100),
        (item.get("briefDescription", "").lower(), 30),
        (item.get("request", "").lower(), 20),
        (item.get("action", "").lower(), 12),
        (item.get("category", "").lower(), 10),
        (item.get("subcategory", "").lower(), 10),
        (item.get("status", "").lower(), 8),
        (item.get("caller", "").lower(), 6),
        (item.get("operator", "").lower(), 6),
        (item.get("operatorGroup", "").lower(), 6),
    )

    return sum(
        weight
        for term in terms
        for text, weight in weighted_fields
        if term in text
    )


def get_all_knowledge_items() -> list[dict[str, Any]]:
    all_items = []
    start = 0

    while True:
        data = knowledge_get(
            "/knowledgeItems",
            params={
                "start": start,
                "page_size": KNOWLEDGE_PAGE_SIZE,
                "fields": KNOWLEDGE_FIELDS,
            },
        )

        page_items = extract_list(data)
        all_items.extend(page_items)

        if not page_items:
            break

        if not isinstance(data, dict) or not data.get("next"):
            break

        start += len(page_items)

    return all_items


@mcp.tool()
def health() -> dict[str, Any]:
    """Check whether the MCP server has the required TOPdesk configuration."""
    missing = []

    if not TOPDESK_USER:
        missing.append("TOPDESK_USER")

    if not TOPDESK_TOKEN:
        missing.append("TOPDESK_TOKEN")

    return {
        "status": "ok" if not missing else "configuration_error",
        "missingVariables": missing,
        "topdeskHost": TOPDESK_HOST,
    }


@mcp.tool()
def search_knowledge(
    query: str,
    limit: int = 7,
) -> dict[str, Any]:
    """Search TOPdesk Knowledge Base and return the most relevant articles."""
    query = query.strip()
    limit = max(1, min(limit, 10))

    if not query:
        raise ValueError("query must not be empty")

    terms = tokenize(query)
    transformed_items = [
        transform_knowledge_item(item)
        for item in get_all_knowledge_items()
    ]

    results = []

    for item in transformed_items:
        score = knowledge_score(item, terms)

        if score > 0:
            result = dict(item)
            result["relevanceScore"] = score
            results.append(result)

    results.sort(
        key=lambda item: (
            item.get("relevanceScore", 0),
            item.get("modificationDate", ""),
        ),
        reverse=True,
    )

    selected = results[:limit]

    return {
        "query": query,
        "count": len(selected),
        "references": selected,
    }


@mcp.tool()
@mcp.tool()
def get_knowledge_item(
    identifier: str,
) -> dict[str, Any]:
    """
    Get one TOPdesk Knowledge Item by UUID or KI number.

    Accepted examples:
    - KI 0009
    - KI0009
    - 0009
    - A TOPdesk Knowledge Item UUID
    """
    identifier = identifier.strip()

    if not identifier:
        raise ValueError("identifier must not be empty")

    normalized_identifier = re.sub(
        r"\s+",
        " ",
        identifier,
    ).strip()

    uuid_pattern = re.compile(
        r"^[0-9a-fA-F]{8}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{12}$"
    )

    # Hvis input allerede er et UUID, hentes artiklen direkte.
    if uuid_pattern.fullmatch(normalized_identifier):
        data = knowledge_get(
            f"/knowledgeItems/{quote(normalized_identifier, safe='')}",
            params={
                "fields": KNOWLEDGE_FIELDS,
            },
        )

        return transform_knowledge_item(data)

    # Normaliser KI-nummeret.
    number_part = re.sub(
        r"^KI\s*",
        "",
        normalized_identifier,
        flags=re.IGNORECASE,
    ).strip()

    if not number_part:
        raise ValueError(
            f"Invalid Knowledge Item identifier: {identifier}"
        )

    # Bevar eksisterende nuller, men understøt også fx "9".
    if number_part.isdigit():
        number_part = number_part.zfill(4)

    expected_number = f"KI {number_part}".upper()

    # Find først Knowledge Item via listen for at få UUID'et.
    items = get_all_knowledge_items()

    matching_item = None

    for item in items:
        item_number = str(
            item.get("number")
            or ""
        ).strip().upper()

        if item_number == expected_number:
            matching_item = item
            break

    if matching_item is None:
        raise ValueError(
            f"Knowledge Item {expected_number} was not found."
        )

    knowledge_item_id = str(
        matching_item.get("id")
        or ""
    ).strip()

    if not knowledge_item_id:
        raise ValueError(
            f"Knowledge Item {expected_number} has no UUID."
        )

    # Hent derefter den komplette artikel via UUID.
    data = knowledge_get(
        f"/knowledgeItems/{quote(knowledge_item_id, safe='')}",
        params={
            "fields": KNOWLEDGE_FIELDS,
        },
    )

    transformed = transform_knowledge_item(data)

    # Sikrer nummeret, hvis detalje-endpointet ikke returnerer det.
    if not transformed.get("number"):
        transformed["number"] = expected_number

    return transformed

@mcp.tool()
def list_recent_incidents(
    limit: int = 10,
    start: int = 0,
    status: str = "",
) -> dict[str, Any]:
    """List recent accessible TOPdesk incidents, optionally filtered by status."""
    limit = max(1, min(limit, 100))
    start = max(0, start)
    status_filter = status.strip().lower()

    data = incident_get(
        "/incidents",
        params={
            "pageStart": start,
            "pageSize": limit,
            "sort": "creationDate:desc",
            "dateFormat": "iso8601",
            "fields": INCIDENT_FIELDS,
        },
    )

    incidents = [
        transform_incident(item)
        for item in extract_list(data)
    ]

    if status_filter:
        incidents = [
            item
            for item in incidents
            if status_filter in item.get("status", "").lower()
        ]

    return {
        "count": len(incidents),
        "start": start,
        "limit": limit,
        "incidents": incidents,
    }


@mcp.tool()
def search_incidents(
    query: str,
    limit: int = 7,
    scan: int = 250,
) -> dict[str, Any]:
    """Search recent TOPdesk incidents and return 5 to 10 relevant references."""
    query = query.strip()
    limit = max(5, min(limit, 10))
    scan = max(25, min(scan, 1000))

    if not query:
        raise ValueError("query must not be empty")

    data = incident_get(
        "/incidents",
        params={
            "pageStart": 0,
            "pageSize": scan,
            "sort": "creationDate:desc",
            "dateFormat": "iso8601",
            "fields": INCIDENT_FIELDS,
        },
    )

    incidents = [
        transform_incident(item)
        for item in extract_list(data)
    ]

    terms = tokenize(query)
    results = []

    for incident in incidents:
        score = incident_score(incident, terms)

        if score > 0:
            result = dict(incident)
            result["relevanceScore"] = score
            results.append(result)

    results.sort(
        key=lambda item: (
            item.get("relevanceScore", 0),
            item.get("creationDate", ""),
        ),
        reverse=True,
    )

    selected = results[:limit]

    return {
        "query": query,
        "scanned": len(incidents),
        "count": len(selected),
        "references": selected,
    }


@mcp.tool()
def get_incident_by_id(
    incident_id: str,
) -> dict[str, Any]:
    """Get one TOPdesk incident by UUID."""
    incident_id = incident_id.strip()

    if not incident_id:
        raise ValueError("incident_id must not be empty")

    data = incident_get(
        f"/incidents/id/{quote(incident_id, safe='')}",
        params={"dateFormat": "iso8601"},
    )

    return transform_incident(data)


@mcp.tool()
def get_incident_by_number(
    number: str,
) -> dict[str, Any]:
    """Get one TOPdesk incident by its complete incident number."""
    number = number.strip()

    if not number:
        raise ValueError("number must not be empty")

    data = incident_get(
        f"/incidents/number/{quote(number, safe='')}",
        params={"dateFormat": "iso8601"},
    )

    return transform_incident(data)


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))

    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port,
        streamable_http_path="/mcp",
    )