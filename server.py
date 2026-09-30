from __future__ import annotations

import html
import os
import re
from datetime import datetime
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
WRITE_OPERATIONS_ENABLED = os.getenv(
    "WRITE_OPERATIONS_ENABLED",
    "false",
).strip().lower() in {"1", "true", "yes", "on"}

KNOWLEDGE_BASE_URL = f"{TOPDESK_HOST}/services/knowledge-base-v1"
INCIDENT_BASE_URL = f"{TOPDESK_HOST}/tas/api"
DEFAULT_ENTRY_TYPE_NAME = "Chat"

KNOWLEDGE_FIELDS = (
    "title,description,content,keywords,urls,modificationDate,"
    "availableTranslations"
)

INCIDENT_FIELDS = (
    "id,number,briefDescription,request,action,creationDate,modificationDate,"
    "targetDate,closedDate,status,caller,operator,operatorGroup,category,"
    "subcategory,callType,entryType,priority,urgency,impact,branch,location,object,"
    "processingStatus"
)


class TopdeskApiError(RuntimeError):
    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_text: str = "",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


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
            or value.get("number")
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


def topdesk_request(
    method: str,
    base_url: str,
    path: str,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    accept: str = "application/json",
) -> Any:
    validate_configuration()

    if method.upper() != "GET" and not WRITE_OPERATIONS_ENABLED:
        raise PermissionError(
            "TOPdesk write operations are disabled. "
            "Set WRITE_OPERATIONS_ENABLED=true."
        )

    response = requests.request(
        method=method.upper(),
        url=f"{base_url}{path}",
        params=params,
        json=json_body,
        auth=(TOPDESK_USER, TOPDESK_TOKEN),
        headers={
            "Accept": accept,
            "Content-Type": "application/json",
        },
        timeout=REQUEST_TIMEOUT,
    )

    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        raise TopdeskApiError(
            f"TOPdesk returned HTTP {response.status_code} for {path}.",
            response.status_code,
            response.text[:2000],
        ) from exc

    if response.status_code == 204 or not response.content:
        return {}

    return response.json()


def knowledge_get(
    path: str,
    params: dict[str, Any] | None = None,
) -> Any:
    return topdesk_request(
        "GET",
        KNOWLEDGE_BASE_URL,
        path,
        params=params,
        accept=(
            "application/x.topdesk-kb-ki-list-v1+json, "
            "application/x.topdesk-kb-ki-v1+json, application/json"
        ),
    )


def incident_get(
    path: str,
    params: dict[str, Any] | None = None,
) -> Any:
    return topdesk_request(
        "GET",
        INCIDENT_BASE_URL,
        path,
        params=params,
    )


def incident_write(
    method: str,
    path: str,
    json_body: dict[str, Any],
    params: dict[str, Any] | None = None,
) -> Any:
    return topdesk_request(
        method,
        INCIDENT_BASE_URL,
        path,
        params=params,
        json_body=json_body,
    )


def extract_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in (
            "item",
            "items",
            "results",
            "data",
            "persons",
            "operators",
            "operatorGroups",
        ):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def transform_knowledge_item(item: dict[str, Any]) -> dict[str, Any]:
    translation = item.get("translation") or {}
    content = translation.get("content") or {}
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
    result = {
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
        "entryType",
        "priority",
        "urgency",
        "impact",
        "branch",
        "location",
        "object",
        "processingStatus",
    ):
        result[name] = scalar(item.get(name))
    return result


def get_all_knowledge_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
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
        page = extract_list(data)
        items.extend(page)

        if not page:
            break
        if not isinstance(data, dict) or not data.get("next"):
            break
        start += len(page)

    return items


def normalize_ki_number(identifier: str) -> str:
    value = re.sub(r"\s+", " ", identifier.strip()).upper()
    value = re.sub(r"^KI\s*", "", value).strip()
    if value.isdigit():
        value = value.zfill(4)
    return f"KI {value}"


def is_uuid(value: str) -> bool:
    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            value.strip(),
        )
    )


def compact_metadata(
    items: list[dict[str, Any]],
    limit: int = 100,
) -> list[dict[str, Any]]:
    compact = []
    for item in items[:limit]:
        row: dict[str, Any] = {
            "id": str(item.get("id") or item.get("value") or ""),
            "name": str(
                item.get("name")
                or item.get("text")
                or item.get("value")
                or ""
            ),
        }
        category = item.get("category")
        if isinstance(category, dict):
            row["categoryId"] = str(category.get("id") or "")
            row["categoryName"] = str(category.get("name") or "")
        compact.append(row)
    return compact


def get_metadata(path: str) -> list[dict[str, Any]]:
    return compact_metadata(extract_list(incident_get(path)))


def is_masked_operator_name(value: Any) -> bool:
    """Return True when TOPdesk has returned an empty or masked display name."""
    text = str(value or "").strip()
    if not text:
        return True
    without_separators = re.sub(r"[\s*._-]+", "", text)
    return not without_separators


def first_unmasked_text(*values: Any) -> str:
    """Return the first non-empty, non-masked text value."""
    for value in values:
        text = clean_html(value).strip()
        if text and not is_masked_operator_name(text):
            return text
    return ""


def extract_operator_name(operator: dict[str, Any]) -> str:
    """Extract the best available real operator name from a TOPdesk response."""
    person = operator.get("person")
    person = person if isinstance(person, dict) else {}

    first_name = first_unmasked_text(
        operator.get("firstName"),
        operator.get("firstname"),
        person.get("firstName"),
        person.get("firstname"),
    )
    last_name = first_unmasked_text(
        operator.get("surName"),
        operator.get("surname"),
        operator.get("lastName"),
        operator.get("lastname"),
        person.get("surName"),
        person.get("surname"),
        person.get("lastName"),
        person.get("lastname"),
    )
    combined_name = " ".join(
        part for part in (first_name, last_name) if part
    ).strip()
    if combined_name:
        return combined_name

    return first_unmasked_text(
        operator.get("dynamicName"),
        operator.get("fullName"),
        operator.get("displayName"),
        person.get("dynamicName"),
        person.get("fullName"),
        person.get("displayName"),
        person.get("name"),
        operator.get("name"),
        operator.get("text"),
    )


def resolve_operator_choice(
    operator: dict[str, Any],
    index: int,
) -> dict[str, Any]:
    """Resolve an operator name, using the detail endpoint when needed."""
    operator_id = str(
        operator.get("id")
        or operator.get("value")
        or ""
    ).strip()
    operator_name = extract_operator_name(operator)

    if operator_id and not operator_name:
        try:
            detail = incident_get(
                f"/incidents/operators/lookup/{quote(operator_id, safe='')}"
            )
            if isinstance(detail, dict):
                operator_name = extract_operator_name(detail)
        except TopdeskApiError:
            operator_name = ""

    if not operator_name:
        operator_name = f"Operatør {index}"

    return {
        "id": operator_id,
        "name": operator_name,
        "number": index,
        "display": f"({index}) {operator_name} (ID: {operator_id})",
    }


def format_user_choices(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Format TOPdesk metadata so users can choose by name and ID."""
    choices = []
    for index, item in enumerate(items, start=1):
        item_id = str(item.get("id") or "").strip()
        item_name = str(item.get("name") or "").strip()
        choice = dict(item)
        choice["number"] = index
        choice["display"] = f"({index}) {item_name} (ID: {item_id})"
        choices.append(choice)
    return choices


def validate_category_subcategory(
    category_id: str,
    subcategory_id: str,
) -> dict[str, Any]:
    subcategories = get_metadata("/incidents/subcategories")
    selected = next(
        (
            item
            for item in subcategories
            if item.get("id") == subcategory_id
        ),
        None,
    )

    if selected is None:
        return {
            "valid": False,
            "message": "Den valgte underkategori findes ikke.",
        }

    linked_category_id = str(selected.get("categoryId") or "")
    if linked_category_id and linked_category_id != category_id:
        return {
            "valid": False,
            "message": (
                "Den valgte underkategori tilhører ikke den valgte kategori."
            ),
        }

    return {"valid": True}


def required_wizard_fields(
    brief_description: str,
    caller_id: str,
    request_text: str,
    category_id: str,
    subcategory_id: str,
    operator_group_id: str,
    operator_id: str,
) -> list[str]:
    values = {
        "brief_description": brief_description,
        "caller_id": caller_id,
        "request_text": request_text,
        "category_id": category_id,
        "subcategory_id": subcategory_id,
        "operator_group_id": operator_group_id,
        "operator_id": operator_id,
    }
    return [
        name
        for name, value in values.items()
        if not value.strip()
    ]


def build_second_line_payload(
    brief_description: str,
    caller_id: str,
    request_text: str,
    category_id: str,
    subcategory_id: str,
    operator_group_id: str,
    operator_id: str,
    call_type_id: str = "",
    impact_id: str = "",
    urgency_id: str = "",
    priority_id: str = "",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": "secondLine",
        "briefDescription": brief_description.strip(),
        "request": request_text.strip(),
        "callerLookup": {"id": caller_id.strip()},
        "entryType": {"name": DEFAULT_ENTRY_TYPE_NAME},
        "category": {"id": category_id.strip()},
        "subcategory": {"id": subcategory_id.strip()},
        "operatorGroup": {"id": operator_group_id.strip()},
        "operator": {"id": operator_id.strip()},
    }

    optional_fields = {
        "callType": call_type_id,
        "impact": impact_id,
        "urgency": urgency_id,
        "priority": priority_id,
    }
    for field_name, reference_id in optional_fields.items():
        if reference_id.strip():
            payload[field_name] = {"id": reference_id.strip()}

    return payload


def extract_match_context(text: str, needle: str, context: int = 140) -> str:
    """Return a short excerpt around a case-insensitive text match."""
    cleaned = clean_html(text)
    if not cleaned or not needle:
        return ""
    position = cleaned.casefold().find(needle.casefold())
    if position < 0:
        return ""
    start = max(0, position - context)
    end = min(len(cleaned), position + len(needle) + context)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(cleaned) else ""
    return f"{prefix}{cleaned[start:end].strip()}{suffix}"


def format_incident_datetime(value: Any) -> str:
    """Format a TOPdesk timestamp as a full date and time."""
    text = str(value or "").strip()
    if not text:
        return ""

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.strftime("%d-%m-%Y %H:%M")
    except (TypeError, ValueError):
        return text


@mcp.tool()
def health() -> dict[str, Any]:
    """Check configuration and write-operation status."""
    missing = []
    if not TOPDESK_USER:
        missing.append("TOPDESK_USER")
    if not TOPDESK_TOKEN:
        missing.append("TOPDESK_TOKEN")
    return {
        "status": "ok" if not missing else "configuration_error",
        "missingVariables": missing,
        "topdeskHost": TOPDESK_HOST,
        "writeOperationsEnabled": WRITE_OPERATIONS_ENABLED,
        "defaultIncidentLine": "secondLine",
        "defaultEntryType": DEFAULT_ENTRY_TYPE_NAME,
    }


@mcp.tool()
def search_knowledge(
    query: str,
    limit: int = 7,
) -> dict[str, Any]:
    """Search TOPdesk Knowledge Base."""
    query = query.strip()
    limit = max(1, min(limit, 10))
    if not query:
        raise ValueError("query must not be empty")

    terms = tokenize(query)
    results = []

    for raw in get_all_knowledge_items():
        item = transform_knowledge_item(raw)
        weighted_fields = (
            (item.get("number", "").lower(), 100),
            (item.get("title", "").lower(), 25),
            (item.get("keywords", "").lower(), 20),
            (item.get("description", "").lower(), 12),
            (item.get("content", "").lower(), 8),
        )
        score = sum(
            weight
            for term in terms
            for text, weight in weighted_fields
            if term in text
        )
        if score:
            item["relevanceScore"] = score
            results.append(item)

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
def get_knowledge_item(identifier: str) -> dict[str, Any]:
    """Get a Knowledge Item by UUID or KI number."""
    identifier = identifier.strip()
    if not identifier:
        raise ValueError("identifier must not be empty")

    if is_uuid(identifier):
        return transform_knowledge_item(
            knowledge_get(
                f"/knowledgeItems/{quote(identifier, safe='')}",
                params={"fields": KNOWLEDGE_FIELDS},
            )
        )

    expected_number = normalize_ki_number(identifier)
    match = next(
        (
            item
            for item in get_all_knowledge_items()
            if str(item.get("number") or "").strip().upper()
            == expected_number
        ),
        None,
    )
    if match is None:
        raise ValueError(f"Knowledge Item {expected_number} was not found.")

    item_id = str(match.get("id") or "").strip()
    if not item_id:
        raise ValueError(f"Knowledge Item {expected_number} has no UUID.")

    result = transform_knowledge_item(
        knowledge_get(
            f"/knowledgeItems/{quote(item_id, safe='')}",
            params={"fields": KNOWLEDGE_FIELDS},
        )
    )
    if not result.get("number"):
        result["number"] = expected_number
    return result


@mcp.tool()
def list_recent_incidents(
    limit: int = 10,
    start: int = 0,
) -> dict[str, Any]:
    """List recent firstLine and secondLine incidents in a fixed table format."""
    limit = max(1, min(limit, 100))
    page_start = max(0, start)
    page_size = min(100, max(limit, 25))
    incidents: list[dict[str, Any]] = []

    while len(incidents) < limit:
        data = incident_get(
            "/incidents",
            params={
                "pageStart": page_start,
                "pageSize": page_size,
                "sort": "creationDate:desc",
                "dateFormat": "iso8601",
                "fields": INCIDENT_FIELDS,
            },
        )
        raw_incidents = extract_list(data)
        if not raw_incidents:
            break

        for raw in raw_incidents:
            incident = transform_incident(raw)
            incident_status = incident.get("status", "").casefold()

            # Include both firstLine and secondLine incidents, but do not expose
            # status as a display column.
            if incident_status not in {"firstline", "secondline"}:
                continue

            # TOPdesk can omit assignment information from the list endpoint.
            # Retrieve the full incident when operator details are missing.
            if not incident.get("operator") or not incident.get("operatorGroup"):
                incident_id = incident.get("id", "").strip()
                incident_number = incident.get("number", "").strip()
                try:
                    if incident_id:
                        detail_raw = incident_get(
                            f"/incidents/id/{quote(incident_id, safe='')}",
                            params={"dateFormat": "iso8601"},
                        )
                    elif incident_number:
                        detail_raw = incident_get(
                            f"/incidents/number/{quote(incident_number, safe='')}",
                            params={"dateFormat": "iso8601"},
                        )
                    else:
                        detail_raw = {}

                    if isinstance(detail_raw, dict) and detail_raw:
                        incident = transform_incident(detail_raw)
                except TopdeskApiError:
                    pass

            incidents.append(
                {
                    "Sagsnummer": incident.get("number", ""),
                    "Beskrivelse": incident.get("briefDescription", ""),
                    "Anmoder": incident.get("caller", "") or "Ikke angivet",
                    "Ansvarlig": incident.get("operator", "") or "Ikke tildelt",
                    "Gruppe": incident.get("operatorGroup", "") or "Ikke tildelt",
                    "Oprettet": format_incident_datetime(
                        incident.get("creationDate", "")
                    ),
                }
            )
            if len(incidents) >= limit:
                break

        if len(raw_incidents) < page_size:
            break
        page_start += len(raw_incidents)

    return {
        "count": len(incidents),
        "displayColumns": [
            "Sagsnummer",
            "Beskrivelse",
            "Anmoder",
            "Ansvarlig",
            "Gruppe",
            "Oprettet",
        ],
        "presentationInstruction": (
            "Vis kun displayColumns i den angivne rækkefølge. "
            "Vis ikke status eller andre felter i tabellen."
        ),
        "incidents": incidents,
    }


@mcp.tool()
def search_incidents(
    query: str,
    limit: int = 7,
    scan: int = INCIDENT_SCAN_LIMIT,
) -> dict[str, Any]:
    """Search recent accessible incidents."""
    query = query.strip()
    if not query:
        raise ValueError("query must not be empty")

    limit = max(1, min(limit, 25))
    scan = max(25, min(scan, 1000))
    terms = tokenize(query)

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

    results = []
    for raw in extract_list(data):
        item = transform_incident(raw)
        weighted_fields = (
            (item.get("number", "").lower(), 100),
            (item.get("briefDescription", "").lower(), 30),
            (item.get("request", "").lower(), 20),
            (item.get("action", "").lower(), 12),
            (item.get("category", "").lower(), 10),
            (item.get("subcategory", "").lower(), 10),
            (item.get("caller", "").lower(), 6),
        )
        score = sum(
            weight
            for term in terms
            for text, weight in weighted_fields
            if term in text
        )
        if score:
            item["relevanceScore"] = score
            results.append(item)

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
        "count": len(selected),
        "references": selected,
    }


@mcp.tool()
def find_incidents_by_requester(
    requester_name: str,
    title_contains: str = "",
    status: str = "",
    limit: int = 100,
    scan: int = 1000,
    exact_match: bool = True,
) -> dict[str, Any]:
    """Find incidents by TOPdesk caller/requester.

    This tool only matches the structured caller field. It does not claim that
    the caller processed or closed the incident.
    """
    requester_name = re.sub(r"\s+", " ", requester_name).strip()
    title_contains = re.sub(r"\s+", " ", title_contains).strip()
    status = re.sub(r"\s+", " ", status).strip()

    if not requester_name:
        raise ValueError("requester_name must not be empty")

    limit = max(1, min(limit, 500))
    scan = max(1, min(scan, 5000))
    requester_filter = requester_name.casefold()
    title_filter = title_contains.casefold()
    status_filter = status.casefold()

    matches: list[dict[str, Any]] = []
    scanned = 0
    page_start = 0
    page_size = min(100, scan)

    while scanned < scan and len(matches) < limit:
        current_page_size = min(page_size, scan - scanned)
        data = incident_get(
            "/incidents",
            params={
                "pageStart": page_start,
                "pageSize": current_page_size,
                "sort": "creationDate:desc",
                "dateFormat": "iso8601",
                "fields": INCIDENT_FIELDS,
            },
        )
        raw_incidents = extract_list(data)
        if not raw_incidents:
            break

        for raw in raw_incidents:
            item = transform_incident(raw)
            scanned += 1
            caller_name = re.sub(r"\s+", " ", item.get("caller", "")).strip()
            caller_value = caller_name.casefold()
            requester_matches = (
                caller_value == requester_filter
                if exact_match
                else requester_filter in caller_value
            )
            if not requester_matches:
                continue
            if title_filter and title_filter not in item.get("briefDescription", "").casefold():
                continue
            if status_filter and status_filter not in item.get("status", "").casefold():
                continue

            item["requester"] = caller_name
            item["matchedOn"] = "caller"
            matches.append(item)
            if len(matches) >= limit:
                break

        if len(raw_incidents) < current_page_size:
            break
        page_start += len(raw_incidents)

    return {
        "status": "ok",
        "requesterName": requester_name,
        "titleContains": title_contains,
        "statusFilter": status,
        "exactMatch": exact_match,
        "scannedCount": scanned,
        "count": len(matches),
        "limitReached": len(matches) >= limit,
        "scanLimitReached": scanned >= scan,
        "incidents": matches,
        "note": (
            "Matched against the structured TOPdesk caller field. "
            "Caller is not necessarily the operator who processed or closed the incident."
        ),
    }


@mcp.tool()
def find_incidents_by_name_in_content(
    name: str,
    title_contains: str = "",
    status: str = "",
    limit: int = 200,
    scan: int = 5000,
) -> dict[str, Any]:
    """Find incidents where a person's name occurs in incident content.

    Searches request and action text, with an optional title and status filter.
    Use this when the person's name is embedded in the request text rather than
    returned in TOPdesk's structured caller field. A match proves only that the
    name occurs in the specified field, not who processed or closed the case.
    """
    name = re.sub(r"\s+", " ", name).strip()
    title_contains = re.sub(r"\s+", " ", title_contains).strip()
    status = re.sub(r"\s+", " ", status).strip()

    if not name:
        raise ValueError("name must not be empty")

    limit = max(1, min(limit, 500))
    scan = max(1, min(scan, 5000))
    name_filter = name.casefold()
    title_filter = title_contains.casefold()
    status_filter = status.casefold()

    matches: list[dict[str, Any]] = []
    scanned = 0
    page_start = 0
    page_size = min(100, scan)

    while scanned < scan and len(matches) < limit:
        current_page_size = min(page_size, scan - scanned)
        data = incident_get(
            "/incidents",
            params={
                "pageStart": page_start,
                "pageSize": current_page_size,
                "sort": "creationDate:desc",
                "dateFormat": "iso8601",
                "fields": INCIDENT_FIELDS,
            },
        )
        raw_incidents = extract_list(data)
        if not raw_incidents:
            break

        for raw in raw_incidents:
            item = transform_incident(raw)
            scanned += 1

            title = item.get("briefDescription", "")
            request_text = item.get("request", "")
            action_text = item.get("action", "")

            if title_filter and title_filter not in title.casefold():
                continue
            if status_filter and status_filter not in item.get("status", "").casefold():
                continue

            matched_fields = []
            if name_filter in request_text.casefold():
                matched_fields.append("request")
            if name_filter in action_text.casefold():
                matched_fields.append("action")

            if not matched_fields:
                continue

            item["searchedName"] = name
            item["matchedFields"] = matched_fields
            item["matchEvidence"] = {
                field: extract_match_context(item.get(field, ""), name)
                for field in matched_fields
            }
            matches.append(item)
            if len(matches) >= limit:
                break

        if len(raw_incidents) < current_page_size:
            break
        page_start += len(raw_incidents)

    return {
        "status": "ok",
        "searchedName": name,
        "titleContains": title_contains,
        "statusFilter": status,
        "searchedFields": ["request", "action"],
        "scannedCount": scanned,
        "count": len(matches),
        "limitReached": len(matches) >= limit,
        "scanLimitReached": scanned >= scan,
        "incidents": matches,
        "note": (
            "Results show incidents where the name occurs in request or action text. "
            "A text match does not by itself prove who processed or closed the incident."
        ),
    }


@mcp.tool()
def get_incident_by_id(incident_id: str) -> dict[str, Any]:
    """Get an incident by UUID."""
    incident_id = incident_id.strip()
    if not incident_id:
        raise ValueError("incident_id must not be empty")
    return transform_incident(
        incident_get(
            f"/incidents/id/{quote(incident_id, safe='')}",
            params={"dateFormat": "iso8601"},
        )
    )


@mcp.tool()
def get_incident_by_number(number: str) -> dict[str, Any]:
    """Get an incident by number."""
    number = number.strip()
    if not number:
        raise ValueError("number must not be empty")
    return transform_incident(
        incident_get(
            f"/incidents/number/{quote(number, safe='')}",
            params={"dateFormat": "iso8601"},
        )
    )


@mcp.tool()
def find_callers(
    query: str,
    limit: int = 20,
) -> dict[str, Any]:
    """Find caller candidates for the incident wizard."""
    query = query.strip().lower()
    limit = max(1, min(limit, 100))
    callers = extract_list(
        incident_get(
            "/incidents/callers/lookup",
            params={"pageStart": 0, "pageSize": 1000},
        )
    )
    selected = []
    for caller in callers:
        text = " ".join(str(value) for value in caller.values()).lower()
        if not query or query in text:
            selected.append(caller)
        if len(selected) >= limit:
            break
    return {
        "status": "ok",
        "query": query,
        "count": len(selected),
        "callers": selected,
    }


@mcp.tool()
def get_caller(caller_id: str) -> dict[str, Any]:
    """Get a caller by UUID."""
    caller_id = caller_id.strip()
    if not caller_id:
        raise ValueError("caller_id must not be empty")
    return {
        "status": "ok",
        "caller": incident_get(
            f"/incidents/callers/lookup/{quote(caller_id, safe='')}"
        ),
    }


@mcp.tool()
def list_incident_categories() -> dict[str, Any]:
    """List all incident categories with name, ID, and display label."""
    items = get_metadata("/incidents/categories")
    choices = format_user_choices(items)
    return {
        "status": "ok",
        "count": len(choices),
        "categories": choices,
        "question": "Vælg en kategori fra listen ved at angive nummer, navn eller ID.",
        "displayFormat": "(Nummer) Navn (ID: UUID)",
    }


@mcp.tool()
def list_incident_subcategories(
    category_id: str = "",
) -> dict[str, Any]:
    """List subcategories with name and ID, optionally filtered by category."""
    items = get_metadata("/incidents/subcategories")
    category_id = category_id.strip()
    if category_id:
        items = [
            item
            for item in items
            if not item.get("categoryId")
            or item.get("categoryId") == category_id
        ]
    choices = format_user_choices(items)
    return {
        "status": "ok",
        "categoryId": category_id,
        "count": len(choices),
        "subcategories": choices,
        "question": (
            "Vælg en underkategori fra listen ved at angive nummer, navn eller ID."
        ),
        "displayFormat": "(Nummer) Navn (ID: UUID)",
    }


@mcp.tool()
def list_operator_groups() -> dict[str, Any]:
    """List all operator groups with name, ID, and display label."""
    items = get_metadata("/incidents/operatorgroups/lookup")
    choices = format_user_choices(items)
    return {
        "status": "ok",
        "count": len(choices),
        "operatorGroups": choices,
        "question": (
            "Vælg en operatørgruppe fra listen ved at angive nummer, navn eller ID."
        ),
        "displayFormat": "(Nummer) Navn (ID: UUID)",
    }


@mcp.tool()
def find_operators(
    query: str = "",
    limit: int = 50,
) -> dict[str, Any]:
    """Find responsible operators while preserving their real TOPdesk names."""
    query = query.strip().lower()
    limit = max(1, min(limit, 100))
    operators = extract_list(
        incident_get(
            "/incidents/operators/lookup",
            params={"pageStart": 0, "pageSize": 1000},
        )
    )

    resolved_operators = []
    for operator in operators:
        if not isinstance(operator, dict):
            continue
        choice = resolve_operator_choice(
            operator,
            len(resolved_operators) + 1,
        )
        searchable_text = " ".join(
            (
                choice.get("name", ""),
                choice.get("id", ""),
                " ".join(str(value) for value in operator.values()),
            )
        ).lower()
        if query and query not in searchable_text:
            continue
        choice["number"] = len(resolved_operators) + 1
        choice["display"] = (
            f"({choice['number']}) {choice['name']} "
            f"(ID: {choice['id']})"
        )
        resolved_operators.append(choice)
        if len(resolved_operators) >= limit:
            break

    return {
        "status": "ok",
        "query": query,
        "count": len(resolved_operators),
        "operators": resolved_operators,
        "question": (
            "Vælg en ansvarlig operatør fra listen ved at angive nummer, navn eller ID."
        ),
        "displayFormat": "(Nummer) Navn (ID: UUID)",
        "note": (
            "TOPdesk validates that the selected operator belongs to the "
            "selected operator group when the incident is created."
        ),
    }


@mcp.tool()
def get_operator(operator_id: str) -> dict[str, Any]:
    """Get a responsible operator by UUID."""
    operator_id = operator_id.strip()
    if not operator_id:
        raise ValueError("operator_id must not be empty")
    return {
        "status": "ok",
        "operator": incident_get(
            f"/incidents/operators/lookup/{quote(operator_id, safe='')}"
        ),
    }


@mcp.tool()
def create_incident(
    brief_description: str,
    caller_id: str,
    request_text: str,
    category_id: str,
    subcategory_id: str,
    operator_group_id: str,
    operator_id: str,
    call_type_id: str = "",
    impact_id: str = "",
    urgency_id: str = "",
    priority_id: str = "",
    confirmed: bool = False,
) -> dict[str, Any]:
    """
    Create a Second Line incident with mandatory classification and assignment.
    """
    missing = required_wizard_fields(
        brief_description,
        caller_id,
        request_text,
        category_id,
        subcategory_id,
        operator_group_id,
        operator_id,
    )
    if missing:
        return {
            "status": "needs_input",
            "missingFields": missing,
        }

    if len(brief_description.strip()) > 80:
        return {
            "status": "needs_input",
            "message": "Titlen må højst indeholde 80 tegn.",
        }

    relationship = validate_category_subcategory(
        category_id.strip(),
        subcategory_id.strip(),
    )
    if not relationship.get("valid"):
        return {
            "status": "invalid_classification",
            "message": relationship.get("message"),
        }

    payload = build_second_line_payload(
        brief_description=brief_description,
        caller_id=caller_id,
        request_text=request_text,
        category_id=category_id,
        subcategory_id=subcategory_id,
        operator_group_id=operator_group_id,
        operator_id=operator_id,
        call_type_id=call_type_id,
        impact_id=impact_id,
        urgency_id=urgency_id,
        priority_id=priority_id,
    )

    if not confirmed:
        return {
            "status": "confirmation_required",
            "operation": "create_incident",
            "proposedIncident": payload,
        }

    try:
        data = incident_write(
            "POST",
            "/incidents",
            payload,
            params={
                "dateFormat": "iso8601",
                "fields": INCIDENT_FIELDS,
            },
        )
    except TopdeskApiError as error:
        if error.status_code == 400:
            return {
                "status": "invalid_assignment_or_classification",
                "httpStatus": 400,
                "message": (
                    "TOPdesk afviste kombinationen. Kontrollér at "
                    "underkategorien tilhører kategorien, og at den "
                    "ansvarlige tilhører den valgte operatørgruppe."
                ),
                "topdeskResponse": error.response_text,
            }
        raise

    return {
        "status": "created",
        "incident": transform_incident(data),
    }


@mcp.tool()
def update_incident_by_number(
    number: str,
    action_text: str = "",
    request_text: str = "",
    brief_description: str = "",
    category_id: str = "",
    subcategory_id: str = "",
    operator_group_id: str = "",
    operator_id: str = "",
    priority_id: str = "",
    confirmed: bool = False,
) -> dict[str, Any]:
    """Update selected incident fields after explicit confirmation."""
    number = number.strip()
    if not number:
        raise ValueError("number must not be empty")

    payload: dict[str, Any] = {}
    if action_text.strip():
        payload["action"] = action_text.strip()
    if request_text.strip():
        payload["request"] = request_text.strip()
    if brief_description.strip():
        if len(brief_description.strip()) > 80:
            raise ValueError("brief_description must be 80 characters or fewer")
        payload["briefDescription"] = brief_description.strip()

    for field_name, reference_id in {
        "category": category_id,
        "subcategory": subcategory_id,
        "operatorGroup": operator_group_id,
        "operator": operator_id,
        "priority": priority_id,
    }.items():
        if reference_id.strip():
            payload[field_name] = {"id": reference_id.strip()}

    if not payload:
        raise ValueError("At least one update field must be provided")

    if not confirmed:
        return {
            "status": "confirmation_required",
            "incidentNumber": number,
            "proposedChanges": payload,
        }

    data = incident_write(
        "PATCH",
        f"/incidents/number/{quote(number, safe='')}",
        payload,
        params={
            "dateFormat": "iso8601",
            "fields": INCIDENT_FIELDS,
        },
    )
    return {
        "status": "updated",
        "incident": transform_incident(data),
    }


@mcp.tool()
def incident_wizard_start(
    problem: str,
    caller_query: str = "",
    knowledge_limit: int = 3,
    incident_limit: int = 3,
) -> dict[str, Any]:
    """Start Incident Wizard V1 without changing TOPdesk data."""
    problem = problem.strip()
    if not problem:
        return {
            "status": "needs_input",
            "step": "problem",
            "question": "Beskriv kort problemet.",
        }

    caller_candidates = (
        find_callers(caller_query, 10)
        if caller_query.strip()
        else {
            "status": "needs_input",
            "question": "Gælder sagen dig selv eller en kollega?",
            "callers": [],
        }
    )

    return {
        "status": "wizard_started",
        "step": "review_existing_help",
        "defaultIncidentLine": "secondLine",
        "defaultEntryType": DEFAULT_ENTRY_TYPE_NAME,
        "problem": problem,
        "knowledge": search_knowledge(
            problem,
            max(1, min(knowledge_limit, 5)),
        ),
        "similarIncidents": search_incidents(
            problem,
            max(1, min(incident_limit, 5)),
            INCIDENT_SCAN_LIMIT,
        ),
        "callerCandidates": caller_candidates,
        "choices": {
            "categories": format_user_choices(
                get_metadata("/incidents/categories")
            ),
            "operatorGroups": format_user_choices(
                get_metadata("/incidents/operatorgroups/lookup")
            ),
        },
        "selectionInstructions": {
            "category": (
                "Vis alle kategorier som '(Nummer) Navn (ID: UUID)' og bed "
                "brugeren vælge en af de viste muligheder."
            ),
            "subcategory": (
                "Når kategorien er valgt, kald "
                "incident_wizard_get_subcategories med kategoriens ID, vis "
                "alle underkategorier som '(Nummer) Navn (ID: UUID)', og bed "
                "brugeren vælge en af de viste muligheder."
            ),
            "operatorGroup": (
                "Vis alle operatørgrupper som '(Nummer) Navn (ID: UUID)' og "
                "bed brugeren vælge en af de viste muligheder."
            ),
            "operator": (
                "Når operatørgruppen er valgt, kald "
                "incident_wizard_get_assignment_choices med gruppens ID, vis "
                "alle operatører som '(Nummer) Navn (ID: UUID)', og bed "
                "brugeren vælge en af de viste muligheder."
            ),
            "neverAskForUnknownId": (
                "Bed aldrig brugeren skrive et ukendt TOPdesk-ID uden først "
                "at vise de tilgængelige navne og ID'er."
            ),
        },
        "requiredSequence": [
            "caller",
            "category",
            "subcategory",
            "operatorGroup",
            "operator",
            "preview",
            "confirmation",
        ],
        "nextQuestion": (
            "Vis højst tre relevante hjælpeforslag og spørg, om brugeren "
            "stadig ønsker at oprette en Second Line-sag."
        ),
    }


@mcp.tool()
def incident_wizard_get_subcategories(
    category_id: str,
) -> dict[str, Any]:
    """Get only the undercategories belonging to the selected category."""
    return list_incident_subcategories(category_id=category_id)


@mcp.tool()
def incident_wizard_get_assignment_choices(
    operator_group_id: str,
    operator_query: str = "",
) -> dict[str, Any]:
    """
    Return the selected group and operator candidates.

    TOPdesk performs the final membership validation at creation time.
    """
    operator_group_id = operator_group_id.strip()
    if not operator_group_id:
        groups = format_user_choices(
            get_metadata("/incidents/operatorgroups/lookup")
        )
        return {
            "status": "needs_input",
            "step": "operator_group",
            "message": (
                "Vælg først en operatørgruppe fra listen. Angiv nummer, navn eller ID."
            ),
            "operatorGroups": groups,
            "displayFormat": "(Nummer) Navn (ID: UUID)",
        }

    group = incident_get(
        f"/incidents/operatorgroups/lookup/"
        f"{quote(operator_group_id, safe='')}"
    )
    operators = find_operators(
        query=operator_query,
        limit=100,
    )
    return {
        "status": "ok",
        "operatorGroup": group,
        "operators": operators.get("operators", []),
        "message": (
            "Vælg en ansvarlig operatør fra listen ved at angive nummer, "
            "navn eller ID. TOPdesk validerer ved oprettelsen, at den "
            "ansvarlige tilhører den valgte gruppe."
        ),
        "displayFormat": "(Nummer) Navn (ID: UUID)",
    }


@mcp.tool()
def incident_wizard_preview(
    brief_description: str,
    caller_id: str,
    request_text: str,
    category_id: str,
    subcategory_id: str,
    operator_group_id: str,
    operator_id: str,
    call_type_id: str = "",
    impact_id: str = "",
    urgency_id: str = "",
    priority_id: str = "",
) -> dict[str, Any]:
    """Validate and preview a complete Second Line wizard draft."""
    missing = required_wizard_fields(
        brief_description,
        caller_id,
        request_text,
        category_id,
        subcategory_id,
        operator_group_id,
        operator_id,
    )
    if missing:
        return {
            "status": "needs_input",
            "step": "incident_details",
            "missingFields": missing,
            "message": (
                "Kategori, underkategori, operatørgruppe og ansvarlig "
                "skal vælges før preview."
            ),
        }

    if len(brief_description.strip()) > 80:
        return {
            "status": "needs_input",
            "message": "Titlen må højst indeholde 80 tegn.",
        }

    relationship = validate_category_subcategory(
        category_id.strip(),
        subcategory_id.strip(),
    )
    if not relationship.get("valid"):
        return {
            "status": "invalid_classification",
            "message": relationship.get("message"),
        }

    payload = build_second_line_payload(
        brief_description=brief_description,
        caller_id=caller_id,
        request_text=request_text,
        category_id=category_id,
        subcategory_id=subcategory_id,
        operator_group_id=operator_group_id,
        operator_id=operator_id,
        call_type_id=call_type_id,
        impact_id=impact_id,
        urgency_id=urgency_id,
        priority_id=priority_id,
    )

    return {
        "status": "confirmation_required",
        "step": "confirm",
        "incidentLine": "secondLine",
        "caller": get_caller(caller_id.strip()),
        "category": next(
            (
                item
                for item in get_metadata("/incidents/categories")
                if item.get("id") == category_id.strip()
            ),
            {"id": category_id.strip()},
        ),
        "subcategory": next(
            (
                item
                for item in get_metadata("/incidents/subcategories")
                if item.get("id") == subcategory_id.strip()
            ),
            {"id": subcategory_id.strip()},
        ),
        "operatorGroup": incident_get(
            f"/incidents/operatorgroups/lookup/"
            f"{quote(operator_group_id.strip(), safe='')}"
        ),
        "operator": get_operator(operator_id.strip()),
        "proposedIncident": payload,
        "allowedAnswers": [
            "Ja, opret sagen",
            "Rediger kategori",
            "Rediger underkategori",
            "Rediger gruppe",
            "Rediger ansvarlig",
            "Annuller",
        ],
    }


@mcp.tool()
def incident_wizard_submit(
    brief_description: str,
    caller_id: str,
    request_text: str,
    category_id: str,
    subcategory_id: str,
    operator_group_id: str,
    operator_id: str,
    call_type_id: str = "",
    impact_id: str = "",
    urgency_id: str = "",
    priority_id: str = "",
    confirmed: bool = False,
) -> dict[str, Any]:
    """Submit the complete wizard draft as a Second Line incident."""
    if not confirmed:
        return {
            "status": "confirmation_required",
            "message": "Brugeren skal eksplicit bekræfte oprettelsen.",
        }

    result = create_incident(
        brief_description=brief_description,
        caller_id=caller_id,
        request_text=request_text,
        category_id=category_id,
        subcategory_id=subcategory_id,
        operator_group_id=operator_group_id,
        operator_id=operator_id,
        call_type_id=call_type_id,
        impact_id=impact_id,
        urgency_id=urgency_id,
        priority_id=priority_id,
        confirmed=True,
    )
    if result.get("status") == "created":
        result["wizardStatus"] = "completed"
        result["incidentLine"] = "secondLine"
    return result


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port,
        streamable_http_path="/mcp",
    )
