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

mcp = MCPServer("TOPdesk MCP Read Only")

TOPDESK_USER = os.getenv("TOPDESK_USER", "").strip()
TOPDESK_TOKEN = os.getenv("TOPDESK_TOKEN", "").strip()
TOPDESK_HOST = os.getenv(
    "TOPDESK_HOST",
    "https://saether.topdesk.net",
).rstrip("/")

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
KNOWLEDGE_PAGE_SIZE = int(os.getenv("KNOWLEDGE_PAGE_SIZE", "100"))
INCIDENT_SCAN_LIMIT = int(os.getenv("INCIDENT_SCAN_LIMIT", "250"))
RESERVATION_SCAN_LIMIT = int(os.getenv("RESERVATION_SCAN_LIMIT", "250"))
ASSET_PAGE_SIZE = int(os.getenv("ASSET_PAGE_SIZE", "100"))

KNOWLEDGE_BASE_URL = f"{TOPDESK_HOST}/services/knowledge-base-v1"
GENERAL_API_URL = f"{TOPDESK_HOST}/tas/api"
ASSET_API_URL = f"{TOPDESK_HOST}/tas/api/assetmgmt"

KNOWLEDGE_FIELDS = (
    "title,description,content,keywords,urls,modificationDate,"
    "availableTranslations"
)

INCIDENT_FIELDS = (
    "id,number,briefDescription,request,action,creationDate,modificationDate,"
    "targetDate,closedDate,status,caller,operator,operatorGroup,category,"
    "subcategory,callType,priority,urgency,impact,branch,location,object"
)

SEARCH_SYNONYMS = {
    "booking": ["reservation", "reservere", "booke"],
    "reservation": ["booking", "reservere", "booke"],
    "reservere": ["reservation", "booking", "booke"],
    "booke": ["booking", "reservation", "reservere"],
    "mødelokale": ["lokale", "meeting room", "møderum"],
    "lokale": ["mødelokale", "møderum", "meeting room"],
    "arbejdsplads": ["desk", "skrivebord", "workplace"],
    "parkering": ["parkeringsplads", "parking"],
    "annullere": ["afbestille", "cancel", "cancellation"],
    "support": ["helpdesk", "it-support", "kundeservice"],
    "eskalere": ["escalation", "second line", "2nd line"],
    "computer": ["pc", "laptop", "arbejdsstation"],
    "telefon": ["mobil", "smartphone", "phone"],
}


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


def expand_query_terms(query: str) -> list[str]:
    terms = tokenize(query)
    expanded = set(terms)
    for term in terms:
        for synonym in SEARCH_SYNONYMS.get(term, []):
            expanded.update(tokenize(synonym))
    return sorted(expanded)


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


def api_get(
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
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        raise TopdeskApiError(
            f"TOPdesk returned HTTP {response.status_code} for {path}.",
            response.status_code,
            response.text[:1000],
        ) from exc
    if response.status_code == 204 or not response.content:
        return []
    return response.json()


def knowledge_get(path: str, params: dict[str, Any] | None = None) -> Any:
    return api_get(
        KNOWLEDGE_BASE_URL,
        path,
        params=params,
        accept=(
            "application/x.topdesk-kb-ki-list-v1+json, "
            "application/x.topdesk-kb-ki-v1+json, application/json"
        ),
    )


def general_get(path: str, params: dict[str, Any] | None = None) -> Any:
    return api_get(GENERAL_API_URL, path, params=params)


def asset_get(path: str, params: dict[str, Any] | None = None) -> Any:
    return api_get(ASSET_API_URL, path, params=params)


def extract_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in (
            "item", "items", "results", "data", "reservations", "assets",
            "reservableAssets", "reservableLocations", "reservableServices",
            "values", "templates", "branches", "persons",
        ):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def safe_read(
    capability: str,
    reader: Any,
    path: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        data = reader(path, params=params)
        return {
            "status": "ok",
            "capability": capability,
            "source": "TOPdesk",
            "data": data,
        }
    except TopdeskApiError as error:
        if error.status_code in (401, 403):
            return {
                "status": "permission_required",
                "capability": capability,
                "httpStatus": error.status_code,
                "message": (
                    "The configured TOPdesk API account does not have read "
                    "access to this capability."
                ),
            }
        if error.status_code == 404:
            return {
                "status": "not_available",
                "capability": capability,
                "httpStatus": 404,
                "message": (
                    "This endpoint is not available in the connected TOPdesk "
                    "environment or the requested record does not exist."
                ),
            }
        return {
            "status": "api_error",
            "capability": capability,
            "httpStatus": error.status_code,
            "message": str(error),
        }


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
        "status", "caller", "operator", "operatorGroup", "category",
        "subcategory", "callType", "priority", "urgency", "impact",
        "branch", "location", "object",
    ):
        result[name] = scalar(item.get(name))
    return result


def transform_reservation(item: dict[str, Any]) -> dict[str, Any]:
    facilities = item.get("reservedFacilities") or item.get("facilities") or []
    return {
        "id": str(item.get("id") or ""),
        "number": str(item.get("number") or ""),
        "name": clean_html(
            item.get("name") or item.get("briefDescription")
            or item.get("description") or item.get("title") or ""
        ),
        "description": clean_html(item.get("description") or ""),
        "startDate": str(
            item.get("startDate") or item.get("startDateTime")
            or item.get("start") or ""
        ),
        "endDate": str(
            item.get("endDate") or item.get("endDateTime")
            or item.get("end") or ""
        ),
        "status": scalar(item.get("status")),
        "requester": scalar(
            item.get("requester") or item.get("person") or item.get("caller")
        ),
        "location": scalar(
            item.get("location") or item.get("reservableLocation")
        ),
        "asset": scalar(item.get("asset") or item.get("reservableAsset")),
        "facilities": (
            [scalar(value) for value in facilities]
            if isinstance(facilities, list) else []
        ),
    }


def transform_asset(item: dict[str, Any]) -> dict[str, Any]:
    fields = item.get("fields") or item.get("data") or {}
    return {
        "id": str(item.get("id") or item.get("unid") or ""),
        "name": clean_html(
            item.get("name") or item.get("text") or item.get("title") or ""
        ),
        "type": scalar(
            item.get("type") or item.get("resourceCategory")
            or item.get("template")
        ),
        "status": scalar(item.get("status") or fields.get("status")),
        "serialNumber": scalar(
            item.get("serialNumber") or fields.get("serialNumber")
        ),
        "location": scalar(item.get("location") or fields.get("location")),
        "owner": scalar(
            item.get("owner") or item.get("person") or fields.get("owner")
        ),
        "raw": item,
    }


def weighted_score(
    item: dict[str, Any],
    terms: list[str],
    fields: tuple[tuple[str, int], ...],
) -> int:
    total = 0
    for field_name, weight in fields:
        value = item.get(field_name, "")
        if isinstance(value, list):
            text = " ".join(str(v) for v in value).lower()
        else:
            text = str(value or "").lower()
        total += sum(weight for term in terms if term in text)
    return total


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


def no_results(source: str, query: str) -> dict[str, Any]:
    return {
        "status": "no_results",
        "source": source,
        "query": query,
        "count": 0,
        "message": (
            "TOPdesk returned no matching data. Do not invent a procedure or "
            "record; explain that no documented result was found."
        ),
    }


# 1
@mcp.tool()
def health() -> dict[str, Any]:
    """Check configuration and expose the read-only nature of this server."""
    missing = []
    if not TOPDESK_USER:
        missing.append("TOPDESK_USER")
    if not TOPDESK_TOKEN:
        missing.append("TOPDESK_TOKEN")
    return {
        "status": "ok" if not missing else "configuration_error",
        "mode": "read_only",
        "missingVariables": missing,
        "topdeskHost": TOPDESK_HOST,
    }


# 2
@mcp.tool()
def list_capabilities() -> dict[str, Any]:
    """List the read-only MCP capabilities exposed by this server."""
    return {
        "status": "ok",
        "mode": "read_only",
        "capabilities": [
            "search_knowledge", "get_knowledge_item", "list_knowledge_items",
            "search_everything", "list_recent_incidents", "search_incidents",
            "get_incident_by_id", "get_incident_by_number",
            "get_incident_time_spent_by_id", "get_incident_time_spent_by_number",
            "list_incident_statuses", "list_incident_categories",
            "list_incident_subcategories", "list_incident_priorities",
            "list_incident_urgencies", "list_incident_impacts",
            "list_incident_call_types", "list_incident_entry_types",
            "list_incident_closure_codes", "list_operator_groups",
            "list_operators", "list_sla_services", "list_services",
            "find_callers", "get_caller", "list_reservations",
            "search_reservations", "get_reservation",
            "list_reservable_locations", "get_reservable_location",
            "get_location_availability", "list_reservable_assets",
            "get_reservable_asset_availability", "list_reservable_services",
            "get_reservable_service", "list_assets", "search_assets",
            "get_asset", "get_asset_current_items",
        ],
    }


# 3
@mcp.tool()
def search_knowledge(query: str, limit: int = 7) -> dict[str, Any]:
    """Search TOPdesk Knowledge Base with Danish and English synonyms."""
    query = query.strip()
    limit = max(1, min(limit, 10))
    if not query:
        raise ValueError("query must not be empty")
    terms = expand_query_terms(query)
    items = [transform_knowledge_item(x) for x in get_all_knowledge_items()]
    results = []
    for item in items:
        score = weighted_score(
            item,
            terms,
            (
                ("number", 100), ("title", 25), ("keywords", 20),
                ("description", 12), ("content", 8),
            ),
        )
        if score > 0:
            enriched = dict(item)
            enriched["relevanceScore"] = score
            results.append(enriched)
    results.sort(
        key=lambda x: (x.get("relevanceScore", 0), x.get("modificationDate", "")),
        reverse=True,
    )
    selected = results[:limit]
    if not selected:
        return no_results("TOPdesk Knowledge Base", query)
    return {
        "status": "ok", "source": "TOPdesk Knowledge Base", "query": query,
        "expandedTerms": terms, "count": len(selected), "references": selected,
    }


# 4
@mcp.tool()
def get_knowledge_item(identifier: str) -> dict[str, Any]:
    """Get a Knowledge Item by KI number or UUID."""
    identifier = identifier.strip()
    if not identifier:
        raise ValueError("identifier must not be empty")
    if is_uuid(identifier):
        try:
            data = knowledge_get(
                f"/knowledgeItems/{quote(identifier, safe='')}",
                params={"fields": KNOWLEDGE_FIELDS},
            )
            return {"status": "ok", "item": transform_knowledge_item(data)}
        except TopdeskApiError as error:
            return {
                "status": "not_found" if error.status_code == 404 else "api_error",
                "message": str(error),
            }
    expected_number = normalize_ki_number(identifier)
    match = next(
        (
            item for item in get_all_knowledge_items()
            if str(item.get("number") or "").strip().upper() == expected_number
        ),
        None,
    )
    if not match:
        return no_results("TOPdesk Knowledge Base", expected_number)
    item_id = str(match.get("id") or "").strip()
    if not item_id:
        return {"status": "data_error", "message": "Knowledge Item has no UUID."}
    data = knowledge_get(
        f"/knowledgeItems/{quote(item_id, safe='')}",
        params={"fields": KNOWLEDGE_FIELDS},
    )
    item = transform_knowledge_item(data)
    if not item.get("number"):
        item["number"] = expected_number
    return {"status": "ok", "source": "TOPdesk Knowledge Base", "item": item}


# 5
@mcp.tool()
def list_knowledge_items(limit: int = 20) -> dict[str, Any]:
    """List recent Knowledge Base items using modification date."""
    limit = max(1, min(limit, 100))
    items = [transform_knowledge_item(x) for x in get_all_knowledge_items()]
    items.sort(key=lambda x: x.get("modificationDate", ""), reverse=True)
    return {"status": "ok", "count": min(len(items), limit), "items": items[:limit]}


# 6
@mcp.tool()
def list_recent_incidents(limit: int = 10, start: int = 0) -> dict[str, Any]:
    """List the newest accessible TOPdesk incidents."""
    limit = max(1, min(limit, 100))
    data = general_get(
        "/incidents",
        params={
            "pageStart": max(0, start), "pageSize": limit,
            "sort": "creationDate:desc", "dateFormat": "iso8601",
            "fields": INCIDENT_FIELDS,
        },
    )
    incidents = [transform_incident(x) for x in extract_list(data)]
    return {"status": "ok", "count": len(incidents), "incidents": incidents}


# 7
@mcp.tool()
def search_incidents(
    query: str,
    limit: int = 7,
    scan: int = INCIDENT_SCAN_LIMIT,
) -> dict[str, Any]:
    """Search accessible recent incidents locally across relevant fields."""
    query = query.strip()
    if not query:
        raise ValueError("query must not be empty")
    limit = max(1, min(limit, 25))
    scan = max(25, min(scan, 1000))
    data = general_get(
        "/incidents",
        params={
            "pageStart": 0, "pageSize": scan, "sort": "creationDate:desc",
            "dateFormat": "iso8601", "fields": INCIDENT_FIELDS,
        },
    )
    terms = expand_query_terms(query)
    results = []
    for raw in extract_list(data):
        item = transform_incident(raw)
        score = weighted_score(
            item,
            terms,
            (
                ("number", 100), ("briefDescription", 30), ("request", 20),
                ("action", 12), ("category", 10), ("subcategory", 10),
                ("status", 8), ("caller", 6), ("operator", 6),
                ("operatorGroup", 6),
            ),
        )
        if score > 0:
            item["relevanceScore"] = score
            results.append(item)
    results.sort(
        key=lambda x: (x.get("relevanceScore", 0), x.get("creationDate", "")),
        reverse=True,
    )
    selected = results[:limit]
    if not selected:
        return no_results("TOPdesk Incidents", query)
    return {"status": "ok", "query": query, "count": len(selected), "incidents": selected}


# 8
@mcp.tool()
def get_incident_by_id(incident_id: str) -> dict[str, Any]:
    """Get a TOPdesk incident by UUID."""
    result = safe_read(
        "get_incident_by_id", general_get,
        f"/incidents/id/{quote(incident_id.strip(), safe='')}",
        {"dateFormat": "iso8601"},
    )
    if result["status"] == "ok":
        result["incident"] = transform_incident(result.pop("data"))
    return result


# 9
@mcp.tool()
def get_incident_by_number(number: str) -> dict[str, Any]:
    """Get a TOPdesk incident by complete incident number."""
    result = safe_read(
        "get_incident_by_number", general_get,
        f"/incidents/number/{quote(number.strip(), safe='')}",
        {"dateFormat": "iso8601"},
    )
    if result["status"] == "ok":
        result["incident"] = transform_incident(result.pop("data"))
    return result


# 10
@mcp.tool()
def get_incident_time_spent_by_id(incident_id: str) -> dict[str, Any]:
    """Retrieve time registrations for an incident UUID."""
    return safe_read(
        "get_incident_time_spent_by_id", general_get,
        f"/incidents/id/{quote(incident_id.strip(), safe='')}/timespent",
    )


# 11
@mcp.tool()
def get_incident_time_spent_by_number(number: str) -> dict[str, Any]:
    """Retrieve time registrations for an incident number."""
    return safe_read(
        "get_incident_time_spent_by_number", general_get,
        f"/incidents/number/{quote(number.strip(), safe='')}/timespent",
    )


def metadata_tool(capability: str, path: str) -> dict[str, Any]:
    result = safe_read(capability, general_get, path)
    if result["status"] == "ok":
        result["items"] = extract_list(result.pop("data"))
        result["count"] = len(result["items"])
    return result


# 12
@mcp.tool()
def list_incident_statuses() -> dict[str, Any]:
    """List configured incident processing statuses."""
    return metadata_tool("list_incident_statuses", "/incidents/statuses")


# 13
@mcp.tool()
def list_incident_categories() -> dict[str, Any]:
    """List configured incident categories."""
    return metadata_tool("list_incident_categories", "/incidents/categories")


# 14
@mcp.tool()
def list_incident_subcategories() -> dict[str, Any]:
    """List configured incident subcategories."""
    return metadata_tool("list_incident_subcategories", "/incidents/subcategories")


# 15
@mcp.tool()
def list_incident_priorities() -> dict[str, Any]:
    """List configured incident priorities."""
    return metadata_tool("list_incident_priorities", "/incidents/priorities")


# 16
@mcp.tool()
def list_incident_urgencies() -> dict[str, Any]:
    """List configured incident urgencies."""
    return metadata_tool("list_incident_urgencies", "/incidents/urgencies")


# 17
@mcp.tool()
def list_incident_impacts() -> dict[str, Any]:
    """List configured incident impacts."""
    return metadata_tool("list_incident_impacts", "/incidents/impacts")


# 18
@mcp.tool()
def list_incident_call_types() -> dict[str, Any]:
    """List configured incident call types."""
    return metadata_tool("list_incident_call_types", "/incidents/call_types")


# 19
@mcp.tool()
def list_incident_entry_types() -> dict[str, Any]:
    """List configured incident entry types."""
    return metadata_tool("list_incident_entry_types", "/incidents/entry_types")


# 20
@mcp.tool()
def list_incident_closure_codes() -> dict[str, Any]:
    """List configured incident closure codes."""
    return metadata_tool("list_incident_closure_codes", "/incidents/closure_codes")


# 21
@mcp.tool()
def list_operator_groups() -> dict[str, Any]:
    """List TOPdesk operator groups available to the API account."""
    return metadata_tool("list_operator_groups", "/incidents/operatorgroups/lookup")


# 22
@mcp.tool()
def list_operators() -> dict[str, Any]:
    """List TOPdesk operators available to the API account."""
    return metadata_tool("list_operators", "/incidents/operators/lookup")


# 23
@mcp.tool()
def list_sla_services() -> dict[str, Any]:
    """List configured incident SLA services."""
    return metadata_tool("list_sla_services", "/incidents/slas")


# 24
@mcp.tool()
def list_services() -> dict[str, Any]:
    """List configured services connected to incident SLAs."""
    return metadata_tool("list_services", "/incidents/slas/services")


# 25
@mcp.tool()
def find_callers(query: str, limit: int = 20) -> dict[str, Any]:
    """Search TOPdesk callers/persons visible to the API account."""
    query = query.strip().lower()
    limit = max(1, min(limit, 100))
    result = safe_read(
        "find_callers", general_get, "/incidents/callers/lookup",
        {"pageStart": 0, "pageSize": 1000},
    )
    if result["status"] != "ok":
        return result
    callers = extract_list(result.pop("data"))
    selected = []
    for caller in callers:
        text = " ".join(str(v) for v in caller.values()).lower()
        if not query or query in text:
            selected.append(caller)
        if len(selected) >= limit:
            break
    return {"status": "ok", "query": query, "count": len(selected), "callers": selected}


# 26
@mcp.tool()
def get_caller(caller_id: str) -> dict[str, Any]:
    """Get a TOPdesk caller/person by UUID."""
    return safe_read(
        "get_caller", general_get,
        f"/incidents/callers/lookup/{quote(caller_id.strip(), safe='')}",
    )


# 27
@mcp.tool()
def list_reservations(limit: int = 20, start: int = 0) -> dict[str, Any]:
    """List reservations visible to the configured API account."""
    result = safe_read(
        "list_reservations", general_get, "/reservations",
        {"pageStart": max(0, start), "pageSize": max(1, min(limit, 100))},
    )
    if result["status"] == "ok":
        reservations = [transform_reservation(x) for x in extract_list(result.pop("data"))]
        result.update({"count": len(reservations), "reservations": reservations})
    return result


# 28
@mcp.tool()
def search_reservations(
    query: str,
    limit: int = 10,
    scan: int = RESERVATION_SCAN_LIMIT,
) -> dict[str, Any]:
    """Search reservations visible to the configured API account."""
    query = query.strip()
    result = safe_read(
        "search_reservations", general_get, "/reservations",
        {"pageStart": 0, "pageSize": max(25, min(scan, 1000))},
    )
    if result["status"] != "ok":
        return result
    terms = expand_query_terms(query)
    candidates = []
    for raw in extract_list(result.pop("data")):
        item = transform_reservation(raw)
        score = weighted_score(
            item, terms,
            (
                ("number", 100), ("name", 30), ("description", 20),
                ("location", 15), ("asset", 15), ("status", 8),
                ("facilities", 12),
            ),
        )
        if score > 0:
            item["relevanceScore"] = score
            candidates.append(item)
    candidates.sort(
        key=lambda x: (x.get("relevanceScore", 0), x.get("startDate", "")),
        reverse=True,
    )
    selected = candidates[:max(1, min(limit, 25))]
    if not selected:
        return no_results("TOPdesk Reservations", query)
    return {"status": "ok", "query": query, "count": len(selected), "reservations": selected}


# 29
@mcp.tool()
def get_reservation(identifier: str) -> dict[str, Any]:
    """Get one reservation by UUID or reservation number."""
    result = safe_read(
        "get_reservation", general_get,
        f"/reservations/{quote(identifier.strip(), safe='')}",
    )
    if result["status"] == "ok":
        result["reservation"] = transform_reservation(result.pop("data"))
    return result


# 30
@mcp.tool()
def list_reservable_locations(limit: int = 100) -> dict[str, Any]:
    """List reservable TOPdesk locations, such as rooms and workspaces."""
    result = safe_read(
        "list_reservable_locations", general_get, "/reservableLocations",
        {"pageSize": max(1, min(limit, 500))},
    )
    if result["status"] == "ok":
        result["locations"] = extract_list(result.pop("data"))
        result["count"] = len(result["locations"])
    return result


# 31
@mcp.tool()
def get_reservable_location(location_id: str) -> dict[str, Any]:
    """Get a reservable TOPdesk location by UUID."""
    return safe_read(
        "get_reservable_location", general_get,
        f"/reservableLocations/{quote(location_id.strip(), safe='')}",
    )


# 32
@mcp.tool()
def get_location_availability(
    location_id: str,
    start_date: str,
    end_date: str,
) -> dict[str, Any]:
    """Get the reservable interval for a TOPdesk location."""
    return safe_read(
        "get_location_availability", general_get,
        f"/reservableLocations/{quote(location_id.strip(), safe='')}/reservableInterval",
        {"startDate": start_date, "endDate": end_date},
    )


# 33
@mcp.tool()
def list_reservable_assets(limit: int = 100) -> dict[str, Any]:
    """List assets that can be reserved in TOPdesk."""
    result = safe_read(
        "list_reservable_assets", general_get, "/reservableAssets",
        {"pageSize": max(1, min(limit, 500))},
    )
    if result["status"] == "ok":
        result["assets"] = extract_list(result.pop("data"))
        result["count"] = len(result["assets"])
    return result


# 34
@mcp.tool()
def get_reservable_asset_availability(
    asset_id: str,
    start_date: str,
    end_date: str,
) -> dict[str, Any]:
    """Get the reservable interval for a reservable asset."""
    return safe_read(
        "get_reservable_asset_availability", general_get,
        f"/reservableAssets/{quote(asset_id.strip(), safe='')}/reservableInterval",
        {"startDate": start_date, "endDate": end_date},
    )


# 35
@mcp.tool()
def list_reservable_services(limit: int = 100) -> dict[str, Any]:
    """List reservable services available in TOPdesk."""
    result = safe_read(
        "list_reservable_services", general_get, "/reservableServices",
        {"pageSize": max(1, min(limit, 500))},
    )
    if result["status"] == "ok":
        result["services"] = extract_list(result.pop("data"))
        result["count"] = len(result["services"])
    return result


# 36
@mcp.tool()
def get_reservable_service(service_id: str) -> dict[str, Any]:
    """Get a reservable service by UUID."""
    return safe_read(
        "get_reservable_service", general_get,
        f"/reservableServices/{quote(service_id.strip(), safe='')}",
    )


# 37
@mcp.tool()
def list_assets(limit: int = 50, page_start: int = 0) -> dict[str, Any]:
    """List Asset Management resources visible to the API account."""
    result = safe_read(
        "list_assets", asset_get, "/assets",
        {"page_size": max(1, min(limit, 100)), "page_start": max(0, page_start)},
    )
    if result["status"] == "ok":
        assets = [transform_asset(x) for x in extract_list(result.pop("data"))]
        result.update({"count": len(assets), "assets": assets})
    return result


# 38
@mcp.tool()
def search_assets(query: str, limit: int = 20, scan: int = 200) -> dict[str, Any]:
    """Search Asset Management resources visible to the API account."""
    query = query.strip()
    result = safe_read(
        "search_assets", asset_get, "/assets",
        {"page_size": max(25, min(scan, 500)), "page_start": 0},
    )
    if result["status"] != "ok":
        return result
    terms = expand_query_terms(query)
    candidates = []
    for raw in extract_list(result.pop("data")):
        item = transform_asset(raw)
        score = weighted_score(
            item, terms,
            (
                ("id", 100), ("name", 30), ("serialNumber", 25),
                ("type", 15), ("location", 12), ("owner", 12), ("status", 8),
            ),
        )
        if score > 0:
            item["relevanceScore"] = score
            candidates.append(item)
    candidates.sort(key=lambda x: x.get("relevanceScore", 0), reverse=True)
    selected = candidates[:max(1, min(limit, 100))]
    if not selected:
        return no_results("TOPdesk Assets", query)
    return {"status": "ok", "query": query, "count": len(selected), "assets": selected}


# 39
@mcp.tool()
def get_asset(asset_id: str) -> dict[str, Any]:
    """Get one Asset Management resource by asset UUID."""
    result = safe_read(
        "get_asset", asset_get,
        f"/assets/{quote(asset_id.strip(), safe='')}",
    )
    if result["status"] == "ok":
        result["asset"] = transform_asset(result.pop("data"))
    return result


# 40
@mcp.tool()
def get_asset_current_items(asset_id: str) -> dict[str, Any]:
    """Get current history items and external links for an asset."""
    return safe_read(
        "get_asset_current_items", asset_get,
        f"/assets/{quote(asset_id.strip(), safe='')}/history/currentItems",
    )


# 41
@mcp.tool()
def search_everything(
    query: str,
    knowledge_limit: int = 5,
    incident_limit: int = 5,
    asset_limit: int = 5,
) -> dict[str, Any]:
    """Search Knowledge Base, incidents and assets with one read-only request."""
    return {
        "status": "ok",
        "query": query,
        "knowledge": search_knowledge(query, knowledge_limit),
        "incidents": search_incidents(query, incident_limit),
        "assets": search_assets(query, asset_limit),
        "instruction": "Use only evidence returned by TOPdesk.",
    }


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port,
        streamable_http_path="/mcp",
    )
