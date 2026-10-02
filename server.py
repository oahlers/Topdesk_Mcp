from __future__ import annotations

import html
import os
import re
import time
from datetime import datetime
from typing import Any
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
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
INCIDENT_CACHE_TTL_SECONDS = int(
    os.getenv("INCIDENT_CACHE_TTL_SECONDS", "600")
)
INCIDENT_CACHE_PAGE_SIZE = int(
    os.getenv("INCIDENT_CACHE_PAGE_SIZE", "2000")
)
LOOKUP_CACHE_TTL_SECONDS = int(
    os.getenv("LOOKUP_CACHE_TTL_SECONDS", "3600")
)
HTTP_POOL_CONNECTIONS = int(os.getenv("HTTP_POOL_CONNECTIONS", "10"))
HTTP_POOL_MAXSIZE = int(os.getenv("HTTP_POOL_MAXSIZE", "20"))

HTTP_SESSION = requests.Session()
HTTP_ADAPTER = HTTPAdapter(
    pool_connections=max(1, HTTP_POOL_CONNECTIONS),
    pool_maxsize=max(1, HTTP_POOL_MAXSIZE),
    pool_block=True,
)
HTTP_SESSION.mount("https://", HTTP_ADAPTER)
HTTP_SESSION.mount("http://", HTTP_ADAPTER)

_LOOKUP_CACHE: dict[str, list[dict[str, Any]]] = {}
_LOOKUP_CACHE_LOADED_AT: dict[str, float] = {}
_INCIDENT_CACHE: list[dict[str, Any]] = []
_INCIDENT_CACHE_LOADED_AT = 0.0
_REQUESTER_INDEX: dict[str, list[dict[str, Any]]] = {}
_OPERATOR_INDEX: dict[str, list[dict[str, Any]]] = {}
_CATEGORY_INDEX: dict[str, list[dict[str, Any]]] = {}
_SUBCATEGORY_INDEX: dict[str, list[dict[str, Any]]] = {}
_INCIDENT_NUMBER_INDEX: dict[str, dict[str, Any]] = {}
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
    "targetDate,closedDate,status,caller,operator,operatorGroup,category,externalNumber,"
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
            or value.get("dynamicName")
            or value.get("displayName")
            or value.get("value")
            or value.get("number")
            or value.get("id")
            or ""
        )
    return str(value or "")


def normalize_incident_number(number: str) -> str:
    value = re.sub(r"\s+", " ", str(number or "").strip()).upper()
    if re.fullmatch(r"\d{4}-\d{3}", value):
        return f"S {value}"
    match = re.fullmatch(r"S\s*(\d{4}-\d{3})", value)
    return f"S {match.group(1)}" if match else value


def incident_number_variants(number: str) -> list[str]:
    normalized = normalize_incident_number(number)
    variants = [normalized]
    if normalized.startswith("S "):
        variants.extend([normalized.replace("S ", "S", 1), normalized[2:]])
    return list(dict.fromkeys(value for value in variants if value))


def fiql_escape(value: str) -> str:
    return quote(str(value or "").strip(), safe="-_.~@")


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

    response = HTTP_SESSION.request(
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
        "externalNumber": str(item.get("externalNumber") or ""),
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


def clear_lookup_cache(cache_key: str = "") -> None:
    """Clear one lookup cache entry or all lookup cache entries."""
    if cache_key:
        _LOOKUP_CACHE.pop(cache_key, None)
        _LOOKUP_CACHE_LOADED_AT.pop(cache_key, None)
        return
    _LOOKUP_CACHE.clear()
    _LOOKUP_CACHE_LOADED_AT.clear()


def get_cached_lookup(
    cache_key: str,
    path: str,
    params: dict[str, Any] | None = None,
    refresh: bool = False,
) -> tuple[list[dict[str, Any]], bool, int]:
    """Return a TOPdesk lookup list from a TTL-controlled memory cache."""
    now = time.monotonic()
    loaded_at = _LOOKUP_CACHE_LOADED_AT.get(cache_key, 0.0)
    age = now - loaded_at
    cache_valid = (
        cache_key in _LOOKUP_CACHE
        and LOOKUP_CACHE_TTL_SECONDS > 0
        and age < LOOKUP_CACHE_TTL_SECONDS
    )
    if cache_valid and not refresh:
        return _LOOKUP_CACHE[cache_key], True, int(age)

    items = extract_list(incident_get(path, params=params))
    _LOOKUP_CACHE[cache_key] = items
    _LOOKUP_CACHE_LOADED_AT[cache_key] = time.monotonic()
    return items, False, 0


def get_metadata(path: str) -> list[dict[str, Any]]:
    cache_key = f"metadata:{path}"
    items, _, _ = get_cached_lookup(cache_key, path)
    return compact_metadata(items)


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


def extract_requester_name(request_text: Any) -> str:
    """Extract the person shown as sender/requester on the first request line."""
    text = clean_html(request_text)
    if not text:
        return ""
    first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
    if not first_line:
        return ""
    dated = re.match(
        r"^\d{1,2}[A-Za-z]{3}\d{4}\s+\d{1,2}:\d{2}\s+(.+?)\s*[:：]$",
        first_line,
    )
    if dated:
        return re.sub(r"\s+", " ", dated.group(1)).strip()
    plain = re.match(r"^(.+?)\s*[:：]$", first_line)
    if plain:
        candidate = re.sub(r"\s+", " ", plain.group(1)).strip()
        if 2 <= len(candidate) <= 100:
            return candidate
    labelled = re.search(
        r"(?:oprettet af|rekvirent(?:navn)?|anmoder|created by)\s*[:：]\s*([^\n;|]+)",
        text,
        flags=re.IGNORECASE,
    )
    return re.sub(r"\s+", " ", labelled.group(1)).strip() if labelled else ""


def caller_display_name(raw_caller: Any) -> str:
    """Return a caller name without performing an extra API request."""
    if isinstance(raw_caller, dict):
        caller_id = str(raw_caller.get("id") or raw_caller.get("value") or "").strip()
        name = scalar(raw_caller).strip()
        return "" if name == caller_id else name
    value = str(raw_caller or "").strip()
    return "" if is_uuid(value) else value


def normalize_business_status(value: Any) -> str:
    """Normalize TOPdesk processingStatus for user-facing tables."""
    text = scalar(value).strip()
    key = re.sub(r"[\s_-]+", " ", text).strip().casefold()
    mapping = {
        "registered": "Registreret",
        "registreret": "Registreret",
        "assigned": "Tildelt",
        "tildelt": "Tildelt",
        "in progress": "Igang",
        "igang": "Igang",
        "i gang": "Igang",
        "waiting for user": "Venter på bruger",
        "waiting for customer": "Venter på bruger",
        "venter på bruger": "Venter på bruger",
        "waiting for supplier": "Venter på leverandør",
        "waiting for vendor": "Venter på leverandør",
        "venter på leverandør": "Venter på leverandør",
        "completed": "Udført",
        "done": "Udført",
        "udført": "Udført",
        "closed": "Lukket",
        "lukket": "Lukket",
        "updated by user": "Opdateret af bruger",
        "updated by customer": "Opdateret af bruger",
        "opdateret af bruger": "Opdateret af bruger",
        "updated by supplier": "Opdateret af leverandør",
        "updated by vendor": "Opdateret af leverandør",
        "opdateret af leverandør": "Opdateret af leverandør",
    }
    if key in {"firstline", "first line", "secondline", "second line"}:
        return "Ikke angivet"
    return mapping.get(key, text or "Ikke angivet")


def incident_result_row(raw: dict[str, Any]) -> dict[str, str]:
    """Create one table row and enrich missing business status on demand."""
    incident = transform_incident(raw)
    processing_status = (
        raw.get("processingStatus")
        or incident.get("processingStatus", "")
    )

    # TOPdesk may omit processingStatus from /incidents list responses.
    # Fetch only the selected incident detail when that value is missing.
    if not scalar(processing_status).strip():
        incident_id = incident.get("id", "").strip()
        incident_number = incident.get("number", "").strip()
        try:
            if incident_id:
                detail_raw = incident_get(
                    f"/incidents/id/{quote(incident_id, safe='')}",
                    params={"dateFormat": "iso8601", "fields": INCIDENT_FIELDS},
                )
            elif incident_number:
                detail_raw = incident_get(
                    f"/incidents/number/{quote(incident_number, safe='')}",
                    params={"dateFormat": "iso8601", "fields": INCIDENT_FIELDS},
                )
            else:
                detail_raw = {}

            if isinstance(detail_raw, dict) and detail_raw:
                detail_incident = transform_incident(detail_raw)
                processing_status = (
                    detail_raw.get("processingStatus")
                    or detail_incident.get("processingStatus", "")
                )
                # Preserve fuller caller/request values when list data omitted them.
                for field in ("request", "caller", "creationDate"):
                    if not incident.get(field) and detail_incident.get(field):
                        incident[field] = detail_incident[field]
        except TopdeskApiError:
            pass

    requester = extract_requester_name(incident.get("request", ""))
    caller = caller_display_name(raw.get("caller")) or incident.get("caller", "")
    return {
        "Sagsnummer": incident.get("number", ""),
        "Beskrivelse": incident.get("briefDescription", ""),
        "Status": normalize_business_status(processing_status),
        "Dato tilføjet (oprettet)": format_incident_datetime(
            incident.get("creationDate", "")
        ),
        "Rekvirentnavn": requester or caller or "Ikke angivet",
        "Anmoder": caller or requester or "Ikke angivet",
    }


def build_incident_indexes(incidents: list[dict[str, Any]]) -> None:
    """Build in-memory indexes for fast requester and metadata searches."""
    global _REQUESTER_INDEX
    global _OPERATOR_INDEX
    global _CATEGORY_INDEX
    global _SUBCATEGORY_INDEX
    global _INCIDENT_NUMBER_INDEX

    requester_index: dict[str, list[dict[str, Any]]] = {}
    operator_index: dict[str, list[dict[str, Any]]] = {}
    category_index: dict[str, list[dict[str, Any]]] = {}
    subcategory_index: dict[str, list[dict[str, Any]]] = {}
    number_index: dict[str, dict[str, Any]] = {}

    for raw in incidents:
        incident = transform_incident(raw)
        requester = extract_requester_name(incident.get("request", "")).casefold()
        caller = caller_display_name(raw.get("caller")).casefold()
        operator = incident.get("operator", "").casefold()
        category = incident.get("category", "").casefold()
        subcategory = incident.get("subcategory", "").casefold()
        number = normalize_incident_number(incident.get("number", "")).casefold()

        for person_key in {requester, caller}:
            if person_key:
                requester_index.setdefault(person_key, []).append(raw)
        if operator:
            operator_index.setdefault(operator, []).append(raw)
        if category:
            category_index.setdefault(category, []).append(raw)
        if subcategory:
            subcategory_index.setdefault(subcategory, []).append(raw)
        if number:
            number_index[number] = raw

    _REQUESTER_INDEX = requester_index
    _OPERATOR_INDEX = operator_index
    _CATEGORY_INDEX = category_index
    _SUBCATEGORY_INDEX = subcategory_index
    _INCIDENT_NUMBER_INDEX = number_index


def clear_incident_cache() -> None:
    """Clear the in-memory incident cache and all derived indexes."""
    global _INCIDENT_CACHE, _INCIDENT_CACHE_LOADED_AT
    global _REQUESTER_INDEX, _OPERATOR_INDEX
    global _CATEGORY_INDEX, _SUBCATEGORY_INDEX, _INCIDENT_NUMBER_INDEX
    _INCIDENT_CACHE = []
    _INCIDENT_CACHE_LOADED_AT = 0.0
    _REQUESTER_INDEX = {}
    _OPERATOR_INDEX = {}
    _CATEGORY_INDEX = {}
    _SUBCATEGORY_INDEX = {}
    _INCIDENT_NUMBER_INDEX = {}


def get_all_incidents_cached(
    refresh: bool = False,
) -> tuple[list[dict[str, Any]], bool, int]:
    """Return all accessible incidents, using a short-lived in-memory cache."""
    global _INCIDENT_CACHE, _INCIDENT_CACHE_LOADED_AT

    now = time.monotonic()
    cache_age = now - _INCIDENT_CACHE_LOADED_AT
    cache_valid = (
        bool(_INCIDENT_CACHE)
        and INCIDENT_CACHE_TTL_SECONDS > 0
        and cache_age < INCIDENT_CACHE_TTL_SECONDS
    )
    if cache_valid and not refresh:
        if not _INCIDENT_NUMBER_INDEX:
            build_incident_indexes(_INCIDENT_CACHE)
        return _INCIDENT_CACHE, True, int(cache_age)

    incidents: list[dict[str, Any]] = []
    page_start = 0
    page_size = max(1, min(INCIDENT_CACHE_PAGE_SIZE, 10000))

    while True:
        data = incident_get(
            "/incidents",
            params={
                "pageStart": page_start,
                "pageSize": page_size,
                "sort": "creationDate:desc",
                "dateFormat": "iso8601",
                "all": "true",
                "fields": INCIDENT_FIELDS,
            },
        )
        page = extract_list(data)
        if not page:
            break
        incidents.extend(page)
        if len(page) < page_size:
            break
        page_start += len(page)

    _INCIDENT_CACHE = incidents
    build_incident_indexes(_INCIDENT_CACHE)
    _INCIDENT_CACHE_LOADED_AT = time.monotonic()
    return _INCIDENT_CACHE, False, 0


def iter_all_incidents(refresh: bool = False):
    """Yield all incidents from the cache-aware historical incident list."""
    incidents, _, _ = get_all_incidents_cached(refresh=refresh)
    yield from incidents


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
        "incidentCacheTtlSeconds": INCIDENT_CACHE_TTL_SECONDS,
        "incidentCacheCount": len(_INCIDENT_CACHE),
        "requesterIndexKeys": len(_REQUESTER_INDEX),
        "operatorIndexKeys": len(_OPERATOR_INDEX),
        "categoryIndexKeys": len(_CATEGORY_INDEX),
        "subcategoryIndexKeys": len(_SUBCATEGORY_INDEX),
        "incidentNumberIndexKeys": len(_INCIDENT_NUMBER_INDEX),
        "lookupCacheTtlSeconds": LOOKUP_CACHE_TTL_SECONDS,
        "lookupCacheEntries": len(_LOOKUP_CACHE),
        "httpPoolConnections": HTTP_POOL_CONNECTIONS,
        "httpPoolMaxSize": HTTP_POOL_MAXSIZE,
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
                    "Status": normalize_business_status(
                        incident.get("processingStatus", "")
                    ),
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
            "Status",
            "Anmoder",
            "Ansvarlig",
            "Gruppe",
            "Oprettet",
        ],
        "presentationInstruction": (
            "Vis kun displayColumns i den angivne rækkefølge. "
            "Vis Status fra processingStatus. Vis aldrig firstLine eller secondLine."
        ),
        "incidents": incidents,
    }


@mcp.tool()
def search_incidents_by_filters(
    incident_number_starts_with: str = "",
    description_starts_with: str = "",
    branch_starts_with: str = "",
    incident_type_starts_with: str = "",
    category_starts_with: str = "",
    subcategory_starts_with: str = "",
    requester_name_starts_with: str = "",
    operator_name_starts_with: str = "",
    external_number_starts_with: str = "",
    object_id_starts_with: str = "",
    limit: int = 50,
    offset: int = 0,
    refresh: bool = False,
) -> dict[str, Any]:
    """Search all incidents and return one paged result set."""
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    number_prefix = re.sub(
        r"\s+", " ", incident_number_starts_with.strip().upper()
    )
    if number_prefix and not number_prefix.startswith("S"):
        number_prefix = f"S {number_prefix}"
    elif number_prefix.startswith("S"):
        number_prefix = re.sub(r"^S\s*", "S ", number_prefix)

    filters = {
        "number": number_prefix,
        "description": description_starts_with,
        "branch": branch_starts_with,
        "type": incident_type_starts_with,
        "category": category_starts_with,
        "subcategory": subcategory_starts_with,
        "requester": requester_name_starts_with,
        "operator": operator_name_starts_with,
        "external": external_number_starts_with,
        "object": object_id_starts_with,
    }
    if not any(str(value or "").strip() for value in filters.values()):
        raise ValueError("At least one structured search filter must be provided")

    all_incidents, cache_hit, cache_age_seconds = get_all_incidents_cached(
        refresh=refresh
    )
    matches: list[dict[str, str]] = []

    for raw in all_incidents:
        incident = transform_incident(raw)
        requester = extract_requester_name(incident.get("request", ""))
        caller = caller_display_name(raw.get("caller"))
        checks = (
            (number_prefix, incident.get("number", "")),
            (description_starts_with, incident.get("briefDescription", "")),
            (branch_starts_with, incident.get("branch", "")),
            (incident_type_starts_with, incident.get("callType", "")),
            (category_starts_with, incident.get("category", "")),
            (subcategory_starts_with, incident.get("subcategory", "")),
            (operator_name_starts_with, incident.get("operator", "")),
            (external_number_starts_with, incident.get("externalNumber", "")),
            (object_id_starts_with, incident.get("object", "")),
        )
        if any(
            str(expected).strip()
            and not str(actual).casefold().startswith(
                str(expected).strip().casefold()
            )
            for expected, actual in checks
        ):
            continue
        if requester_name_starts_with:
            expected = requester_name_starts_with.strip().casefold()
            if not requester.casefold().startswith(expected) and not caller.casefold().startswith(expected):
                continue
        matches.append(incident_result_row(raw))

    total_matches = len(matches)
    page = matches[offset:offset + limit]
    next_offset = offset + len(page)
    has_more = next_offset < total_matches

    return {
        "count": len(page),
        "totalMatches": total_matches,
        "offset": offset,
        "limit": limit,
        "hasMore": has_more,
        "nextOffset": next_offset if has_more else None,
        "scannedCount": len(all_incidents),
        "cacheHit": cache_hit,
        "cacheAgeSeconds": cache_age_seconds,
        "cacheTtlSeconds": INCIDENT_CACHE_TTL_SECONDS,
        "resultType": "table",
        "displayColumns": [
            "Sagsnummer",
            "Beskrivelse",
            "Status",
            "Dato tilføjet (oprettet)",
            "Rekvirentnavn",
            "Anmoder",
        ],
        "presentationInstruction": (
            "Vis altid tableData som en Markdown-tabel. Brug præcis kolonnerne "
            "i displayColumns og i den angivne rækkefølge. Vis Status fra "
            "processingStatus. Vis aldrig firstLine eller secondLine."
        ),
        "tableData": page,
        "incidents": page,
    }


@mcp.tool()
def search_incidents(
    query: str,
    limit: int = 7,
    scan: int = 0,
    refresh: bool = False,
) -> dict[str, Any]:
    """Search all accessible current and archived incidents with strict matching.

    Every meaningful query term must occur somewhere in the incident. This
    prevents generic words such as 'til' from making an unrelated incident look
    like a valid match. Exact title matches are ranked first.
    """
    query = re.sub(r"\s+", " ", query).strip()
    if not query:
        raise ValueError("query must not be empty")

    limit = max(1, min(limit, 25))
    scan = max(0, scan)

    stop_words = {
        "af", "alle", "at", "den", "der", "det", "en", "et", "find",
        "for", "fra", "i", "med", "mig", "og", "på", "sag", "sager",
        "som", "ticket", "tickets", "til", "vis",
    }
    raw_terms = tokenize(query)
    meaningful_terms = [term for term in raw_terms if term not in stop_words]
    if not meaningful_terms:
        meaningful_terms = raw_terms

    normalized_query = re.sub(r"[^\wæøå]+", " ", query.casefold()).strip()

    all_incidents, cache_hit, cache_age_seconds = get_all_incidents_cached(
        refresh=refresh
    )
    search_scope = all_incidents[:scan] if scan > 0 else all_incidents

    results: list[dict[str, Any]] = []
    exact_title_count = 0
    for raw in search_scope:
        item = transform_incident(raw)
        title = item.get("briefDescription", "").casefold()
        searchable_fields = (
            item.get("number", "").casefold(),
            title,
            item.get("request", "").casefold(),
            item.get("action", "").casefold(),
            item.get("category", "").casefold(),
            item.get("subcategory", "").casefold(),
            item.get("caller", "").casefold(),
        )
        combined_text = " ".join(searchable_fields)

        # A valid result must contain every meaningful query term.
        matched_terms = [term for term in meaningful_terms if term in combined_text]
        if meaningful_terms and len(matched_terms) != len(meaningful_terms):
            continue

        normalized_title = re.sub(r"[^\wæøå]+", " ", title).strip()
        exact_title = normalized_title == normalized_query
        title_phrase = normalized_query and normalized_query in normalized_title

        weighted_fields = (
            (item.get("number", "").casefold(), 100),
            (title, 30),
            (item.get("request", "").casefold(), 20),
            (item.get("action", "").casefold(), 12),
            (item.get("category", "").casefold(), 10),
            (item.get("subcategory", "").casefold(), 10),
            (item.get("caller", "").casefold(), 6),
        )
        score = sum(
            weight
            for term in meaningful_terms
            for text, weight in weighted_fields
            if term in text
        )
        if exact_title:
            score += 1000
            exact_title_count += 1
        elif title_phrase:
            score += 500

        item["relevanceScore"] = score
        item["matchType"] = (
            "exact_title" if exact_title else
            "title_phrase" if title_phrase else
            "all_terms"
        )
        item["matchedTerms"] = matched_terms
        results.append(item)

    def incident_search_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
        """Rank exact matches first and sort equal match types newest first."""
        match_type = item.get("matchType", "")
        match_rank = {
            "exact_title": 3,
            "title_phrase": 2,
            "all_terms": 1,
        }.get(match_type, 0)

        creation_date = str(item.get("creationDate") or "").strip()
        try:
            creation_timestamp = datetime.fromisoformat(
                creation_date.replace("Z", "+00:00")
            ).timestamp()
        except (TypeError, ValueError, OSError):
            creation_timestamp = 0.0

        # Exact-title results are ordered by creation date, not by small score
        # differences caused by matches in request/action text.
        if match_type == "exact_title":
            return (match_rank, creation_timestamp, item.get("relevanceScore", 0))

        return (match_rank, item.get("relevanceScore", 0), creation_timestamp)

    results.sort(key=incident_search_sort_key, reverse=True)
    selected = results[:limit]
    return {
        "query": query,
        "matchMode": "all_meaningful_terms",
        "meaningfulTerms": meaningful_terms,
        "exactTitleMatches": exact_title_count,
        "count": len(selected),
        "references": selected,
        "searchedIncidentCount": len(search_scope),
        "cachedIncidentCount": len(all_incidents),
        "cacheHit": cache_hit,
        "cacheAgeSeconds": cache_age_seconds,
        "cacheTtlSeconds": INCIDENT_CACHE_TTL_SECONDS,
        "instruction": (
            "Return only references from this response. Never select or open an "
            "incident that is not returned. If count is 0, state that no matching "
            "incident was found. If exactTitleMatches is 0, do not claim an exact "
            "title match."
        ),
    }


@mcp.tool()
def find_incidents_by_requester(
    requester_name: str,
    title_contains: str = "",
    status: str = "",
    limit: int = 200,
    exact_match: bool = True,
) -> dict[str, Any]:
    """Find current and archived incidents by structured TOPdesk requester."""
    requester_name = re.sub(r"\s+", " ", requester_name).strip()
    if not requester_name:
        raise ValueError("requester_name must not be empty")
    caller_data=incident_get("/incidents/callers/lookup",params={"pageStart":0,"pageSize":1000})
    candidates=[]
    for caller in extract_list(caller_data):
        if not isinstance(caller,dict):
            continue
        caller_name=scalar(caller)
        matched=(caller_name.casefold()==requester_name.casefold() if exact_match else requester_name.casefold() in caller_name.casefold())
        caller_id=str(caller.get("id") or caller.get("value") or "").strip()
        if matched and caller_id:
            candidates.append({"id":caller_id,"name":caller_name})
    rows=[]; seen=set()
    for candidate in candidates:
        clauses=[f"caller.id=={fiql_escape(candidate['id'])}"]
        if title_contains.strip(): clauses.append(f"briefDescription==*{fiql_escape(title_contains)}*")
        if status.strip(): clauses.append(f"status=={fiql_escape(status)}")
        data=incident_get("/incidents",params={
            "pageStart":0,"pageSize":min(max(1,limit),500),"sort":"creationDate:desc",
            "dateFormat":"iso8601","all":"true","query":";".join(clauses),"fields":INCIDENT_FIELDS,
        })
        for raw in extract_list(data):
            incident=transform_incident(raw); number=incident.get("number","")
            if number in seen: continue
            seen.add(number); rows.append(format_incident_search_row(incident,candidate["name"]))
            if len(rows)>=limit: break
        if len(rows)>=limit: break
    return {
        "count":len(rows),"requesterName":requester_name,"callerCandidates":candidates,
        "displayColumns":["Sagsnummer","Beskrivelse","Status","Dato tilføjet (oprettet)","Rekvirentnavn","Anmoder"],
        "incidents":rows,
    }


@mcp.tool()
def find_incidents_created_by_person(
    person_name: str,
    title_contains: str = "",
    category_contains: str = "",
    subcategory_contains: str = "",
    limit: int = 50,
    offset: int = 0,
    refresh: bool = False,
) -> dict[str, Any]:
    """Use for questions asking which incidents a person created, submitted, requested or is the requester for. Return a paged table. Do not use general content search for creator questions."""
    person_name = re.sub(r"\s+", " ", person_name).strip()
    if not person_name:
        raise ValueError("person_name must not be empty")

    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    target = person_name.casefold()
    all_incidents, cache_hit, cache_age_seconds = get_all_incidents_cached(
        refresh=refresh
    )
    indexed_incidents = _REQUESTER_INDEX.get(target, [])

    matches: list[dict[str, str]] = []
    for raw in indexed_incidents:
        incident = transform_incident(raw)
        if title_contains and title_contains.casefold() not in incident.get(
            "briefDescription", ""
        ).casefold():
            continue
        if category_contains and category_contains.casefold() not in incident.get(
            "category", ""
        ).casefold():
            continue
        if subcategory_contains and subcategory_contains.casefold() not in incident.get(
            "subcategory", ""
        ).casefold():
            continue

        requester = extract_requester_name(incident.get("request", ""))
        caller = caller_display_name(raw.get("caller"))
        if requester.casefold() != target and caller.casefold() != target:
            continue
        matches.append(incident_result_row(raw))

    total_matches = len(matches)
    page = matches[offset:offset + limit]
    next_offset = offset + len(page)
    has_more = next_offset < total_matches

    return {
        "count": len(page),
        "totalMatches": total_matches,
        "searchedPerson": person_name,
        "offset": offset,
        "limit": limit,
        "hasMore": has_more,
        "nextOffset": next_offset if has_more else None,
        "scannedCount": len(indexed_incidents),
        "cachedIncidentCount": len(all_incidents),
        "indexUsed": "requester",
        "indexKey": target,
        "cacheHit": cache_hit,
        "cacheAgeSeconds": cache_age_seconds,
        "cacheTtlSeconds": INCIDENT_CACHE_TTL_SECONDS,
        "resultType": "table",
        "displayColumns": [
            "Sagsnummer",
            "Beskrivelse",
            "Status",
            "Dato tilføjet (oprettet)",
            "Rekvirentnavn",
            "Anmoder",
        ],
        "presentationInstruction": (
            "Vis altid tableData som en Markdown-tabel. Brug præcis kolonnerne "
            "i displayColumns og i den angivne rækkefølge. Vis Status fra "
            "processingStatus. Vis aldrig firstLine eller secondLine. Hvis hasMore er true, "
            "oplys efter tabellen at flere resultater kan hentes med nextOffset."
        ),
        "tableData": page,
        "incidents": page,
    }


def find_reference_ids(
    path: str,
    name: str,
    page_size: int = 1000,
) -> list[dict[str, str]]:
    """Resolve matching TOPdesk metadata names to IDs using lookup cache."""
    target = re.sub(r"\s+", " ", name).strip().casefold()
    if not target:
        return []

    cache_key = f"reference:{path}:page_size={page_size}"
    items, _, _ = get_cached_lookup(
        cache_key,
        path,
        params={"pageStart": 0, "pageSize": page_size},
    )

    matches: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id") or item.get("value") or "").strip()
        item_name = scalar(item).strip()
        if item_id and item_name.casefold().startswith(target):
            matches.append({"id": item_id, "name": item_name})
    return matches


def query_incidents_by_reference(
    field_name: str,
    references: list[dict[str, str]],
    title_contains: str = "",
    max_results: int = 10000,
) -> list[dict[str, Any]]:
    """Use TOPdesk FIQL filtering instead of opening every incident detail."""
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for reference in references:
        page_start = 0
        page_size = min(1000, max_results)
        while len(results) < max_results:
            data = incident_get(
                "/incidents",
                params={
                    "pageStart": page_start,
                    "pageSize": min(page_size, max_results - len(results)),
                    "sort": "creationDate:desc",
                    "dateFormat": "iso8601",
                    "all": "true",
                    "query": f"{field_name}.id=={fiql_escape(reference['id'])}",
                    "fields": INCIDENT_FIELDS,
                },
            )
            page = extract_list(data)
            if not page:
                break
            for raw in page:
                incident = transform_incident(raw)
                if title_contains and title_contains.casefold() not in incident.get("briefDescription", "").casefold():
                    continue
                identity = incident.get("number") or incident.get("id")
                if identity and identity not in seen:
                    seen.add(identity)
                    results.append(raw)
            if len(page) < page_size:
                break
            page_start += len(page)
    return results


def indexed_table_response(
    raw_matches: list[dict[str, Any]],
    limit: int,
    offset: int,
    index_used: str,
    index_key: str,
    references: list[dict[str, str]],
) -> dict[str, Any]:
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    total = len(raw_matches)
    page = [incident_result_row(raw) for raw in raw_matches[offset:offset + limit]]
    next_offset = offset + len(page)
    return {
        "count": len(page),
        "totalMatches": total,
        "offset": offset,
        "limit": limit,
        "hasMore": next_offset < total,
        "nextOffset": next_offset if next_offset < total else None,
        "indexUsed": index_used,
        "indexKey": index_key,
        "matchedReferences": references,
        "resultType": "table",
        "displayColumns": ["Sagsnummer", "Beskrivelse", "Status", "Dato tilføjet (oprettet)", "Rekvirentnavn", "Anmoder"],
        "presentationInstruction": "Vis altid tableData som en Markdown-tabel med displayColumns i den angivne rækkefølge.",
        "tableData": page,
        "incidents": page,
    }


@mcp.tool()
def find_incidents_by_operator(
    operator_name: str,
    title_contains: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Find incidents assigned to an operator using TOPdesk server-side filtering."""
    operator_name = re.sub(r"\s+", " ", operator_name).strip()
    references = find_reference_ids("/incidents/operators/lookup", operator_name)
    matches = query_incidents_by_reference("operator", references, title_contains)
    return indexed_table_response(matches, limit, offset, "topdesk-fiql-operator", operator_name.casefold(), references)


@mcp.tool()
def find_incidents_by_category(
    category_name: str,
    title_contains: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Find incidents in a category using TOPdesk server-side filtering."""
    category_name = re.sub(r"\s+", " ", category_name).strip()
    references = find_reference_ids("/incidents/categories", category_name)
    matches = query_incidents_by_reference("category", references, title_contains)
    return indexed_table_response(matches, limit, offset, "topdesk-fiql-category", category_name.casefold(), references)


@mcp.tool()
def find_incidents_by_subcategory(
    subcategory_name: str,
    title_contains: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Find incidents in a subcategory using TOPdesk server-side filtering."""
    subcategory_name = re.sub(r"\s+", " ", subcategory_name).strip()
    references = find_reference_ids("/incidents/subcategories", subcategory_name)
    matches = query_incidents_by_reference("subcategory", references, title_contains)
    return indexed_table_response(matches, limit, offset, "topdesk-fiql-subcategory", subcategory_name.casefold(), references)


@mcp.tool()
def find_incidents_by_name_in_content(
    name: str,
    title_contains: str = "",
    status: str = "",
    limit: int = 200,
    scan: int = 0,
    refresh: bool = False,
) -> dict[str, Any]:
    """Use only for general name mentions in request or action text, not for questions about who created, submitted or requested incidents.

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
    scan = max(0, scan)
    name_filter = name.casefold()
    title_filter = title_contains.casefold()
    status_filter = status.casefold()

    all_incidents, cache_hit, cache_age_seconds = get_all_incidents_cached(
        refresh=refresh
    )
    search_scope = all_incidents[:scan] if scan > 0 else all_incidents

    matches: list[dict[str, Any]] = []
    scanned = 0
    for raw in search_scope:
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
    return {
        "status": "ok",
        "searchedName": name,
        "titleContains": title_contains,
        "statusFilter": status,
        "searchedFields": ["request", "action"],
        "scannedCount": scanned,
        "count": len(matches),
        "limitReached": len(matches) >= limit,
        "scanLimitReached": scan > 0 and scanned >= scan,
        "cachedIncidentCount": len(all_incidents),
        "cacheHit": cache_hit,
        "cacheAgeSeconds": cache_age_seconds,
        "cacheTtlSeconds": INCIDENT_CACHE_TTL_SECONDS,
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
    """Get an incident by number, accepting values with or without the S prefix."""
    variants=incident_number_variants(number)
    if not variants: raise ValueError("number must not be empty")
    errors=[]
    for variant in variants:
        try:
            return transform_incident(incident_get(
                f"/incidents/number/{quote(variant,safe='')}",
                params={"dateFormat":"iso8601"},
            ))
        except TopdeskApiError as error:
            errors.append(f"{variant}: HTTP {error.status_code}")
    normalized=variants[0]
    try:
        data=incident_get("/incidents",params={
            "pageStart":0,"pageSize":10,"dateFormat":"iso8601","all":"true",
            "query":f"number=={fiql_escape(normalized)}","fields":INCIDENT_FIELDS,
        })
        items=extract_list(data)
        if items: return transform_incident(items[0])
    except TopdeskApiError as error:
        errors.append(f"fallback: HTTP {error.status_code}")
    raise ValueError(f"Incident {normalized} was not found. Attempts: "+"; ".join(errors))


@mcp.tool()
def find_callers(
    query: str,
    limit: int = 20,
) -> dict[str, Any]:
    """Find caller candidates for the incident wizard."""
    query = query.strip().lower()
    limit = max(1, min(limit, 100))
    callers, _, _ = get_cached_lookup(
        "callers:page_size=1000",
        "/incidents/callers/lookup",
        params={"pageStart": 0, "pageSize": 1000},
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
    operators, _, _ = get_cached_lookup(
        "operators:page_size=1000",
        "/incidents/operators/lookup",
        params={"pageStart": 0, "pageSize": 1000},
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
