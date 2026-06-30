# ─────────────────────────────────────────────────────────────────
#  core/parser.py — HTTP Request Parser & Normalizer
#
#  WHY IS PARSING IMPORTANT?
#  Attackers are clever. They hide their attacks using tricks like:
#    - URL encoding:    %3Cscript%3E  →  <script>
#    - Double encoding: %253Cscript%253E → <script>
#    - Unicode tricks:  ＜script＞ (full-width chars)
#    - Mixed case:      SeLeCt * FrOm users
#    - Null bytes:      attack\x00normal
#
#  The parser's job is to NORMALIZE everything before checking rules,
#  so attackers can't hide their payloads using encoding tricks.
# ─────────────────────────────────────────────────────────────────

import re
import json
from urllib.parse import unquote, unquote_plus, urlparse, parse_qs
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any


# ── Data Structure: ParsedRequest ────────────────────────────────
@dataclass
class ParsedRequest:
    """
    A clean, structured representation of an incoming HTTP request.
    All values are normalized (decoded, cleaned) and ready for rule matching.
    """
    # Raw request details (exactly as received)
    raw_ip:          str = ""
    raw_method:      str = ""
    raw_path:        str = ""
    raw_query:       str = ""
    raw_headers:     Dict[str, str] = field(default_factory=dict)
    raw_body:        str = ""

    # Normalized values (decoded, cleaned — used for rule matching)
    normalized_path:  str = ""
    normalized_query: str = ""
    normalized_body:  str = ""

    # Extracted components
    query_params:    Dict[str, List[str]] = field(default_factory=dict)
    all_values:      List[str] = field(default_factory=list)   # ALL extracted strings
    user_agent:      str = ""
    content_type:    str = ""

    # Full normalized string to check against rules (combines everything)
    full_payload:    str = ""


class RequestParser:
    """
    Parses and normalizes HTTP requests before security analysis.
    
    USAGE:
        parser = RequestParser()
        parsed = parser.parse({
            "ip": "192.168.1.1",
            "method": "GET",
            "path": "/search",
            "query": "q=<script>alert(1)</script>",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": ""
        })
    """

    def parse(self, request_data: Dict[str, Any]) -> ParsedRequest:
        """
        Main entry point. Takes a raw request dict and returns a ParsedRequest.
        """
        parsed = ParsedRequest()

        # Step 1: Extract raw values
        parsed.raw_ip      = request_data.get("ip", "127.0.0.1")
        parsed.raw_method  = request_data.get("method", "GET").upper()
        parsed.raw_path    = request_data.get("path", "/")
        parsed.raw_query   = request_data.get("query", "")
        parsed.raw_headers = request_data.get("headers", {})
        parsed.raw_body    = request_data.get("body", "") or ""

        # Step 2: Extract useful headers
        headers_lower = {k.lower(): v for k, v in parsed.raw_headers.items()}
        parsed.user_agent   = headers_lower.get("user-agent", "")
        parsed.content_type = headers_lower.get("content-type", "")

        # Step 3: Normalize each component (decode all encoding tricks)
        parsed.normalized_path  = self._normalize(parsed.raw_path)
        parsed.normalized_query = self._normalize(parsed.raw_query)
        parsed.normalized_body  = self._normalize(parsed.raw_body)

        # Step 4: Parse query string into key-value pairs
        if parsed.raw_query:
            try:
                parsed.query_params = parse_qs(parsed.raw_query)
            except Exception:
                parsed.query_params = {}

        # Step 5: Collect ALL string values into one flat list
        # This way rules only need to check one list, not every field
        parsed.all_values = self._collect_all_values(parsed)

        # Step 6: Build the full combined payload string for pattern matching
        parts = [
            parsed.normalized_path,
            parsed.normalized_query,
            parsed.normalized_body,
            parsed.user_agent,
            # Include all header values (attackers sometimes hide payloads in headers)
            " ".join(str(v) for v in parsed.raw_headers.values()),
        ]
        parsed.full_payload = " ".join(filter(None, parts))

        return parsed

    def _normalize(self, text: str) -> str:
        """
        Decode all encoding tricks so attackers can't bypass rules.
        
        Example:
            "%3Cscript%3E"  →  normalize  →  "<script>"
            "%253Cscript"   →  normalize  →  "<script>"   (double encoded)
        """
        if not text:
            return ""

        result = str(text)

        # Round 1: URL decode (%XX encoding)
        result = unquote_plus(result)

        # Round 2: URL decode again (catches double-encoded: %2520 → %20 → space)
        result = unquote_plus(result)

        # Round 3: Remove null bytes (attackers use these to truncate strings)
        result = result.replace("\x00", "").replace("%00", "")

        # Round 4: Normalize whitespace (collapse multiple spaces/tabs/newlines)
        result = re.sub(r'\s+', ' ', result).strip()

        # Round 5: Lowercase for case-insensitive matching
        # (keeps original too — some checks are case-sensitive)
        result_lower = result.lower()

        # Round 6: Normalize HTML entities (&lt; → <, &gt; → >, &#60; → <)
        result_lower = result_lower.replace("&lt;", "<").replace("&gt;", ">")
        result_lower = result_lower.replace("&amp;", "&").replace("&quot;", '"')
        result_lower = re.sub(r'&#(\d+);', lambda m: chr(int(m.group(1))), result_lower)
        result_lower = re.sub(r'&#x([0-9a-f]+);', lambda m: chr(int(m.group(1), 16)), result_lower)

        # Round 7: Remove common obfuscation tricks
        # e.g., "sel/*comment*/ect" → "select"
        result_lower = re.sub(r'/\*.*?\*/', '', result_lower)

        # Return the fully normalized, lowercase version
        return result_lower

    def _collect_all_values(self, parsed: ParsedRequest) -> List[str]:
        """
        Collect every string value from headers, query params, body etc.
        into one flat list for easy rule matching.
        """
        values = []

        # Path and query
        values.append(parsed.normalized_path)
        values.append(parsed.normalized_query)

        # Each query parameter value
        for param_values in parsed.query_params.values():
            for v in param_values:
                values.append(self._normalize(v))

        # Body — try to parse as JSON, XML, or form-data
        if parsed.raw_body:
            values.append(parsed.normalized_body)

            # Try JSON body
            try:
                json_body = json.loads(parsed.raw_body)
                values.extend(self._extract_json_values(json_body))
            except (json.JSONDecodeError, TypeError):
                pass

        # Header values (check for header injection)
        for v in parsed.raw_headers.values():
            values.append(self._normalize(str(v)))

        # Filter out empty strings
        return [v for v in values if v and v.strip()]

    def _extract_json_values(self, obj: Any, depth: int = 0) -> List[str]:
        """
        Recursively extract all string values from a JSON object.
        Attackers often hide payloads deep inside nested JSON.
        
        Max depth = 5 to avoid infinite loops on circular references.
        """
        if depth > 5:
            return []

        values = []
        if isinstance(obj, dict):
            for v in obj.values():
                values.extend(self._extract_json_values(v, depth + 1))
        elif isinstance(obj, list):
            for item in obj:
                values.extend(self._extract_json_values(item, depth + 1))
        elif isinstance(obj, str):
            values.append(self._normalize(obj))

        return values
