"""CSV/Excel ingestion: strict, row-level validation into the transaction pipeline.

Upload contract:
  * multipart file upload; CSV must be UTF-8 with a header row; Excel (.xlsx)
    uses the first worksheet's first row as the header;
  * a column map ({"amount": "amount_minor", ...}) may be supplied; unmapped
    columns use normalized header names;
  * every row is validated with the SAME pydantic schema as the API (extra
    columns are dropped, missing required columns fail the row);
  * the response itemizes per-row errors; there are no silent partial accepts;
  * re-uploading the same file is idempotent (payload-hash dedupe in Store).
"""
from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timezone

from fastapi import HTTPException, UploadFile
from pydantic import ValidationError

from fraud_demo import ACCEPTED_CURRENCIES, Transaction

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_ROWS = 5000
CANONICAL_COLUMNS = {"transaction_id", "account_id", "event_time", "amount_minor",
                     "currency", "country", "device_id", "direction"}
REQUIRED_COLUMNS = CANONICAL_COLUMNS - {"direction"}
# Spreadsheet cells arrive as strings; these fields must become integers
# before strict pydantic validation (a strict int rejects "5000").
INTEGER_COLUMNS = {"amount_minor", "subtotal_minor", "tax_minor"}
# Kept permissive here; the pydantic schema enforces exact value rules.
_TIMEISH = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}")
_EXCEL_EPOCH = datetime(1899, 12, 30, tzinfo=timezone.utc)


def _normalize_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


def _cell_to_str(value) -> str:
    """Normalize one spreadsheet cell to a schema-shaped string."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def _coerce_int(record: dict, columns: set[str]) -> str | None:
    """Convert digit strings in `columns` to ints in place; name a bad field."""
    for field in columns:
        value = record.get(field)
        if value is None or value == "":
            continue
        if isinstance(value, int):
            continue
        text = str(value).strip()
        if text.isdigit():
            record[field] = int(text)
        else:
            return field
    return None


def _validate_rows(dict_rows: list[dict], header_map: dict[str, str]) -> dict:
    """Shared strict validation. dict_rows maps header name -> cell value."""
    rows, errors = [], []
    for index, raw in enumerate(dict_rows, start=2):  # header is line 1
        if index > MAX_ROWS + 1:
            errors.append({"row": index, "field": "-", "reason": "row limit (5000) exceeded"})
            break
        record = {}
        for header, value in raw.items():
            canonical = header_map.get(header or "", "")
            if canonical in CANONICAL_COLUMNS:
                record[canonical] = _cell_to_str(value)
        bad_field = _coerce_int(record, INTEGER_COLUMNS & set(record))
        if bad_field:
            errors.append({"row": index, "field": bad_field,
                           "reason": "amount must be an integer of minor units"})
            continue
        row_errors = []
        for field in sorted(REQUIRED_COLUMNS):
            if not record.get(field):
                row_errors.append({"row": index, "field": field,
                                   "reason": "missing required value"})
        if row_errors:
            errors.extend(row_errors)
            continue
        if record.get("direction") not in (None, "", "inflow", "outflow"):
            errors.append({"row": index, "field": "direction",
                           "reason": "must be 'inflow' or 'outflow'"})
            continue
        if record["currency"] not in ACCEPTED_CURRENCIES:
            errors.append({"row": index, "field": "currency",
                           "reason": f"currency must be one of {', '.join(ACCEPTED_CURRENCIES)}"})
            continue
        if not _TIMEISH.match(record["event_time"]):
            errors.append({"row": index, "field": "event_time",
                           "reason": "event_time must be ISO-8601 with timezone "
                                     "(e.g. 2026-03-01T14:00:00Z)"})
            continue
        try:
            tx = Transaction(**record)
        except ValidationError as exc:
            first = exc.errors()[0]
            errors.append({"row": index, "field": str(first.get("loc", ("?",))[-1]),
                           "reason": first.get("msg", "validation failed")})
            continue
        rows.append({"row": index, "tx": tx})
    columns = sorted({canonical for canonical in header_map.values()
                      if canonical in CANONICAL_COLUMNS})
    return {"rows": rows, "errors": errors, "columns": columns}


def _header_map(fieldnames: list[str], column_map: dict[str, str] | None) -> dict[str, str]:
    mapping = {_normalize_key(k): _normalize_key(v) for k, v in (column_map or {}).items()}
    header_map = {name: mapping.get(_normalize_key(name), _normalize_key(name))
                  for name in fieldnames}
    missing = REQUIRED_COLUMNS - set(header_map.values())
    if missing:
        raise HTTPException(
            422, f"missing required columns: {sorted(missing)}; supply a column_map if "
                 f"your headers differ (known fields: {sorted(CANONICAL_COLUMNS)})")
    return header_map


def parse_csv(content: bytes, column_map: dict[str, str] | None = None) -> dict:
    """Parse and validate CSV bytes; returns {rows, errors, columns}."""
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "file too large (limit 5 MiB)")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(415, f"file is not valid UTF-8 CSV: {exc}") from None
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise HTTPException(422, "CSV has no header row")
    header_map = _header_map(list(reader.fieldnames), column_map)
    return _validate_rows(list(reader), header_map)


def parse_xlsx(content: bytes, column_map: dict[str, str] | None = None) -> dict:
    """Parse and validate the first worksheet of an .xlsx workbook."""
    try:
        import openpyxl
    except ImportError:
        raise HTTPException(501, "xlsx support requires the openpyxl dependency") from None
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "file too large (limit 5 MiB)")
    try:
        workbook = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
    except Exception as exc:
        raise HTTPException(422, f"unreadable xlsx: {exc}") from None
    try:
        sheet = workbook.worksheets[0]
        iterator = sheet.iter_rows(values_only=True)
        try:
            header = next(iterator)
        except StopIteration:
            raise HTTPException(422, "workbook's first sheet is empty") from None
        fieldnames = [_cell_to_str(cell) for cell in header]
        header_map = _header_map(fieldnames, column_map)
        dict_rows = [dict(zip(fieldnames, row)) for row in iterator]
    finally:
        workbook.close()
    return _validate_rows(dict_rows, header_map)


async def read_upload(file: UploadFile) -> bytes:
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "file too large (limit 5 MiB)")
    return content


def read_upload_sync(fileobj) -> bytes:
    """Sync variant for def endpoints; same size cap."""
    content = fileobj.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "file too large (limit 5 MiB)")
    return content


def apply_column_map_json(raw: str | None) -> dict[str, str]:
    """Parse a JSON column map supplied as a form field."""
    if not raw:
        return {}
    import json as _json
    try:
        payload = _json.loads(raw)
    except ValueError as exc:
        raise HTTPException(422, f"column_map_json is not valid JSON: {exc}") from None
    return apply_column_map(payload)


def apply_column_map(payload) -> dict[str, str]:
    """Validate a client-supplied column map; unknown targets are rejected."""
    if not payload:
        return {}
    if not isinstance(payload, dict):
        raise HTTPException(422, "column_map must be an object")
    out = {}
    for source, target in payload.items():
        if _normalize_key(target) not in _ALL_KNOWN_COLUMNS:
            raise HTTPException(422, f"column map target '{target}' is not a known field")
        out[str(source)] = str(target)
    return out


# Invoice upload columns (subset becomes Invoice kwargs).
INVOICE_REQUIRED_COLUMNS = {"invoice_id", "vendor_id", "invoice_number", "issue_date",
                            "due_date", "amount_minor", "currency"}
INVOICE_OPTIONAL_COLUMNS = {"subtotal_minor", "tax_minor", "description"}
_ALL_KNOWN_COLUMNS = CANONICAL_COLUMNS | INVOICE_REQUIRED_COLUMNS | INVOICE_OPTIONAL_COLUMNS


def parse_invoice_csv(content: bytes, column_map: dict[str, str] | None = None) -> dict:
    """Parse and validate an AP invoice CSV; returns rows of Invoice objects."""
    from invoices import Invoice

    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "file too large (limit 5 MiB)")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(415, f"file is not valid UTF-8 CSV: {exc}") from None
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise HTTPException(422, "CSV has no header row")
    mapping = {_normalize_key(k): _normalize_key(v) for k, v in (column_map or {}).items()}
    header_map = {name: mapping.get(_normalize_key(name), _normalize_key(name))
                  for name in reader.fieldnames}
    missing = INVOICE_REQUIRED_COLUMNS - set(header_map.values())
    if missing:
        raise HTTPException(422, f"missing required columns: {sorted(missing)}")

    rows, errors = [], []
    for index, raw in enumerate(reader, start=2):
        if index > MAX_ROWS + 1:
            errors.append({"row": index, "field": "-", "reason": "row limit (5000) exceeded"})
            break
        record = {}
        for header, value in raw.items():
            canonical = header_map.get(header or "", "")
            if canonical in (INVOICE_REQUIRED_COLUMNS | INVOICE_OPTIONAL_COLUMNS):
                record[canonical] = _cell_to_str(value)
        missing_fields = [field for field in sorted(INVOICE_REQUIRED_COLUMNS)
                          if not record.get(field)]
        if missing_fields:
            for field in missing_fields:
                errors.append({"row": index, "field": field, "reason": "missing required value"})
            continue
        bad_field = _coerce_int(record, INTEGER_COLUMNS & set(record))
        if bad_field:
            errors.append({"row": index, "field": bad_field,
                           "reason": "amount must be an integer of minor units"})
            continue
        try:
            invoice = Invoice(**record)
        except ValidationError as exc:
            first = exc.errors()[0]
            errors.append({"row": index, "field": str(first.get("loc", ("?",))[-1]),
                           "reason": first.get("msg", "validation failed")})
            continue
        rows.append({"row": index, "invoice": invoice})
    return {"rows": rows, "errors": errors}
