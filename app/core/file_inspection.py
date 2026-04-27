from __future__ import annotations

import base64
import io
import re
import zipfile
from dataclasses import dataclass
from html import unescape
from xml.etree import ElementTree


DEFAULT_MAX_EXTRACTED_CHARS = 250_000


@dataclass
class ExtractedFileText:
    text: str
    truncated: bool
    status: str
    error: str | None = None


def extract_attachment_text(
    *,
    filename: str,
    extension: str,
    content_b64: str | None,
    fallback_text: str | None,
    max_chars: int = DEFAULT_MAX_EXTRACTED_CHARS,
) -> ExtractedFileText:
    ext = extension.lower().lstrip(".")
    if fallback_text:
        text = fallback_text[:max_chars]
        return ExtractedFileText(
            text=text,
            truncated=len(fallback_text) > max_chars,
            status="truncated" if len(fallback_text) > max_chars else "extracted",
        )
    if not content_b64:
        return ExtractedFileText(text="", truncated=False, status="server_required", error="missing_file_content")

    try:
        raw = base64.b64decode(content_b64, validate=True)
    except Exception as exc:
        return ExtractedFileText(text="", truncated=False, status="extraction_failed", error=f"invalid_base64: {exc}")

    try:
        if ext in {"txt", "csv"}:
            return _cap_text(raw.decode("utf-8", errors="replace"), max_chars)
        if ext == "docx":
            return _extract_docx(raw, max_chars)
        if ext == "xlsx":
            return _extract_xlsx(raw, max_chars)
    except zipfile.BadZipFile:
        return ExtractedFileText(text="", truncated=False, status="extraction_failed", error="not_a_valid_office_zip")
    except RuntimeError as exc:
        return ExtractedFileText(text="", truncated=False, status="extraction_failed", error=str(exc))
    except Exception as exc:
        return ExtractedFileText(text="", truncated=False, status="extraction_failed", error=f"{type(exc).__name__}: {exc}")

    return ExtractedFileText(text="", truncated=False, status="unsupported", error=f"unsupported_extension:{filename}")


def _cap_text(text: str, max_chars: int) -> ExtractedFileText:
    truncated = len(text) > max_chars
    return ExtractedFileText(
        text=text[:max_chars],
        truncated=truncated,
        status="truncated" if truncated else "extracted",
    )


def _append_capped(parts: list[str], value: str, max_chars: int) -> bool:
    current = sum(len(part) for part in parts)
    remaining = max_chars - current
    if remaining <= 0:
        return True
    parts.append(value[:remaining])
    return len(value) > remaining


def _extract_docx(raw: bytes, max_chars: int) -> ExtractedFileText:
    parts: list[str] = []
    truncated = False
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        document_names = [
            name for name in archive.namelist() if name == "word/document.xml" or name.startswith("word/header") or name.startswith("word/footer")
        ]
        if not document_names:
            raise RuntimeError("docx_document_xml_missing")
        for name in document_names:
            root = ElementTree.fromstring(archive.read(name))
            text_nodes = [
                node.text or ""
                for node in root.iter()
                if node.tag.rsplit("}", 1)[-1] == "t" and node.text
            ]
            if text_nodes:
                truncated = _append_capped(parts, " ".join(text_nodes) + "\n", max_chars) or truncated
            if truncated:
                break
    return ExtractedFileText("".join(parts), truncated, "truncated" if truncated else "extracted")


def _extract_xlsx(raw: bytes, max_chars: int) -> ExtractedFileText:
    parts: list[str] = []
    truncated = False
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        shared_strings = _read_xlsx_shared_strings(archive)
        sheet_names = sorted(name for name in archive.namelist() if re.match(r"xl/worksheets/sheet\d+\.xml$", name))
        if not sheet_names:
            raise RuntimeError("xlsx_worksheets_missing")
        for sheet_name in sheet_names:
            root = ElementTree.fromstring(archive.read(sheet_name))
            values: list[str] = []
            for cell in root.iter():
                if cell.tag.rsplit("}", 1)[-1] != "c":
                    continue
                cell_type = cell.attrib.get("t")
                value_node = next((child for child in cell if child.tag.rsplit("}", 1)[-1] == "v"), None)
                inline_text = "".join(
                    node.text or ""
                    for node in cell.iter()
                    if node.tag.rsplit("}", 1)[-1] == "t" and node.text
                )
                value = ""
                if cell_type == "s" and value_node is not None and value_node.text:
                    idx = int(value_node.text)
                    value = shared_strings[idx] if 0 <= idx < len(shared_strings) else ""
                elif inline_text:
                    value = inline_text
                elif value_node is not None and value_node.text:
                    value = value_node.text
                if value:
                    values.append(value)
            if values:
                truncated = _append_capped(parts, " ".join(values) + "\n", max_chars) or truncated
            if truncated:
                break
    return ExtractedFileText("".join(parts), truncated, "truncated" if truncated else "extracted")


def _read_xlsx_shared_strings(archive: zipfile.ZipFile) -> list[str]:
    try:
        raw = archive.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    root = ElementTree.fromstring(raw)
    values: list[str] = []
    for item in root:
        if item.tag.rsplit("}", 1)[-1] != "si":
            continue
        values.append(unescape("".join(node.text or "" for node in item.iter() if node.tag.rsplit("}", 1)[-1] == "t")))
    return values
