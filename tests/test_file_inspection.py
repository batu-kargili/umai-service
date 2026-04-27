from __future__ import annotations

import base64
import io
import zipfile
import unittest

from app.core.file_inspection import extract_attachment_text


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


class FileInspectionTests(unittest.TestCase):
    def test_txt_extraction_truncates_to_budget(self) -> None:
        result = extract_attachment_text(
            filename="notes.txt",
            extension="txt",
            content_b64=_b64(b"abcdef"),
            fallback_text=None,
            max_chars=3,
        )

        self.assertEqual(result.text, "abc")
        self.assertTrue(result.truncated)
        self.assertEqual(result.status, "truncated")

    def test_docx_extraction_reads_document_text(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr(
                "word/document.xml",
                (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                    "<w:body><w:p><w:r><w:t>secret in docx</w:t></w:r></w:p></w:body></w:document>"
                ),
            )

        result = extract_attachment_text(
            filename="doc.docx",
            extension="docx",
            content_b64=_b64(buf.getvalue()),
            fallback_text=None,
            max_chars=250000,
        )

        self.assertIn("secret in docx", result.text)
        self.assertEqual(result.status, "extracted")

    def test_corrupt_office_file_returns_extraction_failed(self) -> None:
        result = extract_attachment_text(
            filename="bad.docx",
            extension="docx",
            content_b64=_b64(b"not a zip"),
            fallback_text=None,
            max_chars=250000,
        )

        self.assertEqual(result.status, "extraction_failed")
        self.assertIn("not_a_valid_office_zip", result.error or "")


if __name__ == "__main__":
    unittest.main()
