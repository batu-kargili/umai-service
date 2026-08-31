"""UMAI service test support package.

Keeping the test directory importable lets database-backed tests share the
``db_session`` context manager from ``tests.conftest`` without accidentally
resolving an unrelated third-party package named ``tests``.
"""
