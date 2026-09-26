from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app
from scripts.export_legacy_sensor_data import LEGACY_TABLES


def test_active_api_has_no_sensor_routes():
    app = create_app()
    # Newer FastAPI wraps included routers in objects without `.path`, so walk
    # the published schema and also prove the old URLs no longer resolve.
    paths = set(app.openapi()["paths"])
    assert not any(path.startswith("/api/v1/sensor") for path in paths)
    assert not any(path.startswith("/api/v1/admin/sensor") for path in paths)

    client = TestClient(app)
    for method, path in (
        ("GET", "/api/v1/sensor/policy"),
        ("POST", "/api/v1/sensor/events"),
        ("POST", "/api/v1/sensor/heartbeat"),
        ("POST", "/api/v1/admin/sensor/bootstrap-tokens"),
    ):
        assert client.request(method, path).status_code == 404, path


def test_export_allowlist_excludes_active_adr_credentials():
    assert LEGACY_TABLES == (
        "endpoint_sensor_events",
        "endpoint_sensor_download_sessions",
    )
    assert all("token" not in name and not name.startswith("adr_") for name in LEGACY_TABLES)


def test_sensor_api_module_is_removed():
    assert not (Path(__file__).parents[1] / "app" / "api" / "sensor.py").exists()
