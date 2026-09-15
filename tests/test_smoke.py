"""Smoke test for NetAudit package."""
import netaudit


def test_package_import():
    assert netaudit.__version__ == "0.1.0"
