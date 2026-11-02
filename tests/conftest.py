"""Integration tests use the bundled benchmark data."""
import os
from pathlib import Path
import pytest


def research_root():
    return Path(os.environ.get('VULINSTRUCT_TEST_DATA_ROOT', Path(__file__).resolve().parents[1]))


def pytest_configure(config):
    config.addinivalue_line('markers', 'research: requires the bundled data directory')


def pytest_collection_modifyitems(config, items):
    if not (research_root() / 'data/MANIFEST.json').exists():
        marker = pytest.mark.skip(reason='Bundled data is missing; use the complete release archive')
        for item in items:
            if 'research' in item.keywords:
                item.add_marker(marker)
