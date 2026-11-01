"""Fetch package metadata from the npm registry."""

import requests


NPM_REGISTRY = "https://registry.npmjs.org"


def get_package_metadata(package: str, version: str) -> dict:
    """Return metadata for a specific npm package version."""

    url = f"{NPM_REGISTRY}/{package}/{version}"

    response = requests.get(url, timeout=15)
    response.raise_for_status()

    return response.json()
