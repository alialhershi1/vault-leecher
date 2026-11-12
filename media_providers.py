"""Provider adapters for openly licensed media catalogues.

Every provider returns the same small schema so the UI is independent of
catalogue implementation. Add future providers by implementing search() and
item(), then registering the adapter in PROVIDERS.
"""
import re
from urllib.parse import quote
import requests

CC_RE = re.compile(
    r"^https?://creativecommons[.]org/licenses/(?:by|by-sa|by-nc|by-nc-sa|by-nd|by-nc-nd)/[0-9.]+/?$",
    re.I,
)
VIDEO_EXTS = (".mp4", ".mkv", ".webm", ".mov", ".m4v", ".avi", ".ogv")
HEADERS = {"User-Agent": "VaultMediaWorker/1.0"}


class ProviderError(ValueError):
    pass


class MediaProvider:
    id = "base"
    name = "Base provider"
    enabled = False

    def search(self, query):
        raise NotImplementedError

    def item(self, identifier):
        raise NotImplementedError


class InternetArchiveCC(MediaProvider):
    id = "archive_cc"
    name = "Internet Archive · Creative Commons"
    enabled = True

    @staticmethod
    def _valid_id(identifier):
        identifier = str(identifier or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,180}", identifier):
            raise ProviderError("Invalid archive item identifier.")
        return identifier

    @staticmethod
    def _licensed(identifier):
        response = requests.get(
            "https://archive.org/metadata/" + quote(identifier, safe="._-"),
            timeout=25, headers=HEADERS,
        )
        response.raise_for_status()
        data = response.json()
        metadata = data.get("metadata") or {}
        license_url = metadata.get("licenseurl") or metadata.get("license_url") or ""
        if not CC_RE.match(str(license_url).strip()):
            raise ProviderError("This item does not declare a supported Creative Commons licence.")
        if str(metadata.get("access-restricted-item", "")).lower() in ("true", "1", "yes"):
            raise ProviderError("This archive item is access restricted.")
        return data, metadata, license_url

    def search(self, query):
        terms = re.findall(r"[A-Za-z0-9]+", str(query or "")[:100])
        if not terms:
            return []
        expression = "mediatype:movies AND licenseurl:* AND title:(" + " AND ".join(terms) + ")"
        response = requests.get(
            "https://archive.org/advancedsearch.php",
            params={
                "q": expression,
                "fl[]": ["identifier", "title", "year", "licenseurl", "creator", "description"],
                "rows": 30, "page": 1, "output": "json", "sort[]": "downloads desc",
            },
            timeout=25, headers=HEADERS,
        )
        response.raise_for_status()
        docs = response.json().get("response", {}).get("docs", [])
        results = []
        for doc in docs:
            license_url = str(doc.get("licenseurl") or "")
            identifier = str(doc.get("identifier") or "")
            if not CC_RE.match(license_url) or not re.fullmatch(r"[A-Za-z0-9._-]{1,180}", identifier):
                continue
            creator = doc.get("creator") or ""
            description = doc.get("description") or ""
            if isinstance(creator, list):
                creator = ", ".join(str(x) for x in creator[:2])
            if isinstance(description, list):
                description = " ".join(str(x) for x in description[:2])
            results.append({
                "id": identifier, "provider": self.id,
                "title": str(doc.get("title") or identifier)[:180],
                "year": str(doc.get("year") or "")[:12],
                "creator": str(creator)[:120], "description": str(description)[:260],
                "license": license_url,
                "poster": "https://archive.org/services/img/" + identifier,
                "page": "https://archive.org/details/" + identifier,
            })
        return results[:24]

    def item(self, identifier):
        identifier = self._valid_id(identifier)
        data, metadata, license_url = self._licensed(identifier)
        files = []
        for entry in data.get("files") or []:
            filename = str(entry.get("name") or "")
            if not filename.lower().endswith(VIDEO_EXTS):
                continue
            try:
                size = int(entry.get("size") or 0)
            except (TypeError, ValueError):
                size = 0
            if size <= 0:
                continue
            files.append({
                "name": filename, "size": size, "kind": "video",
                "format": str(entry.get("format") or "")[:80],
            })
        files.sort(key=lambda x: -x["size"])
        creator = metadata.get("creator") or ""
        description = metadata.get("description") or ""
        if isinstance(creator, list):
            creator = ", ".join(str(x) for x in creator[:3])
        if isinstance(description, list):
            description = " ".join(str(x) for x in description[:3])
        return {
            "item": {
                "id": identifier, "provider": self.id,
                "title": str(metadata.get("title") or identifier)[:180],
                "year": str(metadata.get("year") or metadata.get("date") or "")[:20],
                "creator": str(creator)[:160], "description": str(description)[:1800],
                "license": license_url, "page": "https://archive.org/details/" + identifier,
            },
            "files": files,
        }


# Source 2 is deliberately a disabled slot until an authorized catalogue is selected.
PROVIDERS = {
    "archive_cc": InternetArchiveCC(),
}


def public_providers():
    return [
        {"id": provider.id, "name": provider.name, "enabled": provider.enabled}
        for provider in PROVIDERS.values()
    ] + [{"id": "source_2", "name": "Source 2 · reserved", "enabled": False}]


def get_provider(provider_id):
    provider = PROVIDERS.get(str(provider_id or ""))
    if not provider or not provider.enabled:
        raise ProviderError("This provider is not enabled.")
    return provider
