from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import io
import os

import requests
import streamlit as st
import whois
from PIL import Image


def _classify_content(content: str) -> str:
    """Classify decoded QR content."""
    lowered = content.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return "url"
    if lowered.startswith("mailto:") or ("@" in content and "." in content):
        return "email"
    if lowered.startswith("tel:"):
        return "phone"
    if lowered.startswith("sms:"):
        return "sms"
    return "text"


def _decode_with_pyzbar(image: Image.Image) -> Optional[Dict[str, Any]]:
    """Decode QR/barcode content using pyzbar if available."""
    try:
        from pyzbar.pyzbar import decode  # local import to avoid zbar import failure at module load
    except Exception:
        return None
    decoded = decode(image)
    if not decoded:
        return None
    first = decoded[0]
    return {
        "content": first.data.decode("utf-8", errors="ignore"),
        "symbology": first.type,
    }


def _decode_with_opencv(image: Image.Image) -> Optional[Dict[str, Any]]:
    """Decode QR content using OpenCV as a fallback."""
    try:
        import cv2
        import numpy as np
    except Exception:
        return None

    rgb = image.convert("RGB")
    frame = cv2.cvtColor(np.array(rgb), cv2.COLOR_RGB2BGR)
    detector = cv2.QRCodeDetector()
    content, _, _ = detector.detectAndDecode(frame)
    if not content:
        return None
    return {"content": content, "symbology": "QRCode"}


def _get_secret(name: str) -> Optional[str]:
    """Fetch a secret from Streamlit, falling back to environment variables."""
    try:
        value = st.secrets.get(name)
    except Exception:  # noqa: BLE001 - allow Streamlit-less contexts
        value = None
    if value:
        return str(value)
    return os.getenv(name)


def decode_qr(image_bytes: bytes) -> Dict[str, Any]:
    """Decode QR or barcode content from an image."""
    try:
        image = Image.open(io.BytesIO(image_bytes))
        decoded = _decode_with_pyzbar(image)
        if not decoded:
            decoded = _decode_with_opencv(image)
        if not decoded:
            return {
                "success": False,
                "data": {},
                "error": "No QR code detected (pyzbar unavailable and OpenCV decode failed)",
            }

        content = decoded["content"]
        symbology = decoded["symbology"]
        content_type = _classify_content(content)

        return {
            "success": True,
            "data": {"content": content, "type": content_type, "symbology": symbology},
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001 - return structured error
        return {"success": False, "data": {}, "error": str(exc)}


def _follow_redirects(url: str, max_hops: int = 10) -> Tuple[List[Dict[str, Any]], str]:
    """Follow redirects manually and return the redirect chain."""
    chain: List[Dict[str, Any]] = []
    current_url = url
    for _ in range(max_hops):
        response = requests.get(current_url, allow_redirects=False, timeout=10)
        chain.append({"url": current_url, "status_code": response.status_code})
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            if not location:
                break
            current_url = urljoin(current_url, location)
            continue
        break
    return chain, current_url


def _get_domain_age_days(domain: str) -> Optional[int]:
    """Get domain age in days from WHOIS data."""
    info = whois.whois(domain)
    creation_date = info.creation_date
    if isinstance(creation_date, list):
        creation_date = min(creation_date)
    if not isinstance(creation_date, datetime):
        return None
    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=timezone.utc)
    else:
        creation_date = creation_date.astimezone(timezone.utc)
    return (datetime.now(timezone.utc) - creation_date).days


def _virustotal_scan(url: str, api_key: str) -> Dict[str, Any]:
    """Submit URL to VirusTotal and return the analysis stats."""
    headers = {"x-apikey": api_key}
    submit = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=15)
    submit.raise_for_status()
    submit_data = submit.json()
    analysis_id = submit_data.get("data", {}).get("id")
    if not analysis_id:
        raise RuntimeError("VirusTotal submission failed")

    analysis = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers,
        timeout=15,
    )
    analysis.raise_for_status()
    analysis_data = analysis.json()
    stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(value) for value in stats.values()) if stats else 0

    return {"malicious": malicious, "suspicious": suspicious, "total": total}


def _urlscan_submit(url: str, api_key: str) -> Dict[str, Any]:
    """Submit URL to URLScan.io and return the scan result metadata."""
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json={"url": url}, timeout=20)
    response.raise_for_status()
    payload = response.json()
    return {"uuid": payload.get("uuid"), "result_url": payload.get("result")}


def analyze_url(url: str) -> Dict[str, Any]:
    """Analyze a URL for redirects, domain age, and threat intelligence."""
    errors: List[str] = []
    data: Dict[str, Any] = {}
    try:
        normalized = url.strip()
        if not normalized.startswith("http://") and not normalized.startswith("https://"):
            normalized = f"http://{normalized}"

        redirect_chain, final_url = _follow_redirects(normalized)
        data["redirect_chain"] = redirect_chain
        data["final_url"] = final_url

        original_domain = urlparse(normalized).netloc
        final_domain = urlparse(final_url).netloc

        domain_age_days = None
        try:
            domain_age_days = _get_domain_age_days(final_domain or original_domain)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"WHOIS error: {exc}")
        data["domain_age_days"] = domain_age_days

        vt_result = {"malicious": 0, "suspicious": 0, "total": 0}
        vt_key = _get_secret("VT_API_KEY")
        if vt_key:
            try:
                vt_result = _virustotal_scan(final_url, vt_key)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"VirusTotal error: {exc}")
        else:
            errors.append("VirusTotal API key missing")
        data["vt_result"] = vt_result

        urlscan_result = {"uuid": None, "result_url": None}
        urlscan_key = _get_secret("URLSCAN_API_KEY")
        if urlscan_key:
            try:
                urlscan_result = _urlscan_submit(final_url, urlscan_key)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"URLScan error: {exc}")
        else:
            errors.append("URLScan API key missing")
        data["urlscan_result"] = urlscan_result

        risk_score = 0
        redirect_hops = max(0, len(redirect_chain) - 1)
        if vt_result.get("malicious", 0) > 0:
            risk_score += 30
        if vt_result.get("suspicious", 0) > 2:
            risk_score += 20
        if redirect_hops > 3:
            risk_score += 20
        if domain_age_days is not None and domain_age_days < 90:
            risk_score += 15
        if final_domain and original_domain and final_domain != original_domain:
            risk_score += 15

        if risk_score <= 25:
            risk_level = "LOW"
        elif risk_score <= 50:
            risk_level = "MEDIUM"
        elif risk_score <= 75:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        data["risk_score"] = risk_score
        data["risk_level"] = risk_level

        return {
            "success": True,
            "data": data,
            "error": "; ".join(errors) if errors else None,
        }
    except Exception as exc:  # noqa: BLE001 - return structured error
        return {"success": False, "data": {}, "error": str(exc)}
