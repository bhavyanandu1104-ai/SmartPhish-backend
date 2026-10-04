from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
import time
from urllib.parse import urlparse

app = Flask(**name**)
CORS(app)

API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

VT_SCAN_URL = "https://www.virustotal.com/api/v3/urls"

@app.route("/")
def home():
return "SmartPhish Backend is Running!"

@app.route("/scan", methods=["POST"])
def scan():

```
try:
    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify({
            "success": False,
            "error": "No URL received."
        }), 400

    url = str(data["url"]).strip()

    print("URL received from frontend:", repr(url))

    # Add HTTPS if the URL has no protocol
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print("URL sent to VirusTotal:", repr(url))

    # Validate URL
    parsed = urlparse(url)

    if not parsed.netloc:
        return jsonify({
            "success": False,
            "error": "Invalid URL."
        }), 400

    if not API_KEY:
        return jsonify({
            "success": False,
            "error": "VirusTotal API key is not configured."
        }), 500

    headers = {
        "x-apikey": API_KEY
    }

    # Send URL to VirusTotal
    response = requests.post(
        VT_SCAN_URL,
        headers=headers,
        data={"url": url},
        timeout=30
    )

    print("VirusTotal response status:", response.status_code)
    print("VirusTotal response:", response.text)

    if response.status_code not in [200, 201]:
        return jsonify({
            "success": False,
            "error": "VirusTotal rejected the scan request.",
            "details": response.text
        }), response.status_code

    result = response.json()

    analysis_id = result.get("data", {}).get("id")

    if not analysis_id:
        return jsonify({
            "success": False,
            "error": "VirusTotal did not return an analysis ID."
        }), 500

    analysis_url = (
        "https://www.virustotal.com/api/v3/analyses/"
        + analysis_id
    )

    # Wait for VirusTotal analysis
    # 20 checks × 3 seconds = up to 60 seconds
    for attempt in range(20):

        time.sleep(3)

        analysis_response = requests.get(
            analysis_url,
            headers=headers,
            timeout=15
        )

        print(
            "Analysis check",
            attempt + 1,
            "status:",
            analysis_response.status_code
        )

        if analysis_response.status_code != 200:
            continue

        analysis_data = analysis_response.json()

        status = (
            analysis_data
            .get("data", {})
            .get("attributes", {})
            .get("status")
        )

        print("VirusTotal analysis status:", status)

        if status == "completed":

            stats = (
                analysis_data
                .get("data", {})
                .get("attributes", {})
                .get("stats", {})
            )

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            print("Malicious:", malicious)
            print("Suspicious:", suspicious)
            print("Harmless:", harmless)
            print("Undetected:", undetected)

            return jsonify({
                "success": True,
                "url": url,
                "status": "completed",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected
            })

    # VirusTotal did not finish within 60 seconds
    return jsonify({
        "success": False,
        "error": "VirusTotal analysis is taking longer than expected.",
        "details": "Please try scanning the URL again."
    }), 408

except requests.exceptions.Timeout:

    return jsonify({
        "success": False,
        "error": "VirusTotal request timed
```
