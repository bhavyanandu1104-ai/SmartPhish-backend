from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
import time
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

VT_SCAN_URL = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/"


@app.route("/")
def home():
    return "SmartPhish Backend is Running!"


@app.route("/scan", methods=["POST"])
def scan_url():

    if not API_KEY:
        return jsonify({
            "success": False,
            "error": "VirusTotal API key is not configured."
        }), 500

    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify({
            "success": False,
            "error": "No URL provided."
        }), 400

    url = str(data["url"]).strip()
    print("URL received from frontend:", repr(url))

    if not url:
        return jsonify({
            "success": False,
            "error": "URL cannot be empty."
        }), 400

    # Add HTTPS if the user did not enter a protocol
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Validate URL format
    try:
        parsed = urlparse(url)

        if not parsed.scheme or not parsed.netloc:
            return jsonify({
                "success": False,
                "error": "Please enter a valid website URL."
            }), 400

    except Exception:
        return jsonify({
            "success": False,
            "error": "Invalid URL format."
        }), 400

    headers = {
        "x-apikey": API_KEY,
        "Accept": "application/json"
    }

    try:

        # Send URL to VirusTotal
        response = requests.post(
            VT_SCAN_URL,
            headers=headers,
            data={"url": url},
            timeout=30
        )

        if response.status_code not in [200, 201]:

            print(
                "VirusTotal Error:",
                response.status_code,
                response.text
            )

            return jsonify({
                "success": False,
                "error": "VirusTotal could not scan this URL.",
                "status_code": response.status_code,
                "details": response.text
            }), response.status_code

        scan_data = response.json()

        analysis_id = scan_data["data"]["id"]

        print("VirusTotal Analysis ID:", analysis_id)

        # Wait for VirusTotal analysis
        analysis = None

        for attempt in range(10):

            time.sleep(2)

            analysis_response = requests.get(
                VT_ANALYSIS_URL + analysis_id,
                headers=headers,
                timeout=30
            )

            if analysis_response.status_code != 200:

                print(
                    "Analysis Error:",
                    analysis_response.status_code,
                    analysis_response.text
                )

                return jsonify({
                    "success": False,
                    "error": "Could not retrieve VirusTotal analysis.",
                    "details": analysis_response.text
                }), analysis_response.status_code

            analysis = analysis_response.json()

            status = (
                analysis
                .get("data", {})
                .get("attributes", {})
                .get("status")
            )

            print(
                "Analysis attempt:",
                attempt + 1,
                "Status:",
                status
            )

            if status == "completed":
                break

        if not analysis:

            return jsonify({
                "success": False,
                "error": "No VirusTotal analysis received."
            }), 500

        attributes = (
            analysis
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get("stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        return jsonify({
            "success": True,
            "url": url,
            "status": attributes.get("status"),
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected
        }), 200

    except requests.exceptions.Timeout:

        return jsonify({
            "success": False,
            "error": "VirusTotal request timed out."
        }), 504

    except requests.exceptions.RequestException as e:

        print("Connection Error:", str(e))

        return jsonify({
            "success": False,
            "error": "Could not connect to VirusTotal.",
            "details": str(e)
        }), 500

    except Exception as e:

        print("Unexpected Error:", str(e))

        return jsonify({
            "success": False,
            "error": "Unexpected server error.",
            "details": str(e)
        }), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
