from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
import time

app = Flask(__name__)
CORS(app)

# Put your VirusTotal API key in the environment variable
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
            "error": "VirusTotal API key is not configured."
        }), 500

    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({
            "error": "No URL provided."
        }), 400

    url = data["url"].strip()

    if not url:
        return jsonify({
            "error": "URL cannot be empty."
        }), 400

    headers = {
        "x-apikey": API_KEY
    }

    try:
        # Send URL to VirusTotal
        response = requests.post(
            VT_SCAN_URL,
            headers=headers,
            data={"url": url},
            timeout=20
        )

        if response.status_code != 200:
            return jsonify({
                "error": "VirusTotal could not scan this URL.",
                "details": response.text
            }), response.status_code

        scan_data = response.json()

        analysis_id = scan_data["data"]["id"]

        # Check analysis status
        analysis = None

        for attempt in range(5):

            time.sleep(2)

            analysis_response = requests.get(
                VT_ANALYSIS_URL + analysis_id,
                headers=headers,
                timeout=20
            )

            if analysis_response.status_code != 200:
                return jsonify({
                    "error": "Could not retrieve VirusTotal analysis."
                }), analysis_response.status_code

            analysis = analysis_response.json()

            status = analysis["data"]["attributes"].get("status")

            if status == "completed":
                break

        attributes = analysis["data"]["attributes"]

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
        })

    except requests.exceptions.RequestException as e:

        return jsonify({
            "error": "Could not connect to VirusTotal.",
            "details": str(e)
        }), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)