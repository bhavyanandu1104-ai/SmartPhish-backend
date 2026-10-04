from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
import time

app = Flask(__name__)

# Allow your GitHub Pages frontend to communicate with the backend
CORS(app)

# VirusTotal API key is stored safely in Render Environment Variables
API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

VT_SCAN_URL = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/"


@app.route("/")
def home():
    return "SmartPhish Backend is Running!"


@app.route("/scan", methods=["POST"])
def scan_url():

    # Check API key
    if not API_KEY:
        return jsonify({
            "success": False,
            "error": "VirusTotal API key is not configured."
        }), 500

    # Get JSON data
    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify({
            "success": False,
            "error": "No URL provided."
        }), 400

    # Get URL
    url = str(data["url"]).strip()

    if not url:
        return jsonify({
            "success": False,
            "error": "URL cannot be empty."
        }), 400

    headers = {
        "x-apikey": API_KEY
    }

    try:

        # --------------------------------
        # STEP 1: Send URL to VirusTotal
        # --------------------------------

        response = requests.post(
            VT_SCAN_URL,
            headers=headers,
            data={"url": url},
            timeout=30
        )

        # If VirusTotal rejects the request,
        # print the REAL error in Render Logs.
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

        # Get analysis ID
        try:
            analysis_id = scan_data["data"]["id"]
        except (KeyError, TypeError):

            print("Unexpected VirusTotal response:", scan_data)

            return jsonify({
                "success": False,
                "error": "Invalid response received from VirusTotal.",
                "details": scan_data
            }), 500


        # --------------------------------
        # STEP 2: Check analysis status
        # --------------------------------

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
                    "VirusTotal Analysis Error:",
                    analysis_response.status_code,
                    analysis_response.text
                )

                return jsonify({
                    "success": False,
                    "error": "Could not retrieve VirusTotal analysis.",
                    "status_code": analysis_response.status_code,
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
                "VirusTotal Analysis Attempt:",
                attempt + 1,
                "Status:",
                status
            )

            if status == "completed":
                break


        # --------------------------------
        # STEP 3: Read VirusTotal results
        # --------------------------------

        if not analysis:

            return jsonify({
                "success": False,
                "error": "No analysis result received."
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

        status = attributes.get("status", "unknown")


        # --------------------------------
        # STEP 4: Return result to frontend
        # --------------------------------

        return jsonify({
            "success": True,
            "url": url,
            "status": status,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected
        }), 200


    except requests.exceptions.Timeout:

        print("VirusTotal request timed out.")

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

        print("Unexpected Server Error:", str(e))

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
