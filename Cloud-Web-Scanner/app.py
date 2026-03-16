import os
from flask import Flask, render_template, request, jsonify
import urllib.request
import urllib.error
import re
import json

app = Flask(__name__)

@app.route('/')
def home():
    response = app.make_response(render_template('index.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json()
    if not data or 'ids' not in data:
        return jsonify({"error": "Invalid request"}), 400
    ids = data['ids']
    results = scan_extensions(ids)
    return jsonify(results)

def scan_extensions(ids):
    results = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Sec-Ch-Ua': '"Chromium";v="122", "Google Chrome";v="122"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1'
    }

    for ext_id in ids:
        ext_id = ext_id.strip()
        if not ext_id: continue
        url = f"https://crxplorer.com/extension/{ext_id}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                html = response.read().decode('utf-8')
                name_match = re.search(r'<h1[^>]*>([^<]+)</h1>', html, re.IGNORECASE)
                if not name_match: name_match = re.search(r'<h4[^>]*>([^<]+)</h4>', html, re.IGNORECASE)
                name = name_match.group(1).strip() if name_match else ext_id
                score = -1
                score_match = re.search(r'score of (\d+)/100', html, re.IGNORECASE)
                if score_match: score = int(score_match.group(1))
                else:
                    score_match = re.search(r'bg-(?:danger|warning|success|info)">\s*<h2[^>]*>(\d+)</h2>', html, re.IGNORECASE)
                    if score_match: score = int(score_match.group(1))
                level = 'Bilinmiyor'
                level_match = re.search(r'Risk:\s*<strong>([^<]+)</strong>', html, re.IGNORECASE)
                if level_match: level = level_match.group(1).strip()
                else:
                    level_match = re.search(r'\((\w+)\s*Risk\)', html, re.IGNORECASE)
                    if level_match: level = level_match.group(1)
                perm_count = '?'
                perm_match = re.search(r'scanned its (\d+) permissions', html, re.IGNORECASE)
                if perm_match: perm_count = perm_match.group(1)
                rec = 'DEGERLENDIR'
                if score == -1: rec = 'BILINMIYOR'
                elif score <= 40: rec = 'ENGELLE'
                elif score <= 70: rec = 'DIKKAT'
                elif score <= 80: rec = 'DEGERLENDIR'
                else: rec = 'WHITELIST'
                results.append({"Name": name, "ID": ext_id, "CRXScore": score, "CRXLevel": level, "Permissions": perm_count, "Recommendation": rec})
        except urllib.error.HTTPError as e:
            results.append({"Name": f"Hata ({e.code})", "ID": ext_id, "CRXScore": -1, "CRXLevel": "Bloklandi", "Permissions": "!", "Recommendation": "LOCAL KULLANIN"})
        except Exception as e:
            results.append({"Name": "Hata", "ID": ext_id, "CRXScore": -1, "CRXLevel": "Hata", "Permissions": "!", "Recommendation": "HATA"})
    return results

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
