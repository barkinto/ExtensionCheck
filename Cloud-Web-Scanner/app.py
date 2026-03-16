import os
from flask import Flask, render_template, request, jsonify
import urllib.request
import urllib.error
import re
import json

app = Flask(__name__)

@app.route('/')
def home():
    # Render.com will serve our safe ASCII HTML template directly
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
    # Using a typical Firefox browser user agent
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0'

    for ext_id in ids:
        ext_id = ext_id.strip()
        if not ext_id: continue
        
        req = urllib.request.Request(
            f"https://crxplorer.com/extension/{ext_id}",
            headers={'User-Agent': user_agent}
        )

        try:
            with urllib.request.urlopen(req) as response:
                html = response.read().decode('utf-8')
                
                # 1. Name
                name_match = re.search(r'<h4[^>]*>([^<]+)</h4>', html, re.IGNORECASE)
                name = name_match.group(1).strip() if name_match else ext_id

                # 2. Risk Score
                score_match = re.search(r'bg-(?:danger|warning|success|info)">\s*<h2[^>]*>(\d+)</h2>', html, re.IGNORECASE)
                crx_score = int(score_match.group(1)) if score_match else -1

                # 3. Risk Level
                level_match = re.search(r'Risk:\s*<strong>([^<]+)</strong>', html, re.IGNORECASE)
                crx_level = level_match.group(1).strip() if level_match else 'Bilinmiyor'

                # 4. Perm Count
                perm_count = '?'
                perm_block_match = re.search(r'<h4[^>]*>Permissions</h4>.*?(<div.*?)(?:<h4|$)', html, re.IGNORECASE | re.DOTALL)
                if perm_block_match:
                    perm_block = perm_block_match.group(1)
                    if 'None' in perm_block:
                        perm_count = '0'
                    else:
                        trs = re.findall(r'<tr[^>]*>', perm_block, re.IGNORECASE)
                        cnt = 0
                        for tr in trs:
                            if '<tr>' in tr or '<tr ' in tr: cnt += 1
                        perm_count = str(max(0, cnt - 1))

                recommendation = 'DEGERLENDIR'
                if crx_score == -1: recommendation = 'Bilinmiyor'
                elif crx_score <= 40: recommendation = 'ENGELLE'
                elif crx_score <= 70: recommendation = 'DIKKAT'
                elif crx_score <= 80: recommendation = 'DEGERLENDIR'
                else: recommendation = 'WHITELIST'

                results.append({
                    "Name": name,
                    "ID": ext_id,
                    "CRXScore": crx_score,
                    "CRXLevel": crx_level,
                    "Permissions": perm_count,
                    "Recommendation": recommendation
                })

        except urllib.error.HTTPError as e:
            pass # Ignore standard timeouts or 404s gracefully over Cloud APIs
        except Exception as e:
            pass

    return results

if __name__ == '__main__':
    # Cloud environments inject their specific port via OS environment
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
