from flask import Flask, request, render_template, jsonify
import shodan
import requests

app = Flask(__name__)

SHODAN_API_KEY = "sP0jZedwmwja7nRupTLHFjsRW17fOSH0"
api = shodan.Shodan(SHODAN_API_KEY)

@app.route('/url', methods=['POST', 'GET'])
def url():
    if request.method == 'GET':
        return render_template("url.html")
    if request.method == 'POST':
        ip_address = request.form.get('url')
        if not ip_address:
            return "<html><body><h1>Invalid IP address</h1></body></html>"
        else:
            url = f'https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}'
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()

                # Extract ports and locations
                ports_info = [
                    {
                        "port": entry.get('port'),
                        "location": entry.get('location')
                    }
                    for entry in data['data']
                    if entry.get('port') and entry.get('location')
                ]

                # Extract SSL details
                ssl_info = []
                for entry in data['data']:
                    if 'ssl' in entry:
                        ssl_details = entry['ssl']
                        chain = ssl_details.get('chain', [])
                        for cert in chain:
                            ssl_info.append({
                                "port": entry.get('port'),
                                "subject": cert.get('subject'),
                                "issuer": cert.get('issuer'),
                                "validity": cert.get('validity'),
                                "fingerprint_sha1": cert['fingerprint'].get('sha1'),
                                "fingerprint_sha256": cert['fingerprint'].get('sha256'),
                                "cipher": ssl_details.get('cipher'),
                                "versions": ', '.join(ssl_details.get('versions', []))
                            })

                return render_template("url.html", ports_info=ports_info, ssl_info=ssl_info)
            else:
                return f"Error: Unable to fetch data for IP {ip_address}. HTTP Status Code: {response.status_code}"

if __name__ == '__main__':
    app.run(debug=True)
