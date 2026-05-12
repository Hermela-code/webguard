from flask import Flask, render_template, request, jsonify
from scanner import run_full_scan
import datetime

app = Flask(__name__)

# Basic configuration
app.config['SECRET_KEY'] = 'webguard_dev_key_123'

@app.route('/')
def index():
    """Renders the Home Page where users input a URL."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Handles the scan request and returns results."""
    target_url = request.form.get('url')
    
    if not target_url:
        return render_template('index.html', error="Please provide a valid URL.")

    # Validate URL basic structure
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    try:
        # Run the scan using our engine
        print(f"[*] Starting scan for: {target_url}")
        scan_results = run_full_scan(target_url)
        
        # Capture current time for the report
        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return render_template('dashboard.html', 
                               results=scan_results, 
                               url=target_url, 
                               date=scan_date)
    
    except Exception as e:
        print(f"[!] Scan Error: {str(e)}")
        return render_template('index.html', error=f"An error occurred during scanning: {str(e)}")

# Optional API route for future enhancements (e.g., real-time dashboard)
@app.route('/api/scan', methods=['POST'])
def api_scan():
    target_url = request.json.get('url')
    if not target_url:
        return jsonify({"error": "No URL provided"}), 400
    results = run_full_scan(target_url)
    return jsonify(results)

if __name__ == '__main__':
    # Running on 0.0.0.0 so it's accessible in development
    # Using port 5000 by default
    app.run(debug=True, host='0.0.0.0', port=5000)