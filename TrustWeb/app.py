from flask import Flask, render_template, request, redirect, url_for, flash
import os
import json
import sys

# =========================
# ADD PATHS
# =========================
sys.path.append(r"E:\trust-auditor")
sys.path.append(r"E:\trust-auditor\integration")

# =========================
# IMPORTS
# =========================
from standalone_audit import run_and_return
import hybrid_fusion

# =========================
# APP CONFIG
# =========================
app = Flask(__name__)
app.secret_key = "trust_auditor_secure_key"

# Initialize DB safely
hybrid_fusion.init_db()


# =========================
# 🏠 LANDING PAGE
# =========================
@app.route('/')
def home():
    return render_template('home.html')


# =========================
# 📊 DASHBOARD
# =========================
@app.route('/dashboard')
def dashboard():

    results = []

    if os.path.exists(hybrid_fusion.OUTPUT_FILE):
        try:
            with open(hybrid_fusion.OUTPUT_FILE, 'r') as f:
                data = json.load(f)

                if isinstance(data, list):
                    results = data

        except Exception as e:
            print("❌ ERROR loading JSON:", e)

    return render_template('dashboard.html', results=results)  # ← FIXED


# =========================
# 🧪 DEMO MODE (SAFE)
# =========================
@app.route('/audit', methods=['POST'])
def run_new_audit():

    domain = request.form.get('domain')

    if domain:
        flash(f"Demo Mode: Showing precomputed results for {domain}")

    return redirect(url_for('dashboard'))


# =========================
# 📄 REPORT PAGE
# =========================
@app.route('/report/<domain>')
def report(domain):

    if not os.path.exists(hybrid_fusion.OUTPUT_FILE):
        return "No data found", 404

    with open(hybrid_fusion.OUTPUT_FILE, 'r') as f:
        data = json.load(f)

    domain_data = next(
        (item for item in data if item.get("domain") == domain),
        None
    )

    if not domain_data:
        return "Domain not found", 404

    return render_template('results.html', data=domain_data)  # ← FIXED


# =========================
# ⚡ LIVE AUDIT (MAIN FIX)
# =========================
@app.route('/live', methods=['GET', 'POST'])
def live_audit():

    result = None

    if request.method == 'POST':

        domain = request.form.get('domain')

        if domain:

            print(f"\n🚀 Running FULL pipeline for: {domain}")

            try:
                # 🔥 RUN FULL PIPELINE (SYNC)
                result = run_and_return(domain)

                if result:
                    print("✅ RESULT GENERATED")
                    flash(f"✅ Audit completed for {domain}")
                else:
                    print("⚠️ NO RESULT RETURNED")
                    flash("⚠️ Pipeline ran but no result generated")

            except Exception as e:
                print("❌ PIPELINE ERROR:", e)
                flash("❌ Error running pipeline")

    return render_template('live.html', result=result)


# =========================
# 🚀 RUN SERVER
# =========================
if __name__ == '__main__':
    app.run(debug=True, port=5000)
