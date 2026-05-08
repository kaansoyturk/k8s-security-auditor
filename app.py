from flask import Flask, render_template, jsonify
from modules.rbac_auditor import audit_rbac
from modules.pod_auditor import audit_pods
from modules.network_auditor import audit_network
from modules.secret_auditor import audit_secrets
from modules.score_engine import calculate_score

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan")
def scan():
    print("\n🔍 Kubernetes Güvenlik Denetimi Başlıyor...")

    try:
        print("  [1/4] RBAC analizi...")
        rbac_results = audit_rbac()

        print("  [2/4] Pod analizi...")
        pod_results = audit_pods()

        print("  [3/4] Network analizi...")
        network_results = audit_network()

        print("  [4/4] Secret analizi...")
        secret_results = audit_secrets()

        print("  Skor hesaplanıyor...")
        score = calculate_score(rbac_results, pod_results, network_results, secret_results)

        print(f"  ✅ Tamamlandı — Skor: {score['total_score']}")

        return jsonify({
            "score": score,
            "rbac": rbac_results,
            "pods": pod_results,
            "network": network_results,
            "secrets": secret_results
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5055)