from kubernetes import client, config
import base64

SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "key", "token",
    "api_key", "apikey", "auth", "credential", "private",
    "aws", "azure", "gcp", "database", "db_pass"
]

def audit_secrets():
    results = {
        "secrets": [],
        "issues": [],
        "score": 100
    }

    try:
        config.load_kube_config()
        core = client.CoreV1Api()

        secrets = core.list_secret_for_all_namespaces().items

        for secret in secrets:
            secret_info = {
                "name": secret.metadata.name,
                "namespace": secret.metadata.namespace,
                "type": secret.type,
                "data_keys": [],
                "issues": []
            }

            # Secret veri anahtarları
            if secret.data:
                secret_info["data_keys"] = list(secret.data.keys())

                # Hassas anahtar kontrolü
                for key in secret.data.keys():
                    key_lower = key.lower()
                    for keyword in SENSITIVE_KEYWORDS:
                        if keyword in key_lower:
                            secret_info["issues"].append(f"Hassas veri anahtarı: {key}")
                            break

                # Base64 decode ile boş değer kontrolü
                for key, value in secret.data.items():
                    try:
                        decoded = base64.b64decode(value).decode("utf-8")
                        if decoded in ["", "null", "none", "undefined"]:
                            secret_info["issues"].append(f"Boş secret değeri: {key}")
                            results["score"] -= 5
                    except:
                        pass

            # Default namespace'deki secret kontrolü
            if secret.metadata.namespace == "default":
                secret_info["issues"].append("Default namespace'de secret")
                results["score"] -= 5

            # Service account token kontrolü
            if secret.type == "kubernetes.io/service-account-token":
                secret_info["issues"].append("Service account token secret")

            # Docker registry credential kontrolü
            if secret.type == "kubernetes.io/dockerconfigjson":
                secret_info["issues"].append("Docker registry credential secret — güvenli saklandığından emin ol")

            results["secrets"].append(secret_info)

        # Toplam secret sayısı kontrolü
        if len(secrets) > 50:
            results["issues"].append(f"Çok fazla secret: {len(secrets)} — temizlik önerilir")
            results["score"] -= 5

    except Exception as e:
        results["issues"].append(f"Secret analizi hatası: {str(e)}")
        results["score"] = 0

    results["score"] = max(0, results["score"])
    return results
