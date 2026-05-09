def calculate_score(rbac_results, pod_results, network_results, secret_results, cis_results=None):
    scores = {
        "rbac": rbac_results.get("score", 0),
        "pods": pod_results.get("score", 0),
        "network": network_results.get("score", 0),
        "secrets": secret_results.get("score", 0),
        "cis": cis_results.get("score", 0) if cis_results else 100
    }

    weights = {
        "rbac": 0.25,
        "pods": 0.25,
        "network": 0.20,
        "secrets": 0.15,
        "cis": 0.15
    }

    total_score = sum(scores[k] * weights[k] for k in scores)
    total_score = round(total_score)

    if total_score >= 80:
        grade = "A"
        level = "Güvenli"
        color = "green"
    elif total_score >= 60:
        grade = "B"
        level = "Orta"
        color = "yellow"
    elif total_score >= 40:
        grade = "C"
        level = "Riskli"
        color = "orange"
    else:
        grade = "D"
        level = "Tehlikeli"
        color = "red"

    all_issues = []
    all_issues.extend(rbac_results.get("issues", []))
    all_issues.extend(pod_results.get("issues", []))
    all_issues.extend(network_results.get("issues", []))
    all_issues.extend(secret_results.get("issues", []))

    # CIS failed check'lerini ekle
    if cis_results:
        for check in cis_results.get("checks", []):
            if not check["passed"]:
                all_issues.append(f"CIS {check['id']}: {check['title']}")

    return {
        "total_score": total_score,
        "grade": grade,
        "level": level,
        "color": color,
        "scores": scores,
        "all_issues": all_issues,
        "issue_count": len(all_issues),
        "pod_count": len(pod_results.get("pods", [])),
        "namespace_count": len(pod_results.get("namespaces", [])),
        "secret_count": len(secret_results.get("secrets", [])),
        "policy_count": len(network_results.get("network_policies", [])),
        "cis_passed": cis_results.get("passed", 0) if cis_results else 0,
        "cis_failed": cis_results.get("failed", 0) if cis_results else 0
    }