from kubernetes import client, config

def audit_rbac():
    results = {
        "cluster_roles": [],
        "role_bindings": [],
        "service_accounts": [],
        "issues": [],
        "score": 100
    }

    try:
        config.load_kube_config()
        rbac = client.RbacAuthorizationV1Api()
        core = client.CoreV1Api()

        # ClusterRole kontrolü
        cluster_roles = rbac.list_cluster_role().items
        for cr in cluster_roles:
            role_info = {
                "name": cr.metadata.name,
                "rules": [],
                "dangerous": False,
                "issues": []
            }

            if cr.rules:
                for rule in cr.rules:
                    resources = rule.resources or []
                    verbs = rule.verbs or []

                    # Wildcard kontrolü
                    if "*" in resources or "*" in verbs:
                        role_info["dangerous"] = True
                        role_info["issues"].append(f"Wildcard izin: resources={resources}, verbs={verbs}")
                        if not cr.metadata.name.startswith("system:"):
                            results["issues"].append(f"Tehlikeli ClusterRole: {cr.metadata.name} — wildcard izin")
                            results["score"] -= 15

                    # Kritik kaynak erişimi
                    critical_resources = ["secrets", "pods/exec", "nodes"]
                    for res in critical_resources:
                        if res in resources and ("*" in verbs or "get" in verbs):
                            if not cr.metadata.name.startswith("system:"):
                                role_info["issues"].append(f"Kritik kaynak erişimi: {res}")

                    role_info["rules"].append({
                        "resources": resources,
                        "verbs": verbs
                    })

            results["cluster_roles"].append(role_info)

        # ClusterRoleBinding kontrolü
        bindings = rbac.list_cluster_role_binding().items
        for binding in bindings:
            if not binding.subjects:
                continue

            for subject in binding.subjects:
                binding_info = {
                    "name": binding.metadata.name,
                    "role": binding.role_ref.name,
                    "subject": subject.name,
                    "subject_kind": subject.kind,
                    "issues": []
                }

                # ServiceAccount cluster-admin kontrolü
                if binding.role_ref.name == "cluster-admin" and subject.kind == "ServiceAccount":
                    binding_info["issues"].append("ServiceAccount'a cluster-admin yetkisi verilmiş!")
                    results["issues"].append(f"Tehlikeli binding: {subject.name} — cluster-admin")
                    results["score"] -= 25

                # Default namespace'deki default SA kontrolü
                if subject.name == "default" and subject.kind == "ServiceAccount":
                    binding_info["issues"].append("Default service account'a yetki verilmiş!")
                    results["score"] -= 10

                results["role_bindings"].append(binding_info)

        # Service Account kontrolü
        namespaces = core.list_namespace().items
        for ns in namespaces:
            ns_name = ns.metadata.name
            sas = core.list_namespaced_service_account(ns_name).items

            for sa in sas:
                sa_info = {
                    "name": sa.metadata.name,
                    "namespace": ns_name,
                    "automount": sa.automount_service_account_token,
                    "issues": []
                }

                # Otomatik token mount kontrolü
                if sa.automount_service_account_token is None or sa.automount_service_account_token:
                    if sa.metadata.name == "default":
                        sa_info["issues"].append("Default SA otomatik token mount aktif")
                        results["score"] -= 5

                results["service_accounts"].append(sa_info)

    except Exception as e:
        results["issues"].append(f"RBAC analizi hatası: {str(e)}")
        results["score"] = 0

    results["score"] = max(0, results["score"])
    return results