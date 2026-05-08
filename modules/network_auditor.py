from kubernetes import client, config

def audit_network():
    results = {
        "network_policies": [],
        "services": [],
        "ingresses": [],
        "issues": [],
        "score": 100
    }

    try:
        config.load_kube_config()
        core = client.CoreV1Api()
        networking = client.NetworkingV1Api()

        # Namespace listesi
        namespaces = core.list_namespace().items

        # Network Policy kontrolü
        for ns in namespaces:
            ns_name = ns.metadata.name
            policies = networking.list_namespaced_network_policy(ns_name).items

            if not policies:
                if ns_name not in ["kube-system", "kube-public", "kube-node-lease"]:
                    results["issues"].append(f"Network Policy yok: {ns_name}")
                    results["score"] -= 10

            for policy in policies:
                policy_info = {
                    "name": policy.metadata.name,
                    "namespace": ns_name,
                    "pod_selector": str(policy.spec.pod_selector),
                    "ingress_rules": len(policy.spec.ingress or []),
                    "egress_rules": len(policy.spec.egress or []),
                    "issues": []
                }
                results["network_policies"].append(policy_info)

        # Service kontrolü
        services = core.list_service_for_all_namespaces().items
        for svc in services:
            svc_info = {
                "name": svc.metadata.name,
                "namespace": svc.metadata.namespace,
                "type": svc.spec.type,
                "ports": [],
                "issues": []
            }

            # NodePort ve LoadBalancer kontrolü
            if svc.spec.type == "NodePort":
                svc_info["issues"].append("NodePort servisi — dışarıya açık olabilir")
                results["score"] -= 5

            if svc.spec.type == "LoadBalancer":
                svc_info["issues"].append("LoadBalancer servisi — internete açık!")
                results["issues"].append(f"LoadBalancer servisi: {svc.metadata.name}")
                results["score"] -= 10

            # Port bilgileri
            if svc.spec.ports:
                for port in svc.spec.ports:
                    svc_info["ports"].append({
                        "port": port.port,
                        "protocol": port.protocol
                    })

                    # Tehlikeli portlar
                    if port.port in [22, 3306, 5432, 27017, 6379]:
                        svc_info["issues"].append(f"Tehlikeli port servisi: {port.port}")
                        results["issues"].append(f"Tehlikeli port: {svc.metadata.name} — {port.port}")
                        results["score"] -= 15

            results["services"].append(svc_info)

        # Ingress kontrolü
        try:
            ingresses = networking.list_ingress_for_all_namespaces().items
            for ing in ingresses:
                ing_info = {
                    "name": ing.metadata.name,
                    "namespace": ing.metadata.namespace,
                    "tls": bool(ing.spec.tls),
                    "issues": []
                }

                # TLS kontrolü
                if not ing.spec.tls:
                    ing_info["issues"].append("TLS/HTTPS aktif değil!")
                    results["issues"].append(f"TLS'siz Ingress: {ing.metadata.name}")
                    results["score"] -= 15

                results["ingresses"].append(ing_info)
        except:
            pass

    except Exception as e:
        results["issues"].append(f"Network analizi hatası: {str(e)}")
        results["score"] = 0

    results["score"] = max(0, results["score"])
    return results