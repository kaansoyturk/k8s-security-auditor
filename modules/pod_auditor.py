from kubernetes import client, config

def audit_pods():
    results = {
        "pods": [],
        "namespaces": [],
        "issues": [],
        "score": 100
    }

    try:
        config.load_kube_config()
        core = client.CoreV1Api()

        # Namespace listesi
        namespaces = core.list_namespace().items
        results["namespaces"] = [ns.metadata.name for ns in namespaces]

        # Pod listesi
        pods = core.list_pod_for_all_namespaces().items

        for pod in pods:
            pod_info = {
                "name": pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "status": pod.status.phase,
                "issues": [],
                "score": 100
            }

            spec = pod.spec

            # Host network kontrolü
            if spec.host_network:
                pod_info["issues"].append("Host network kullanıyor!")
                results["issues"].append(f"Host network pod: {pod.metadata.name}")
                pod_info["score"] -= 30
                results["score"] -= 5

            # Host PID kontrolü
            if spec.host_pid:
                pod_info["issues"].append("Host PID namespace paylaşıyor!")
                results["issues"].append(f"Host PID pod: {pod.metadata.name}")
                pod_info["score"] -= 25
                results["score"] -= 5

            # Host IPC kontrolü
            if spec.host_ipc:
                pod_info["issues"].append("Host IPC namespace paylaşıyor!")
                pod_info["score"] -= 20

            # Container güvenlik kontrolleri
            containers = spec.containers or []
            for container in containers:
                sc = container.security_context

                if sc:
                    if sc.privileged:
                        pod_info["issues"].append(f"Privileged container: {container.name}")
                        results["issues"].append(f"Privileged container: {pod.metadata.name}/{container.name}")
                        pod_info["score"] -= 35
                        results["score"] -= 10

                    if sc.run_as_user == 0:
                        pod_info["issues"].append(f"Root kullanıcı: {container.name}")
                        pod_info["score"] -= 20

                    if sc.allow_privilege_escalation:
                        pod_info["issues"].append(f"Privilege escalation izinli: {container.name}")
                        pod_info["score"] -= 15

                    if not sc.read_only_root_filesystem:
                        pod_info["issues"].append(f"Read-only root filesystem kapalı: {container.name}")
                        pod_info["score"] -= 10
                else:
                    pod_info["issues"].append(f"Security context tanımsız: {container.name}")
                    pod_info["score"] -= 15

                # Resource limits kontrolü
                if not container.resources or not container.resources.limits:
                    pod_info["issues"].append(f"Resource limit yok: {container.name}")
                    pod_info["score"] -= 10

            pod_info["score"] = max(0, pod_info["score"])
            results["pods"].append(pod_info)

    except Exception as e:
        results["issues"].append(f"Pod analizi hatası: {str(e)}")
        results["score"] = 0

    results["score"] = max(0, results["score"])
    return results