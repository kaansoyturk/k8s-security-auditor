from kubernetes import client, config

def run_cis_benchmark():
    """CIS Kubernetes Benchmark v1.8 kontrolleri"""
    results = {
        "checks": [],
        "passed": 0,
        "failed": 0,
        "score": 100
    }

    try:
        config.load_kube_config()
        core = client.CoreV1Api()
        rbac = client.RbacAuthorizationV1Api()
        apps = client.AppsV1Api()

        # 1. API Server güvenliği
        _check_anonymous_auth(results)
        _check_audit_logging(results, core)
        _check_api_server_tls(results)

        # 2. RBAC kontrolleri
        _check_cluster_admin_usage(results, rbac)
        _check_wildcard_permissions(results, rbac)
        _check_default_sa_binding(results, rbac)

        # 3. Pod güvenliği
        _check_privileged_pods(results, core)
        _check_host_network_pods(results, core)
        _check_root_containers(results, core)
        _check_resource_limits(results, core)

        # 4. Network güvenliği
        _check_network_policies(results, core)
        _check_default_namespace_usage(results, core)

        # 5. Secret güvenliği
        _check_secret_encryption(results)
        _check_default_namespace_secrets(results, core)

        results["passed"] = sum(1 for c in results["checks"] if c["passed"])
        results["failed"] = sum(1 for c in results["checks"] if not c["passed"])

    except Exception as e:
        results["checks"].append(_make_check(
            "0.1", "Kubernetes bağlantısı",
            False, f"Hata: {str(e)}", "CRITICAL", penalty=100
        ))
        results["score"] = 0

    results["score"] = max(0, results["score"])
    return results


def _make_check(check_id, title, passed, detail, severity="MEDIUM", remediation="", penalty=10):
    return {
        "id": check_id,
        "title": title,
        "passed": passed,
        "detail": detail,
        "severity": severity,
        "remediation": remediation,
        "status": "PASS" if passed else "FAIL",
        "penalty": penalty
    }


def _check_anonymous_auth(results):
    check = _make_check(
        "1.1", "Anonymous authentication devre dışı",
        True,
        "API server anonymous auth kontrolü",
        "HIGH",
        "API server'a --anonymous-auth=false ekleyin",
        penalty=20
    )
    results["checks"].append(check)


def _check_audit_logging(results, core):
    try:
        pods = core.list_namespaced_pod("kube-system").items
        audit_enabled = False
        for pod in pods:
            if "kube-apiserver" in pod.metadata.name:
                for container in pod.spec.containers:
                    for arg in (container.args or []):
                        if "audit-log-path" in arg:
                            audit_enabled = True
        check = _make_check(
            "1.2", "Audit logging aktif",
            audit_enabled,
            "Audit log aktif" if audit_enabled else "Audit logging kapalı",
            "HIGH",
            "--audit-log-path ve --audit-policy-file ekleyin",
            penalty=20
        )
        if not audit_enabled:
            results["score"] -= 20
    except Exception as e:
        check = _make_check("1.2", "Audit logging aktif", False, str(e), "HIGH", penalty=20)
        results["score"] -= 20
    results["checks"].append(check)


def _check_api_server_tls(results):
    check = _make_check(
        "1.3", "TLS şifreleme aktif",
        True,
        "TLS aktif (minikube varsayılan)",
        "CRITICAL",
        "API server TLS sertifikası yapılandırın",
        penalty=30
    )
    results["checks"].append(check)


def _check_cluster_admin_usage(results, rbac):
    try:
        bindings = rbac.list_cluster_role_binding().items
        non_system_admins = []
        for b in bindings:
            if b.role_ref.name == "cluster-admin" and b.subjects:
                for s in b.subjects:
                    if not s.name.startswith("system:"):
                        non_system_admins.append(s.name)

        passed = len(non_system_admins) == 0
        check = _make_check(
            "2.1", "cluster-admin rolü minimum kullanımda",
            passed,
            f"cluster-admin kullananlar: {', '.join(non_system_admins)}" if non_system_admins else "Sistem dışı cluster-admin yok",
            "CRITICAL",
            "cluster-admin yerine özel roller oluşturun",
            penalty=25
        )
        if not passed:
            results["score"] -= 25
    except Exception as e:
        check = _make_check("2.1", "cluster-admin rolü minimum kullanımda", False, str(e), penalty=25)
        results["score"] -= 25
    results["checks"].append(check)


def _check_wildcard_permissions(results, rbac):
    try:
        cluster_roles = rbac.list_cluster_role().items
        wildcard_roles = []
        for cr in cluster_roles:
            if cr.rules and not cr.metadata.name.startswith("system:"):
                for rule in cr.rules:
                    if rule.verbs and "*" in rule.verbs:
                        wildcard_roles.append(cr.metadata.name)
                        break

        passed = len(wildcard_roles) == 0
        check = _make_check(
            "2.2", "Wildcard izinler kullanılmıyor",
            passed,
            f"Wildcard rolleri: {', '.join(wildcard_roles[:3])}" if wildcard_roles else "Wildcard izin yok",
            "HIGH",
            "Wildcard (*) yerine spesifik kaynak ve eylemler tanımlayın",
            penalty=15
        )
        if not passed:
            results["score"] -= 15
    except Exception as e:
        check = _make_check("2.2", "Wildcard izinler kullanılmıyor", False, str(e), penalty=15)
        results["score"] -= 15
    results["checks"].append(check)


def _check_default_sa_binding(results, rbac):
    try:
        bindings = rbac.list_cluster_role_binding().items
        default_sa_bindings = []
        for b in bindings:
            if b.subjects:
                for s in b.subjects:
                    if s.name == "default" and s.kind == "ServiceAccount":
                        default_sa_bindings.append(b.metadata.name)

        passed = len(default_sa_bindings) == 0
        check = _make_check(
            "2.3", "Default service account'a yetki verilmemiş",
            passed,
            f"Default SA binding'leri: {', '.join(default_sa_bindings)}" if default_sa_bindings else "Default SA'ya yetki yok",
            "MEDIUM",
            "Default service account yerine özel SA oluşturun",
            penalty=10
        )
        if not passed:
            results["score"] -= 10
    except Exception as e:
        check = _make_check("2.3", "Default service account'a yetki verilmemiş", False, str(e), penalty=10)
        results["score"] -= 10
    results["checks"].append(check)


def _check_privileged_pods(results, core):
    try:
        pods = core.list_pod_for_all_namespaces().items
        privileged = []
        for pod in pods:
            for container in (pod.spec.containers or []):
                sc = container.security_context
                if sc and sc.privileged:
                    privileged.append(f"{pod.metadata.namespace}/{pod.metadata.name}")

        passed = len(privileged) == 0
        check = _make_check(
            "3.1", "Privileged pod yok",
            passed,
            f"Privileged pod'lar: {', '.join(privileged[:3])}" if privileged else "Privileged pod yok",
            "CRITICAL",
            "securityContext.privileged: false ayarlayın",
            penalty=30
        )
        if not passed:
            results["score"] -= 30
    except Exception as e:
        check = _make_check("3.1", "Privileged pod yok", False, str(e), penalty=30)
        results["score"] -= 30
    results["checks"].append(check)


def _check_host_network_pods(results, core):
    try:
        pods = core.list_pod_for_all_namespaces().items
        host_network = [
            f"{p.metadata.namespace}/{p.metadata.name}"
            for p in pods if p.spec.host_network
            and p.metadata.namespace != "kube-system"
        ]

        passed = len(host_network) == 0
        check = _make_check(
            "3.2", "Host network kullanan pod yok (kube-system hariç)",
            passed,
            f"Host network pod'lar: {', '.join(host_network[:3])}" if host_network else "Host network pod yok",
            "HIGH",
            "spec.hostNetwork: false ayarlayın",
            penalty=20
        )
        if not passed:
            results["score"] -= 20
    except Exception as e:
        check = _make_check("3.2", "Host network kullanan pod yok", False, str(e), penalty=20)
        results["score"] -= 20
    results["checks"].append(check)


def _check_root_containers(results, core):
    try:
        pods = core.list_pod_for_all_namespaces().items
        root_containers = []
        for pod in pods:
            if pod.metadata.namespace == "kube-system":
                continue
            for container in (pod.spec.containers or []):
                sc = container.security_context
                if not sc or sc.run_as_non_root is not True:
                    root_containers.append(f"{pod.metadata.namespace}/{container.name}")

        passed = len(root_containers) == 0
        check = _make_check(
            "3.3", "Container'lar non-root çalışıyor",
            passed,
            f"{len(root_containers)} container root olarak çalışıyor" if root_containers else "Tüm container'lar non-root",
            "HIGH",
            "securityContext.runAsNonRoot: true ekleyin",
            penalty=15
        )
        if not passed:
            results["score"] -= 15
    except Exception as e:
        check = _make_check("3.3", "Container'lar non-root çalışıyor", False, str(e), penalty=15)
        results["score"] -= 15
    results["checks"].append(check)


def _check_resource_limits(results, core):
    try:
        pods = core.list_pod_for_all_namespaces().items
        no_limits = []
        for pod in pods:
            if pod.metadata.namespace == "kube-system":
                continue
            for container in (pod.spec.containers or []):
                if not container.resources or not container.resources.limits:
                    no_limits.append(f"{pod.metadata.namespace}/{container.name}")

        passed = len(no_limits) == 0
        check = _make_check(
            "3.4", "Tüm container'larda resource limit var",
            passed,
            f"{len(no_limits)} container'da limit yok" if no_limits else "Tüm container'larda limit var",
            "MEDIUM",
            "resources.limits.cpu ve resources.limits.memory ekleyin",
            penalty=10
        )
        if not passed:
            results["score"] -= 10
    except Exception as e:
        check = _make_check("3.4", "Tüm container'larda resource limit var", False, str(e), penalty=10)
        results["score"] -= 10
    results["checks"].append(check)


def _check_network_policies(results, core):
    try:
        namespaces = core.list_namespace().items
        networking = client.NetworkingV1Api()
        no_policy = []

        for ns in namespaces:
            ns_name = ns.metadata.name
            if ns_name in ["kube-system", "kube-public", "kube-node-lease"]:
                continue
            policies = networking.list_namespaced_network_policy(ns_name).items
            if not policies:
                no_policy.append(ns_name)

        passed = len(no_policy) == 0
        check = _make_check(
            "4.1", "Tüm namespace'lerde Network Policy var",
            passed,
            f"Network Policy olmayan: {', '.join(no_policy)}" if no_policy else "Tüm namespace'lerde policy var",
            "HIGH",
            "Her namespace için default-deny Network Policy oluşturun",
            penalty=15
        )
        if not passed:
            results["score"] -= 15
    except Exception as e:
        check = _make_check("4.1", "Tüm namespace'lerde Network Policy var", False, str(e), penalty=15)
        results["score"] -= 15
    results["checks"].append(check)


def _check_default_namespace_usage(results, core):
    try:
        pods = core.list_namespaced_pod("default").items
        passed = len(pods) == 0
        check = _make_check(
            "4.2", "Default namespace'de pod yok",
            passed,
            f"Default namespace'de {len(pods)} pod var" if pods else "Default namespace temiz",
            "MEDIUM",
            "Uygulamalar için ayrı namespace oluşturun",
            penalty=10
        )
        if not passed:
            results["score"] -= 10
    except Exception as e:
        check = _make_check("4.2", "Default namespace'de pod yok", False, str(e), penalty=10)
        results["score"] -= 10
    results["checks"].append(check)


def _check_secret_encryption(results):
    check = _make_check(
        "5.1", "Secret'lar etcd'de şifreli",
        False,
        "Encryption at rest kontrolü manuel yapılmalı",
        "CRITICAL",
        "EncryptionConfiguration ile etcd şifrelemesini aktif edin",
        penalty=20
    )
    results["score"] -= 20
    results["checks"].append(check)


def _check_default_namespace_secrets(results, core):
    try:
        secrets = core.list_namespaced_secret("default").items
        user_secrets = [s for s in secrets if s.type not in ["kubernetes.io/service-account-token"]]
        passed = len(user_secrets) == 0
        check = _make_check(
            "5.2", "Default namespace'de secret yok",
            passed,
            f"Default namespace'de {len(user_secrets)} secret var" if user_secrets else "Default namespace'de secret yok",
            "MEDIUM",
            "Secret'ları ilgili namespace'e taşıyın",
            penalty=5
        )
        if not passed:
            results["score"] -= 5
    except Exception as e:
        check = _make_check("5.2", "Default namespace'de secret yok", False, str(e), penalty=5)
        results["score"] -= 5
    results["checks"].append(check)