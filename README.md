# ⎈ Kubernetes Security Auditor

Kubernetes cluster'larını güvenlik açıkları için tarayan kapsamlı denetim platformu.

## Ne Yapıyor?

4 farklı modülde Kubernetes cluster'ını analiz ederek 0-100 arası güvenlik skoru üretir.

## Modüller

- RBAC — ClusterRole wildcard izinler, tehlikeli RoleBinding'ler, ServiceAccount güvenliği
- Pod Güvenliği — Privileged container, host network/PID/IPC, security context, resource limits
- Network — Network Policy eksikliği, LoadBalancer servisleri, tehlikeli portlar, TLS kontrolü
- Secret — Hassas veri anahtarları, default namespace secret'ları, boş değer kontrolü

## Teknolojiler

- Python 3
- kubernetes — Kubernetes Python SDK
- Flask — Web arayüzü
- python-dotenv — Güvenli yapılandırma

## Kurulum

    git clone https://github.com/kaansoyturk/k8s-security-auditor.git
    cd k8s-security-auditor
    python3 -m venv venv
    source venv/bin/activate
    pip3 install kubernetes flask colorama reportlab python-dotenv

## Gereksinimler

- Kubernetes cluster (minikube, EKS, GKE, AKS)
- kubectl yapılandırılmış (~/.kube/config)

## Minikube ile Test

    brew install minikube kubectl
    minikube start --driver=docker

## Kullanim

    python3 app.py

Tarayicide ac: http://localhost:5055

## Desteklenen Platformlar

- Minikube (yerel geliştirme)
- AWS EKS
- Google GKE
- Azure AKS

## Gelistirici

Kaan Soyturk — github.com/kaansoyturk