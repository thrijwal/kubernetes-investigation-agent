# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

resource "google_compute_network" "k8s_agent_prod_vpc" {
  name                    = "k8s-agent-prod-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  description             = "Custom VPC network for k8s-inv-agent production Cloud Run egress"

  depends_on = [
    resource.google_project_service.services,
  ]
}

resource "google_compute_subnetwork" "private_egress_subnet" {
  name                     = "k8s-agent-prod-egress-subnet"
  project                  = var.project_id
  region                   = "us-east1"
  network                  = google_compute_network.k8s_agent_prod_vpc.id
  ip_cidr_range            = "10.10.1.0/24"
  private_ip_google_access = true
  description              = "Private egress subnet (10.10.1.0/24) in us-east1 with Private Google Access enabled"
}

resource "google_compute_subnetwork" "k8s_agent_egress_subnet" {
  name                     = "k8s-agent-egress-subnet"
  project                  = var.project_id
  region                   = "us-east1"
  network                  = google_compute_network.k8s_agent_prod_vpc.id
  ip_cidr_range            = "10.10.2.0/24"
  private_ip_google_access = true
  description              = "Direct VPC egress subnet k8s-agent-egress-subnet in us-east1 with Private Google Access enabled"
}

resource "google_compute_router" "nat_router" {
  name        = "k8s-agent-nat-router"
  project     = var.project_id
  region      = "us-east1"
  network     = google_compute_network.k8s_agent_prod_vpc.id
  description = "Cloud Router for NAT egress in k8s-agent-prod-vpc"
}

resource "google_compute_router_nat" "nat_gateway" {
  name                               = "k8s-agent-nat"
  project                            = var.project_id
  router                             = google_compute_router.nat_router.name
  region                             = google_compute_router.nat_router.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.private_egress_subnet.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  subnetwork {
    name                    = google_compute_subnetwork.k8s_agent_egress_subnet.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

output "vpc_network_name" {
  description = "Name of the custom VPC network"
  value       = google_compute_network.k8s_agent_prod_vpc.name
}

output "egress_subnetwork_name" {
  description = "Name of the Direct VPC egress subnetwork in us-east1"
  value       = google_compute_subnetwork.k8s_agent_egress_subnet.name
}

output "egress_subnetwork_cidr" {
  description = "CIDR range of the private egress subnetwork"
  value       = google_compute_subnetwork.private_egress_subnet.ip_cidr_range
}

output "nat_router_name" {
  description = "Name of the Cloud Router for NAT egress"
  value       = google_compute_router.nat_router.name
}

output "nat_gateway_name" {
  description = "Name of the Cloud NAT gateway"
  value       = google_compute_router_nat.nat_gateway.name
}

# ------------------------------------------------------------------------------
# Custom VPC Network Infrastructure for Private GKE Cluster (us-east1)
# ------------------------------------------------------------------------------

resource "google_compute_network" "gke_network" {
  name                    = "${var.project_name}-network"
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  description             = "Custom VPC network for private GKE cluster in ${var.region}"

  depends_on = [resource.google_project_service.services]
}

resource "google_compute_subnetwork" "gke_subnet" {
  name                     = "${var.project_name}-subnet"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.gke_network.id
  ip_cidr_range            = "10.0.0.0/20"
  private_ip_google_access = true
  description              = "Private GKE node subnetwork with secondary ranges for pods and services"

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.4.0.0/14"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.8.0.0/20"
  }
}

resource "google_compute_router" "router" {
  name        = "${var.project_name}-router"
  project     = var.project_id
  region      = var.region
  network     = google_compute_network.gke_network.id
  description = "Cloud Router for private GKE cluster NAT gateway in ${var.region}"
}

resource "google_compute_router_nat" "nat" {
  name                               = "${var.project_name}-nat"
  project                            = var.project_id
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

resource "google_compute_firewall" "allow_internal" {
  name        = "${var.project_name}-allow-internal"
  network     = google_compute_network.gke_network.name
  project     = var.project_id
  description = "Allow internal pod-to-pod, node-to-node, and metrics-server traffic across GKE CIDRs"

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = ["10.0.0.0/8"]
}

output "gke_vpc_network_name" {
  description = "Name of the custom VPC network for the private GKE cluster"
  value       = google_compute_network.gke_network.name
}

output "gke_subnetwork_name" {
  description = "Name of the private GKE subnetwork in us-east1"
  value       = google_compute_subnetwork.gke_subnet.name
}

output "gke_node_cidr" {
  description = "Primary CIDR range for GKE nodes"
  value       = google_compute_subnetwork.gke_subnet.ip_cidr_range
}

output "gke_pods_secondary_cidr" {
  description = "Secondary CIDR range for GKE pods"
  value       = "10.4.0.0/14"
}

output "gke_services_secondary_cidr" {
  description = "Secondary CIDR range for GKE services"
  value       = "10.8.0.0/20"
}

output "gke_nat_router_name" {
  description = "Name of the Cloud Router for the private GKE cluster"
  value       = google_compute_router.router.name
}

output "gke_nat_gateway_name" {
  description = "Name of the Cloud NAT gateway for the private GKE cluster"
  value       = google_compute_router_nat.nat.name
}

# ------------------------------------------------------------------------------
# Private GKE Cluster & Workload Identity Configuration (us-east1)
# ------------------------------------------------------------------------------

resource "google_container_cluster" "app" {
  name     = var.project_name
  location = var.region
  project  = var.project_id

  network    = google_compute_network.gke_network.name
  subnetwork = google_compute_subnetwork.gke_subnet.name

  # Enable Autopilot mode (automatically configures Workload Identity pool PROJECT_ID.svc.id.goog)
  enable_autopilot = true

  # Use private nodes (no external IPs) on custom VPC network
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  deletion_protection = false

  depends_on = [
    resource.google_project_service.services,
  ]
}

resource "google_artifact_registry_repository" "docker_repo" {
  location      = var.region
  repository_id = var.project_name
  format        = "DOCKER"
  project       = var.project_id

  depends_on = [resource.google_project_service.services]
}

# Allow GKE Kubernetes ServiceAccount to impersonate the application GCP SA via Workload Identity
resource "google_service_account_iam_member" "workload_identity_binding" {
  service_account_id = google_service_account.app_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.project_name}/${var.project_name}]"

  depends_on = [google_container_cluster.app]
}

resource "kubernetes_namespace_v1" "app" {
  metadata {
    name = var.project_name
  }
  depends_on = [google_container_cluster.app]
}

resource "kubernetes_service_account_v1" "app" {
  metadata {
    name      = var.project_name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    annotations = {
      "iam.gke.io/gcp-service-account" = "${var.project_name}-app@${var.project_id}.iam.gserviceaccount.com"
    }
  }
}

resource "kubernetes_service_v1" "app" {
  metadata {
    name      = var.project_name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels = {
      app = var.project_name
    }
  }
  spec {
    type = "LoadBalancer"
    port {
      port        = 8080
      target_port = 8080
      protocol    = "TCP"
    }
    selector = {
      app = var.project_name
    }
  }
  wait_for_load_balancer = true
}

resource "kubernetes_horizontal_pod_autoscaler_v2" "app" {
  metadata {
    name      = var.project_name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels = {
      app = var.project_name
    }
  }
  spec {
    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = var.project_name
    }
    min_replicas = 2
    max_replicas = 10
    metric {
      type = "Resource"
      resource {
        name = "cpu"
        target {
          type                = "Utilization"
          average_utilization = 70
        }
      }
    }
  }
}

resource "kubernetes_pod_disruption_budget_v1" "app" {
  metadata {
    name      = var.project_name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels = {
      app = var.project_name
    }
  }
  spec {
    min_available = 1
    selector {
      match_labels = {
        app = var.project_name
      }
    }
  }
}

resource "kubernetes_deployment_v1" "app" {
  metadata {
    name      = var.project_name
    namespace = kubernetes_namespace_v1.app.metadata[0].name
    labels = {
      app = var.project_name
    }
  }

  spec {
    selector {
      match_labels = {
        app = var.project_name
      }
    }

    template {
      metadata {
        labels = {
          app = var.project_name
        }
      }

      spec {
        termination_grace_period_seconds = 600
        service_account_name             = kubernetes_service_account_v1.app.metadata[0].name

        container {
          name  = var.project_name
          image = "${var.region}-docker.pkg.dev/${var.project_id}/${var.project_name}/${var.project_name}:latest"

          port {
            container_port = 8080
            protocol       = "TCP"
          }

          env {
            name  = "APP_URL"
            value = "http://${kubernetes_service_v1.app.status[0].load_balancer[0].ingress[0].ip}:8080"
          }

          env {
            name  = "AGENT_VERSION"
            value = "0.1.0"
          }

          env {
            name  = "LOGS_BUCKET_NAME"
            value = google_storage_bucket.logs_data_bucket.name
          }

          env {
            name  = "OTEL_SERVICE_NAME"
            value = var.project_name
          }

          env {
            name  = "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"
            value = "NO_CONTENT"
          }

          env {
            name  = "ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS"
            value = "false"
          }

          env {
            name  = "OTEL_SEMCONV_STABILITY_OPT_IN"
            value = "gen_ai_latest_experimental"
          }

          env {
            name  = "OTEL_INSTRUMENTATION_GENAI_UPLOAD_FORMAT"
            value = "jsonl"
          }

          env {
            name  = "OTEL_INSTRUMENTATION_GENAI_COMPLETION_HOOK"
            value = "upload"
          }

          env {
            name  = "OTEL_INSTRUMENTATION_GENAI_UPLOAD_BASE_PATH"
            value = "gs://${google_storage_bucket.logs_data_bucket.name}/completions"
          }

          env {
            name  = "GOOGLE_CLOUD_PROJECT"
            value = var.project_id
          }

          env {
            name  = "GOOGLE_CLOUD_LOCATION"
            value = "global"
          }

          env {
            name  = "GOOGLE_GENAI_USE_ENTERPRISE"
            value = "True"
          }

          resources {
            requests = {
              cpu    = "0.5"
              memory = "1Gi"
            }
            limits = {
              cpu    = "1"
              memory = "2Gi"
            }
          }

          startup_probe {
            tcp_socket {
              port = 8080
            }
            initial_delay_seconds = 10
            period_seconds        = 10
            failure_threshold     = 18
          }

          readiness_probe {
            tcp_socket {
              port = 8080
            }
            initial_delay_seconds = 15
            period_seconds        = 10
          }

          liveness_probe {
            tcp_socket {
              port = 8080
            }
            initial_delay_seconds = 15
            period_seconds        = 20
          }

          lifecycle {
            pre_stop {
              exec {
                command = ["sleep", "10"]
              }
            }
          }
        }
      }
    }
  }

  depends_on = [kubernetes_namespace_v1.app, kubernetes_service_v1.app]
}

output "gke_cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.app.name
}

output "gke_cluster_endpoint" {
  description = "GKE cluster endpoint"
  value       = google_container_cluster.app.endpoint
}

output "gke_workload_identity_pool" {
  description = "Workload Identity pool for the GKE cluster"
  value       = "${var.project_id}.svc.id.goog"
}

output "gke_artifact_registry_image" {
  description = "Container image URI in Artifact Registry"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${var.project_name}/${var.project_name}:latest"
}

output "gke_load_balancer_ip" {
  description = "External LoadBalancer IP for the GKE service"
  value       = kubernetes_service_v1.app.status[0].load_balancer[0].ingress[0].ip
}
