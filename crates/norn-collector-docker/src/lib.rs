use std::{collections::BTreeMap, fs, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use norn_core::{
    Collector, DockerMetadata, Exposure, InventoryItem, InventoryKind, InventorySource,
    NetworkEndpoint, RuntimeStatus,
};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct DockerCollector {
    socket: String,
    fixture_path: Option<PathBuf>,
}

impl DockerCollector {
    pub fn new(socket: impl Into<String>) -> Self {
        Self {
            socket: socket.into(),
            fixture_path: None,
        }
    }

    pub fn with_fixture(socket: impl Into<String>, fixture_path: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            fixture_path: Some(fixture_path.into()),
        }
    }

    async fn collect_from_runtime(&self) -> Result<Vec<InventoryItem>> {
        if self.socket.starts_with("http://") || self.socket.starts_with("https://") {
            return collect_via_http_endpoint(&self.socket).await;
        }

        #[cfg(unix)]
        {
            let socket = PathBuf::from(&self.socket);
            tokio::task::spawn_blocking(move || collect_via_unix_socket(socket))
                .await
                .context("docker collection task failed")?
        }

        #[cfg(not(unix))]
        {
            Err(anyhow!(
                "Docker socket collection from {} is only supported on Unix-like systems; use fixture_path for tests",
                self.socket
            ))
        }
    }
}

#[async_trait]
impl Collector for DockerCollector {
    fn name(&self) -> &'static str {
        "docker"
    }

    async fn collect(&self) -> Result<Vec<InventoryItem>> {
        if let Some(path) = &self.fixture_path {
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read Docker fixture {}", path.display()))?;
            return parse_docker_inspect_json(&content);
        }

        self.collect_from_runtime().await
    }
}

pub fn parse_docker_inspect_json(input: &str) -> Result<Vec<InventoryItem>> {
    let inspections: Vec<ContainerInspect> =
        serde_json::from_str(input).context("failed to parse Docker inspect JSON")?;
    inspections
        .iter()
        .map(inventory_item_from_inspect)
        .collect::<Result<Vec<_>>>()
}

fn inventory_item_from_inspect(container: &ContainerInspect) -> Result<InventoryItem> {
    let name = container.name.trim_start_matches('/').to_string();
    let short_id = container.id.chars().take(12).collect::<String>();
    let labels = container.config.labels.clone().unwrap_or_default();
    let endpoints = extract_endpoints(container);
    let exposure = strongest_exposure(&endpoints);
    let docker_socket_mounted = docker_socket_mounted(container);
    let privileged = container.host_config.privileged.unwrap_or(false);
    let image = container.config.image.clone();

    let mut item = InventoryItem::new(
        format!("docker:{short_id}"),
        name,
        InventorySource::Docker,
        InventoryKind::Container,
    );
    item.status = if container.state.running.unwrap_or(false) {
        RuntimeStatus::Running
    } else {
        RuntimeStatus::Stopped
    };
    item.image = Some(image.clone());
    item.labels = labels.clone();
    item.endpoints = endpoints;
    item.exposure = exposure;
    item.collected_at = Utc::now();
    item.docker = Some(DockerMetadata {
        container_id: container.id.clone(),
        image,
        image_id: None,
        privileged,
        docker_socket_mounted,
        labels,
    });

    Ok(item)
}

fn extract_endpoints(container: &ContainerInspect) -> Vec<NetworkEndpoint> {
    let mut endpoints = Vec::new();
    let ports = container
        .network_settings
        .ports
        .as_ref()
        .or(container.host_config.port_bindings.as_ref());

    if let Some(ports) = ports {
        for (container_port, bindings) in ports {
            let (port, protocol) = parse_container_port(container_port);
            match bindings {
                Some(bindings) if !bindings.is_empty() => {
                    for binding in bindings {
                        let host_port = binding.host_port.parse::<u16>().unwrap_or(port);
                        let address = if binding.host_ip.trim().is_empty() {
                            "0.0.0.0".to_string()
                        } else {
                            binding.host_ip.clone()
                        };
                        endpoints.push(NetworkEndpoint {
                            protocol: protocol.clone(),
                            exposure: exposure_for_address(&address),
                            address,
                            port: host_port,
                            process: Some(container.name.trim_start_matches('/').to_string()),
                        });
                    }
                }
                _ => endpoints.push(NetworkEndpoint {
                    protocol,
                    address: "container-network".to_string(),
                    port,
                    exposure: Exposure::Internal,
                    process: Some(container.name.trim_start_matches('/').to_string()),
                }),
            }
        }
    }

    endpoints
}

fn parse_container_port(value: &str) -> (u16, String) {
    let mut parts = value.split('/');
    let port = parts
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or_default();
    let protocol = parts.next().unwrap_or("tcp").to_string();
    (port, protocol)
}

fn strongest_exposure(endpoints: &[NetworkEndpoint]) -> Exposure {
    if endpoints
        .iter()
        .any(|endpoint| endpoint.exposure == Exposure::Public)
    {
        Exposure::Public
    } else if endpoints
        .iter()
        .any(|endpoint| endpoint.exposure == Exposure::Internal)
    {
        Exposure::Internal
    } else if endpoints
        .iter()
        .any(|endpoint| endpoint.exposure == Exposure::Localhost)
    {
        Exposure::Localhost
    } else {
        Exposure::Unknown
    }
}

fn exposure_for_address(address: &str) -> Exposure {
    let normalized = address.trim_matches(['[', ']']);
    match normalized {
        "0.0.0.0" | "::" | "*" => Exposure::Public,
        "127.0.0.1" | "::1" | "localhost" => Exposure::Localhost,
        "" => Exposure::Public,
        _ => Exposure::Internal,
    }
}

fn docker_socket_mounted(container: &ContainerInspect) -> bool {
    let mounts = container.mounts.iter().any(|mount| {
        mount.source.contains("/var/run/docker.sock")
            || mount.destination.contains("/var/run/docker.sock")
    });
    let binds = container
        .host_config
        .binds
        .as_ref()
        .map(|binds| {
            binds
                .iter()
                .any(|bind| bind.contains("/var/run/docker.sock"))
        })
        .unwrap_or(false);
    mounts || binds
}

#[cfg(unix)]
fn collect_via_unix_socket(socket: PathBuf) -> Result<Vec<InventoryItem>> {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        time::Duration,
    };

    fn docker_get(socket: &PathBuf, path: &str) -> Result<String> {
        let mut stream = UnixStream::connect(socket)
            .with_context(|| format!("failed to connect to Docker socket {}", socket.display()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .context("failed to set Docker socket timeout")?;
        let request = format!("GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .context("failed to write Docker API request")?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .context("failed to read Docker API response")?;
        let (head, body) = response
            .split_once("\r\n\r\n")
            .ok_or_else(|| anyhow!("invalid Docker API HTTP response"))?;
        if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
            return Err(anyhow!("Docker API request {path} failed: {head}"));
        }
        Ok(body.to_string())
    }

    let containers_json = docker_get(&socket, "/containers/json")?;
    let containers: Vec<DockerPsContainer> =
        serde_json::from_str(&containers_json).context("failed to parse Docker container list")?;
    let mut inspect_json = Vec::new();
    for container in containers {
        inspect_json.push(docker_get(
            &socket,
            &format!("/containers/{}/json", container.id),
        )?);
    }

    let mut items = Vec::new();
    for body in inspect_json {
        let inspect: ContainerInspect =
            serde_json::from_str(&body).context("failed to parse Docker inspect response")?;
        items.push(inventory_item_from_inspect(&inspect)?);
    }
    Ok(items)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerPsContainer {
    #[serde(rename = "Id")]
    id: String,
}

async fn collect_via_http_endpoint(base_url: &str) -> Result<Vec<InventoryItem>> {
    let base_url = base_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let containers: Vec<DockerPsContainer> = client
        .get(format!("{base_url}/containers/json"))
        .send()
        .await
        .context("failed to query Docker API container list")?
        .error_for_status()
        .context("Docker API container list returned an error")?
        .json()
        .await
        .context("failed to parse Docker API container list")?;

    let mut items = Vec::new();
    for container in containers {
        let inspect: ContainerInspect = client
            .get(format!("{base_url}/containers/{}/json", container.id))
            .send()
            .await
            .with_context(|| format!("failed to inspect Docker container {}", container.id))?
            .error_for_status()
            .context("Docker API inspect returned an error")?
            .json()
            .await
            .context("failed to parse Docker API inspect response")?;
        items.push(inventory_item_from_inspect(&inspect)?);
    }
    Ok(items)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerInspect {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Config")]
    config: ContainerConfig,
    #[serde(rename = "State")]
    state: ContainerState,
    #[serde(rename = "HostConfig")]
    host_config: HostConfig,
    #[serde(rename = "Mounts", default)]
    mounts: Vec<Mount>,
    #[serde(rename = "NetworkSettings")]
    network_settings: NetworkSettings,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerConfig {
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "Labels")]
    labels: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerState {
    #[serde(rename = "Running")]
    running: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HostConfig {
    #[serde(rename = "Privileged")]
    privileged: Option<bool>,
    #[serde(rename = "Binds")]
    binds: Option<Vec<String>>,
    #[serde(rename = "PortBindings")]
    port_bindings: Option<BTreeMap<String, Option<Vec<PortBinding>>>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Mount {
    #[serde(rename = "Source", default)]
    source: String,
    #[serde(rename = "Destination", default)]
    destination: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkSettings {
    #[serde(rename = "Ports")]
    ports: Option<BTreeMap<String, Option<Vec<PortBinding>>>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PortBinding {
    #[serde(rename = "HostIp", default)]
    host_ip: String,
    #[serde(rename = "HostPort", default)]
    host_port: String,
}

#[cfg(test)]
mod tests {
    use norn_core::Exposure;

    use super::*;

    const FIXTURE: &str = include_str!("../../../fixtures/docker/inspect.json");

    #[test]
    fn parses_docker_inspect_fixture() {
        let items = parse_docker_inspect_json(FIXTURE).unwrap();

        assert_eq!(items.len(), 4);
        assert_eq!(items[0].name, "norn-nginx");
        assert_eq!(items[0].image.as_deref(), Some("nginx:1.25.3"));
        assert_eq!(items[0].labels.get("norn.service").unwrap(), "edge");
    }

    #[test]
    fn detects_public_and_internal_exposure() {
        let items = parse_docker_inspect_json(FIXTURE).unwrap();
        let nginx = items.iter().find(|item| item.name == "norn-nginx").unwrap();
        let postgres = items
            .iter()
            .find(|item| item.name == "norn-postgres")
            .unwrap();

        assert_eq!(nginx.exposure, Exposure::Public);
        assert!(nginx.endpoints.iter().any(|endpoint| endpoint.port == 8080));
        assert_eq!(postgres.exposure, Exposure::Internal);
    }

    #[test]
    fn detects_privileged_container() {
        let items = parse_docker_inspect_json(FIXTURE).unwrap();
        let worker = items
            .iter()
            .find(|item| item.name == "norn-privileged-worker")
            .unwrap();

        assert!(worker.docker.as_ref().unwrap().privileged);
    }

    #[test]
    fn detects_docker_socket_mount() {
        let items = parse_docker_inspect_json(FIXTURE).unwrap();
        let agent = items
            .iter()
            .find(|item| item.name == "norn-build-agent")
            .unwrap();

        assert!(agent.docker.as_ref().unwrap().docker_socket_mounted);
        assert_eq!(agent.exposure, Exposure::Localhost);
    }
}
