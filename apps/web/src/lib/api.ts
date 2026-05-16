import type {
  RemediationItem,
  ScanRecord,
  ScanStatus,
  ServiceSummary,
  Summary,
  VulnerabilitySummary,
} from "../types";

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`${path} returned ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  summary: () => getJson<Summary>("/api/summary"),
  services: () => getJson<ServiceSummary[]>("/api/services"),
  remediation: () => getJson<RemediationItem[]>("/api/remediation"),
  vulnerabilities: () =>
    getJson<VulnerabilitySummary[]>("/api/vulnerabilities?limit=500"),
  scans: () => getJson<ScanRecord[]>("/api/scans"),
  scanStatus: () => getJson<ScanStatus>("/api/scans/status"),
  runScan: async () => {
    const response = await fetch("/api/scans/run", { method: "POST" });
    if (!response.ok) {
      throw new Error(`scan failed with ${response.status}`);
    }
    return response.json();
  },
  testNotification: async (webhookUrl: string) => {
    const response = await fetch("/api/notifications/test", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ webhook_url: webhookUrl }),
    });
    if (!response.ok) {
      throw new Error(`notification test failed with ${response.status}`);
    }
    return response.json();
  },
  ignore: async (vulnerabilityId: string, service: string, days: number) => {
    const response = await fetch("/api/ignore", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        vulnerability_id: vulnerabilityId,
        service: service || undefined,
        days,
      }),
    });
    if (!response.ok) {
      throw new Error(`ignore failed with ${response.status}`);
    }
    return response.json();
  },
};
