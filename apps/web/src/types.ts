export type Exposure = "public" | "internal" | "localhost" | "unknown";
export type RiskLevel = "critical" | "high" | "medium" | "low" | "informational";
export type Severity = "critical" | "high" | "medium" | "low" | "negligible" | "unknown";

export interface Summary {
  running_services: number;
  running_containers: number;
  public_services: number;
  critical_risks: number;
  high_risks: number;
  medium_risks: number;
  low_risks: number;
  last_scan_time?: string | null;
}

export interface ServiceSummary {
  name: string;
  source: string;
  status: string;
  exposure: Exposure;
  highest_risk?: RiskLevel | null;
  vulnerability_count: number;
}

export interface VulnerabilitySummary {
  vulnerability_id: string;
  severity: Severity;
  runtime_risk: RiskLevel;
  affected_service: string;
  exposed: Exposure;
  fix_available: "available" | "not_available" | "unknown";
  first_seen: string;
  last_seen: string;
  package_name?: string | null;
  installed_version?: string | null;
  fixed_version?: string | null;
}

export interface ScanRecord {
  id: string;
  host: string;
  started_at: string;
  completed_at?: string | null;
  status: string;
  inventory_count: number;
  finding_count: number;
  scanner_errors: Array<{ scanner: string; target: string; message: string }>;
}
