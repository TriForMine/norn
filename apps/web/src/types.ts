export type Exposure = "public" | "internal" | "localhost" | "unknown";
export type RiskLevel =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";
export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "negligible"
  | "unknown";

export interface Summary {
  running_services: number;
  running_containers: number;
  listening_ports: number;
  public_services: number;
  critical_risks: number;
  high_risks: number;
  medium_risks: number;
  low_risks: number;
  informational_risks: number;
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

export interface RemediationItem {
  service: string;
  highest_risk: RiskLevel;
  exposure: Exposure;
  vulnerability_count: number;
  fixable_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  informational_count: number;
  top_vulnerabilities: string[];
  affected_packages: RemediationPackage[];
  first_seen: string;
  last_seen: string;
  recommended_action: string;
}

export interface RemediationPackage {
  package_name: string;
  installed_version?: string | null;
  fixed_version?: string | null;
  vulnerability_count: number;
  fixable_count: number;
  highest_risk: RiskLevel;
}

export interface ScanStatus {
  running: boolean;
  phase: string;
  phase_label: string;
  scan_id?: string | null;
  host?: string | null;
  started_at?: string | null;
  completed_target_checks: number;
  total_target_checks: number;
  current_target?: string | null;
  parallelism: number;
  message?: string | null;
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
