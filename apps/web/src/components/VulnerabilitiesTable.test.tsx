import { render, screen } from "@testing-library/react";
import { VulnerabilitiesTable } from "./VulnerabilitiesTable";

test("vulnerabilities table renders sample data", () => {
  render(
    <VulnerabilitiesTable
      vulnerabilities={[
        {
          vulnerability_id: "CVE-2026-0001",
          severity: "critical",
          runtime_risk: "critical",
          affected_service: "norn-nginx",
          exposed: "public",
          fix_available: "available",
          first_seen: "2026-04-25T10:00:00Z",
          last_seen: "2026-04-25T10:00:00Z",
          package_name: "nginx",
          installed_version: "1.25.3",
          fixed_version: "1.25.4"
        }
      ]}
    />
  );

  expect(screen.getByText("CVE-2026-0001")).toBeInTheDocument();
  expect(screen.getByText("norn-nginx")).toBeInTheDocument();
  expect(screen.getAllByText("Critical")).toHaveLength(2);
  expect(screen.getByText("Available")).toBeInTheDocument();
});
