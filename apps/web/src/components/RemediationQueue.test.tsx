import { render, screen } from "@testing-library/react";
import { RemediationQueue } from "./RemediationQueue";

test("remediation queue renders prioritized service guidance", () => {
  render(
    <RemediationQueue
      items={[
        {
          service: "norn-nginx",
          highest_risk: "critical",
          exposure: "public",
          vulnerability_count: 12,
          fixable_count: 8,
          critical_count: 3,
          high_count: 5,
          medium_count: 4,
          low_count: 0,
          informational_count: 0,
          top_vulnerabilities: ["CVE-2026-0001", "GHSA-test"],
          affected_packages: [
            {
              package_name: "openssl",
              installed_version: "1.0.0",
              fixed_version: "1.0.1",
              vulnerability_count: 2,
              fixable_count: 2,
              highest_risk: "critical"
            }
          ],
          first_seen: "2026-04-25T10:00:00Z",
          last_seen: "2026-04-25T10:00:00Z",
          recommended_action: "Patch or update this public-facing service first."
        }
      ]}
    />
  );

  expect(screen.getByText("norn-nginx")).toBeInTheDocument();
  expect(screen.getByText("openssl")).toBeInTheDocument();
  expect(screen.getByText(/1\.0\.0/)).toBeInTheDocument();
  expect(screen.getByText(/1\.0\.1/)).toBeInTheDocument();
  expect(screen.getByText("CVE-2026-0001, GHSA-test")).toBeInTheDocument();
  expect(
    screen.getByText("Patch or update this public-facing service first.")
  ).toBeInTheDocument();
});
