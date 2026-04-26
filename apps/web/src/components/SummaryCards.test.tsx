import { render, screen } from "@testing-library/react";
import { SummaryCards } from "./SummaryCards";

test("dashboard renders summary cards", () => {
  render(
    <SummaryCards
      summary={{
        running_services: 48,
        running_containers: 12,
        public_services: 5,
        critical_risks: 1,
        high_risks: 3,
        medium_risks: 11,
        low_risks: 7,
        last_scan_time: "2026-04-25T10:00:00Z"
      }}
    />
  );

  expect(screen.getByText("Running services")).toBeInTheDocument();
  expect(screen.getByText("48")).toBeInTheDocument();
  expect(screen.getByText("Critical risks")).toBeInTheDocument();
  expect(screen.getByText("1")).toBeInTheDocument();
});
