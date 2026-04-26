import { render, screen } from "@testing-library/react";
import { Badge } from "./Badge";

test("severity and risk badges render correctly", () => {
  const { rerender } = render(<Badge value="critical" />);
  expect(screen.getByText("Critical")).toHaveClass("text-red-800");

  rerender(<Badge value="not_available" />);
  expect(screen.getByText("Not Available")).toHaveClass("text-stone-700");

  rerender(<Badge value={null} />);
  expect(screen.getByText("Unknown")).toHaveClass("text-slate-700");
});
