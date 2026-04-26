import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach } from "vitest";
import { ThemeToggle } from "./ThemeToggle";

beforeEach(() => {
  localStorage.clear();
  document.documentElement.classList.remove("dark");
});

afterEach(() => {
  localStorage.clear();
  document.documentElement.classList.remove("dark");
});

test("theme toggle persists and applies dark mode", () => {
  render(<ThemeToggle />);

  fireEvent.click(screen.getByLabelText("Switch to dark theme"));

  expect(document.documentElement).toHaveClass("dark");
  expect(localStorage.getItem("norn-theme")).toBe("dark");
});
