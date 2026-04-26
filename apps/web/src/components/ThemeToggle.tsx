import { Moon, Sun } from "lucide-react";
import { useTheme } from "../lib/theme";

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const dark = theme === "dark";

  return (
    <button
      aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
      className="focus-ring inline-flex h-10 w-10 items-center justify-center rounded border border-line bg-panel text-ink shadow-surface hover:bg-slate-50 dark:hover:bg-slate-800"
      onClick={() => setTheme(dark ? "light" : "dark")}
      title={dark ? "Switch to light theme" : "Switch to dark theme"}
      type="button"
    >
      {dark ? <Sun className="h-4 w-4" aria-hidden="true" /> : <Moon className="h-4 w-4" aria-hidden="true" />}
    </button>
  );
}
