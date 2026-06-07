export type ViewMode = "mobile" | "desktop";

const KEY = "proxylogs.viewMode";
const DESKTOP_WIDTH = 1280;

export function getViewMode(): ViewMode {
  return localStorage.getItem(KEY) === "desktop" ? "desktop" : "mobile";
}

/**
 * Apply a view mode by swapping the viewport meta tag. "desktop" forces a fixed
 * layout width that the browser scales to fit (the classic "request desktop
 * site" behaviour); "mobile" returns to a responsive, device-width layout.
 */
export function applyViewMode(mode: ViewMode): void {
  const meta = document.querySelector('meta[name="viewport"]');
  if (!meta) return;
  meta.setAttribute(
    "content",
    mode === "desktop"
      ? `width=${DESKTOP_WIDTH}`
      : "width=device-width, initial-scale=1",
  );
}

export function setViewMode(mode: ViewMode): void {
  localStorage.setItem(KEY, mode);
  applyViewMode(mode);
}
