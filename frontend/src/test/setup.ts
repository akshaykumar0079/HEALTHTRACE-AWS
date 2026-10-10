import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(() => cleanup());

// jsdom lacks these; the app only uses them for layout niceties.
if (!window.matchMedia) {
  window.matchMedia = ((query: string) => ({
    matches: false, media: query, onchange: null,
    addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
}
if (!("CSS" in globalThis) || !("escape" in CSS)) {
  Object.defineProperty(globalThis, "CSS", { value: { escape: (s: string) => s.replace(/["\\]/g, "\\$&") }, configurable: true });
}
