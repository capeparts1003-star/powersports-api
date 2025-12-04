// scripts/smoke.js
// Minimal API smoke test: health + categories
// Run: node scripts/smoke.js

const fetch = (...args) => import("node-fetch").then(({ default: f }) => f(...args));

(async () => {
  const base = process.env.API_BASE_URL || "http://localhost:4000";
  const endpoints = ["/health", "/categories"];

  for (const ep of endpoints) {
    try {
      const res = await fetch(base + ep);
      const text = await res.text();
      if (!res.ok) throw new Error(`${res.status}: ${text}`);
      console.log(ep, "OK", text.slice(0, 100));
    } catch (e) {
      console.error(ep, "FAIL", e.message);
      process.exitCode = 1;
    }
  }
})();
