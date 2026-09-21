import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import tailwindcss from "@tailwindcss/vite";

// The build is BYTE-VERIFIED in CI against the committed export
// (internal/ui/dist), so it must be reproducible. Rollup's content-hashed
// assets give that here; the single-worker pin the Metro build needed is not
// -- but the gate is the same one, and it failing means the committed bytes
// stopped being what this source produces.
export default defineConfig({
  plugins: [solid(), tailwindcss()],
  build: {
    // Into the package that embeds it: internal/ui's go:embed reads this
    // directory, and CI diffs it after a rebuild.
    outDir: "../internal/ui/dist",
    emptyOutDir: true,
  },
});
