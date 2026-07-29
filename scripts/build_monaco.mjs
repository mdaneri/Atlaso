import { build } from "esbuild";
import { readFile, writeFile } from "node:fs/promises";

const normalizeGeneratedWhitespace = async (path) => {
  const content = await readFile(path, "utf8");
  await writeFile(path, content.replace(/[ \t]+$/gm, ""), "utf8");
};

await build({
  entryPoints: ["scripts/monaco-entry.js"],
  bundle: true,
  minify: true,
  sourcemap: false,
  globalName: "AtlasoMonacoBundle",
  outfile: "atlaso/app/static/vendor/monaco/atlaso-monaco.min.js",
  loader: { ".ttf": "dataurl" },
  legalComments: "none",
});
await normalizeGeneratedWhitespace(
  "atlaso/app/static/vendor/monaco/atlaso-monaco.min.js",
);

await build({
  entryPoints: ["scripts/monaco-worker-entry.js"],
  bundle: true,
  minify: true,
  sourcemap: false,
  outfile: "atlaso/app/static/vendor/monaco/editor.worker.js",
  legalComments: "none",
});
await normalizeGeneratedWhitespace(
  "atlaso/app/static/vendor/monaco/editor.worker.js",
);
