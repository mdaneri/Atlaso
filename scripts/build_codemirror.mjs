import { build } from "esbuild";

await build({
  entryPoints: ["scripts/codemirror-entry.js"],
  bundle: true,
  minify: true,
  format: "iife",
  globalName: "AtlasoCodeMirrorBundle",
  outfile: "atlaso/app/static/vendor/codemirror/atlaso-codemirror.min.js",
  target: ["es2022"],
  legalComments: "none",
});
