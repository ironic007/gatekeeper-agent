// Decode the base64-encoded circuit artifacts into circuits/ at build time.
const fs = require("fs");
const path = require("path");

const dir = path.join(__dirname, "..", "circuits");
const files = [
  ["gatekeeper.wasm.b64", "gatekeeper.wasm"],
  ["gatekeeper_final.zkey.b64", "gatekeeper_final.zkey"],
];
for (const [src, out] of files) {
  const p = path.join(dir, src);
  if (!fs.existsSync(p)) continue;
  const data = Buffer.from(fs.readFileSync(p, "utf8").trim(), "base64");
  fs.writeFileSync(path.join(dir, out), data);
  console.log("decoded", out, data.length, "bytes");
}
