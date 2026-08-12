#!/usr/bin/env node
// Dependency-free independent RFC 8785 oracle.  JavaScript's key comparison
// provides the UTF-16 code-unit ordering required by JCS.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

function assertUnicode(value, path = "$") {
  if (typeof value === "string") {
    for (let index = 0; index < value.length; index += 1) {
      const unit = value.charCodeAt(index);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const next = value.charCodeAt(index + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error(`invalid-unicode at ${path}`);
        index += 1;
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        throw new Error(`invalid-unicode at ${path}`);
      }
    }
  } else if (Array.isArray(value)) {
    value.forEach((member, index) => assertUnicode(member, `${path}[${index}]`));
  } else if (value && typeof value === "object") {
    for (const [key, member] of Object.entries(value)) {
      assertUnicode(key, path);
      assertUnicode(member, `${path}.${key}`);
    }
  }
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  throw new Error(`unsupported value type ${typeof value}`);
}

const input = JSON.parse(readFileSync(0, "utf8"));
assertUnicode(input);
const canonical = Buffer.from(canonicalize(input), "utf8");
process.stdout.write(JSON.stringify({
  canonical_utf8_hex: canonical.toString("hex"),
  canonical_byte_length: canonical.length,
  sha256: createHash("sha256").update(canonical).digest("hex"),
}) + "\n");
