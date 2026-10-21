#!/usr/bin/env node
// `airs` and `airs-cli`: run the prebuilt Prisma AIRS CLI for this platform
// (lib/launcher.js; docs/DESIGN.md §21.16).
import { main } from "../lib/launcher.js";

await main(import.meta.url);
