---
name: Orval and Zod compatibility
description: Compatibility note for generated API validation schemas in this workspace.
---

Orval v8's Zod client output uses the Zod 4 API, including helpers such as `zod.email()` and `zod.int()`.

**Why:** The workspace template can retain an older Zod 3 catalog entry, which makes code generation succeed but breaks the required library typecheck.

**How to apply:** When regenerating API schemas with Orval v8, keep the workspace Zod catalog on a compatible Zod 4 release and run the library typecheck immediately afterward.