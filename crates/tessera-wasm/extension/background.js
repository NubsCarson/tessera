// Tessera MV3 background service worker (SCAFFOLD).
//
// Responsibility: load the wasm-bindgen glue, mint/refresh a presentation
// header, and install a `declarativeNetRequest` (DNR) rule that attaches it as
// the `Tessera-Presentation` request header on matching outgoing requests.
//
// ── Why declarativeNetRequest, not webRequest ────────────────────────────────
// MV3 deprecates the *blocking* `webRequest` API for content modification, so a
// header that must be present *before* the request goes out can no longer be
// added from a JS `onBeforeSendHeaders` listener in a stable, supported way.
// DNR's `modifyHeaders` action is the supported MV3 path: the browser applies
// the rule natively, so it works even when the service worker is asleep.
//
// LIMITS of the DNR approach (be honest about them):
//   * The header VALUE is static per rule — DNR cannot call into wasm per
//     request. So we mint a presentation in JS and *update the rule's value*;
//     each outgoing request then reuses whatever value the rule currently holds
//     until we rotate it. That means presentations are NOT one-per-request
//     here, which the ARC unlinkability story assumes. A faithful client would
//     mint a fresh presentation per request (what `tessera-client` does on the
//     Rust side); doing that in an extension needs either (a) a server that
//     issues short-lived single-use headers, or (b) the now-restricted blocking
//     webRequest, or (c) rotating the DNR rule aggressively. This scaffold
//     rotates on a timer to illustrate the mechanism, not to be unlinkable.
//   * A real deployment also needs a real credential: `mint_local()` here uses
//     an EPHEMERAL server key (demo only) so the header verifies against
//     nothing real. Wire issuance to a live issuer for actual use.
//
// This file is intentionally a SCAFFOLD. Loading it in a browser against a live
// origin is the human final mile (see README.md).

const RULE_ID = 1;
// The origin you want to carry the credential to. Must also be in
// `host_permissions` in manifest.json.
const TARGET_URL_FILTER = "||example.com/";

let wasm = null;

// Lazily import the wasm-bindgen `--target web` glue. Run the build step in
// README.md first to produce `pkg/tessera_wasm.js` + `pkg/tessera_wasm_bg.wasm`.
async function ensureWasm() {
  if (wasm) return wasm;
  // `pkg/` is produced by: wasm-pack build --target web (see README.md).
  const mod = await import("./pkg/tessera_wasm.js");
  await mod.default(); // initialize the wasm module (loads the .wasm)
  wasm = mod;
  return wasm;
}

// Mint a fresh presentation header and install/replace the DNR rule that
// attaches it to outgoing requests matching TARGET_URL_FILTER.
async function rotatePresentation() {
  const m = await ensureWasm();

  // Demo issuance: ephemeral key, local round-trip. Replace with a credential
  // obtained from a real issuer for actual use (see README.md / lib.rs).
  const enc = new TextEncoder();
  const cred = m.mint_local(
    enc.encode("tessera-extension/issue"),
    enc.encode("tessera-extension/origin"),
    16n // presentation budget; rotate before exhausting it
  );
  const headerValue = cred.present(); // hex Tessera-Presentation header

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [RULE_ID],
    addRules: [
      {
        id: RULE_ID,
        priority: 1,
        action: {
          type: "modifyHeaders",
          requestHeaders: [
            {
              header: "Tessera-Presentation",
              operation: "set",
              value: headerValue,
            },
          ],
        },
        condition: {
          urlFilter: TARGET_URL_FILTER,
          resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest"],
        },
      },
    ],
  });
}

chrome.runtime.onInstalled.addListener(() => {
  rotatePresentation().catch((e) => console.error("[tessera] mint failed:", e));
});

// Rotate periodically so the attached header changes over time (illustrative;
// see the unlinkability LIMITS note above — this is not per-request).
// `create()` returns a Promise in MV3; attach `.catch` so a failed alarm
// (bad args / quota) surfaces in the console instead of an unhandled rejection
// (the optional `?.catch?.` also tolerates older void-returning shims).
chrome.alarms
  ?.create?.("tessera-rotate", { periodInMinutes: 1 })
  ?.catch?.((e) => console.error("[tessera] alarm creation failed:", e));
chrome.alarms?.onAlarm?.addListener?.((a) => {
  if (a.name === "tessera-rotate") {
    rotatePresentation().catch((e) =>
      console.error("[tessera] rotate failed:", e)
    );
  }
});
