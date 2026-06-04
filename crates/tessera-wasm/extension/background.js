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
//   * Credentials are obtained by REAL issuance against `ISSUER_BASE` (fetch its
//     public key, `prepare_issuance`, POST the request, `finalize`) — the same
//     flow proven end-to-end in `examples/node-real-issuance.cjs`. So the header
//     verifies against a real issuer/origin (not the ephemeral `mint_local`
//     demo helper). Point `ISSUER_BASE` at your origin (e.g. tessera-tower-demo)
//     and add it to `host_permissions`.
//
// This file is intentionally a SCAFFOLD. Loading it in a browser against a live
// origin is the human final mile (see README.md).

const RULE_ID = 1;
// The issuer/origin that issues credentials AND that you carry them to. Must
// also be in `host_permissions` in manifest.json. Defaults wire this to the
// local `tessera-tower-demo` origin for the walkthrough in README.md; change
// ISSUER_BASE / TARGET_URL_FILTER / the contexts / LIMIT to target your origin.
const ISSUER_BASE = "http://127.0.0.1:8090";
const TARGET_URL_FILTER = "||127.0.0.1";
// These MUST match the origin's configured contexts + limit exactly (LIMIT
// shapes the range proof, so a mismatch won't even verify) — here, the values
// baked into tessera-tower-demo.
const REQUEST_CTX = "tessera-tower-demo/issue/v1";
const PRESENT_CTX = "tessera-tower-demo/origin/v1";
const LIMIT = 5n; // presentation budget per credential; re-issue when spent

let wasm = null;
let credential = null; // current TesseraCredential (re-issued when budget runs out)

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

const fromHex = (h) => Uint8Array.from(h.trim().match(/../g).map((b) => parseInt(b, 16)));

// REAL issuance against ISSUER_BASE: fetch the public key, prepare a request,
// POST it to the issuer, finalize the response into a credential. (Same flow as
// the verified examples/node-real-issuance.cjs.)
async function issueCredential(m) {
  const enc = new TextEncoder();
  const pubkeyHex = await (await fetch(`${ISSUER_BASE}/pubkey`)).text();
  const flow = m.prepare_issuance(
    fromHex(pubkeyHex),
    enc.encode(REQUEST_CTX),
    enc.encode(PRESENT_CTX),
    LIMIT
  );
  const respHex = await (
    await fetch(`${ISSUER_BASE}/issue`, { method: "POST", body: flow.request_hex() })
  ).text();
  return flow.finalize(respHex);
}

// Mint a fresh presentation header and install/replace the DNR rule that
// attaches it to outgoing requests matching TARGET_URL_FILTER.
async function rotatePresentation() {
  const m = await ensureWasm();
  if (!credential) credential = await issueCredential(m);

  let headerValue;
  try {
    headerValue = credential.present(); // spends one unit of the budget
  } catch {
    // Budget exhausted (or credential invalid): obtain a fresh one and retry.
    credential = await issueCredential(m);
    headerValue = credential.present();
  }

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
