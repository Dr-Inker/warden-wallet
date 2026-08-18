const out = document.getElementById("out");
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64url = (buf) => b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const rpId = location.hostname; // = extension id under chrome-extension://
let credId = null, spki = null;
async function create() {
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { id: rpId, name: "Warden spike" },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "warden", displayName: "Warden" },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],           // ES256 only
    authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "required", userVerification: "required" },
    extensions: { prf: {} },
  }});
  credId = cred.rawId; spki = cred.response.getPublicKey();
  const ext = cred.getClientExtensionResults();
  out.textContent = JSON.stringify({ step: "create", alg: cred.response.getPublicKeyAlgorithm(), prfEnabled: !!(ext.prf && ext.prf.enabled), spki: b64(spki) }, null, 2);
  window.__spike = { credId, spki };
}
async function get() {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const salt = new TextEncoder().encode("WARDEN/prf/v1");
  const a = await navigator.credentials.get({ publicKey: {
    rpId, challenge, userVerification: "required",
    allowCredentials: credId ? [{ type: "public-key", id: credId }] : [],
    extensions: { prf: { eval: { first: salt } } },
  }});
  const ext = a.getClientExtensionResults();
  const result = {
    pubkeyDerSpki: b64(spki), authenticatorData: b64(a.response.authenticatorData),
    clientDataJSON: b64(a.response.clientDataJSON), signatureDer: b64(a.response.signature),
    challenge: b64url(challenge), prfFirst: ext.prf?.results?.first ? b64(ext.prf.results.first) : null,
    origin: location.origin, rpId,
  };
  out.textContent = JSON.stringify(result, null, 2);
  window.__assertion = result;
}
document.getElementById("create").onclick = () => create().catch(e => out.textContent = "create error: " + e);
document.getElementById("get").onclick = () => get().catch(e => out.textContent = "get error: " + e);
