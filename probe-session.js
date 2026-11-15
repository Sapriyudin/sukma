// Login via SIWE, then probe the account state (session, dashboard).
// Private key comes from stdin; the session cookie is saved to a mode-600
// file for later calls. Only the wallet address and account state are printed.
const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");

const BASE = "https://agentgames.zkverify.io";
const SESSION_FILE = path.join(__dirname, ".session.json");

async function main() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  const key = Buffer.concat(chunks).toString("utf8").trim().replace(/^0x/, "");
  if (!/^[0-9a-fA-F]{64}$/.test(key)) {
    console.error("expected a 64-hex-char private key on stdin");
    process.exit(1);
  }
  const wallet = new ethers.Wallet("0x" + key);
  console.log("wallet address:", wallet.address);

  const jar = [];
  async function req(p, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (jar.length) headers.cookie = jar.join("; ");
    const res = await fetch(BASE + p, { ...opts, headers, redirect: "manual" });
    const sc = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const c of sc) jar.push(c.split(";")[0]);
    return res;
  }

  const csrf = await (await req("/api/auth/csrf")).json();
  const nonceJson = await (await req("/api/auth/wallet/siwe/nonce")).json();
  const nonce = nonceJson.nonce || nonceJson;
  const issuedAt = new Date().toISOString();
  const expiration = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  const message =
    `agentgames.zkverify.io wants you to sign in with your Ethereum account:\n` +
    `${wallet.address}\n\n` +
    `Sign in to Agent Games with your wallet.\n\n` +
    `URI: https://agentgames.zkverify.io\n` +
    `Version: 1\n` +
    `Chain ID: 1\n` +
    `Nonce: ${nonce}\n` +
    `Issued At: ${issuedAt}\n` +
    `Expiration Time: ${expiration}`;
  const signature = await wallet.signMessage(message);
  const cb = await req("/api/auth/callback/wallet", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "x-csrf-token": csrf.csrfToken },
    body: new URLSearchParams({ message, signature, csrfToken: csrf.csrfToken }).toString(),
  });
  console.log("login callback status:", cb.status);

  fs.writeFileSync(SESSION_FILE, JSON.stringify({ cookies: jar }, null, 2), { mode: 0o600 });
  console.log("session saved to .session.json (mode 600)");

  const sess = await req("/api/auth/session");
  console.log("session endpoint status:", sess.status);
  console.log("session body:", (await sess.text()).slice(0, 800));

  const dash = await req("/dashboard");
  const html = await dash.text();
  console.log("dashboard status:", dash.status, "bytes:", html.length);
  for (const needle of ["Proof Gatekeeper", "Steal the VFY", "Wildcard", "Creator", "handle", "HMAC", "secret", "endpoint", "Register", "onboard", "points", "rank"]) {
    if (html.toLowerCase().includes(needle.toLowerCase())) {
      const i = html.toLowerCase().indexOf(needle.toLowerCase());
      console.log(`dashboard contains "${needle}": ...${html.slice(Math.max(0, i - 60), i + 120).replace(/\s+/g, " ")}...`);
    }
  }
}

main().catch((e) => { console.error("probe failed:", e.message); process.exit(1); });
