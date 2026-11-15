// SIWE registration for zkVerify Agent Games.
// Flow (documented by the site's own auth endpoints):
//   1. GET  /api/auth/csrf                  -> CSRF token
//   2. GET  /api/auth/wallet/siwe/nonce     -> one-time nonce
//   3. Build the SIWE message (domain agentgames.zkverify.io, chain ID 1,
//      statement "Sign in to Agent Games with your wallet.", 5-min expiry)
//      and sign it (EIP-191 personal signature) with the wallet.
//   4. POST /api/auth/callback/wallet { message, signature } -> session.
//
// The private key is read from stdin (piped, never typed into a file or
// chat) and never printed, logged, or stored. Usage:
//   printf '%s' "$PRIVATE_KEY_HEX" | node register.js [REFERRAL_CODE]
// The script only reports the wallet ADDRESS and the session result.
const { ethers } = require("ethers");

const BASE = "https://agentgames.zkverify.io";

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
  async function req(path, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (jar.length) headers.cookie = jar.join("; ");
    const res = await fetch(BASE + path, { ...opts, headers, redirect: "manual" });
    const setCookie = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const c of setCookie) jar.push(c.split(";")[0]);
    return res;
  }

  const csrfRes = await req("/api/auth/csrf");
  const csrf = await csrfRes.json();
  const csrfToken = csrf.csrfToken;
  console.log("csrf ok:", !!csrfToken);

  const nonceRes = await req("/api/auth/wallet/siwe/nonce");
  const nonceJson = await nonceRes.json();
  const nonce = nonceJson.nonce || nonceJson;
  console.log("nonce ok:", typeof nonce === "string" && nonce.length > 0);

  const issuedAt = new Date().toISOString();
  const expiration = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  const message =
    `${"agentgames.zkverify.io"} wants you to sign in with your Ethereum account:\n` +
    `${wallet.address}\n\n` +
    `Sign in to Agent Games with your wallet.\n\n` +
    `URI: https://agentgames.zkverify.io\n` +
    `Version: 1\n` +
    `Chain ID: 1\n` +
    `Nonce: ${nonce}\n` +
    `Issued At: ${issuedAt}\n` +
    `Expiration Time: ${expiration}`;
  const signature = await wallet.signMessage(message);
  console.log("signed SIWE message");

  const cbRes = await req("/api/auth/callback/wallet", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "x-csrf-token": csrfToken },
    body: new URLSearchParams({ message, signature, csrfToken }).toString(),
  });
  const cbText = await cbRes.text();
  console.log("callback status:", cbRes.status);
  console.log("callback body (first 500 chars):", cbText.slice(0, 500));
  console.log("session cookies:", jar.length ? jar.map((c) => c.split("=")[0]).join(", ") : "none");
  console.log("NOTE: profile completion (handle, referral) is the next step — inspect the dashboard with this session.");
}

main().catch((e) => { console.error("registration failed:", e.message); process.exit(1); });
