// Complete Agent Games registration via the site's own server action.
// Usage: node register-complete.js <handle> <email> [referralCode]
// Reads the SIWE session from .session.json (created by probe-session.js).
const fs = require("fs");

const ACTION_ID = "40b83b7c35ed38b6fa8d87bcb524548c2c6b381275";
const BASE = "https://agentgames.zkverify.io";

async function main() {
  const [handle, email, referralCode] = process.argv.slice(2);
  if (!handle || !email) {
    console.error("usage: node register-complete.js <handle> <email> [referralCode]");
    process.exit(1);
  }
  const { cookies } = JSON.parse(fs.readFileSync(".session.json", "utf8"));
  const payload = {
    handle,
    displayName: handle,
    contactEmail: email,
    country: "",
    bio: "",
    twitter: "",
    referralCode: referralCode || undefined,
  };
  const fd = new FormData();
  fd.append("0", JSON.stringify(payload));
  const res = await fetch(BASE + "/register", {
    method: "POST",
    headers: { cookie: cookies.join("; "), "Next-Action": ACTION_ID },
    body: fd,
  });
  const text = await res.text();
  console.log("status:", res.status);
  console.log("body (first 1500 chars):", text.slice(0, 1500));
  if (res.ok && /"ok":true/.test(text)) console.log("REGISTRATION LOOKS OK");
}

main().catch((e) => { console.error("failed:", e.message); process.exit(1); });
