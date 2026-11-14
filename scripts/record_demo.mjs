// Record the PQ-Chat UI flow as two side-by-side videos (Alice and Bob) for the demo video.
//
// Usage (with `scripts/demo.sh` / `docker compose up` running):
//   node scripts/record_demo.mjs "<alice link>" "<bob link>" <out-dir>
// Writes <out-dir>/alice.webm, <out-dir>/bob.webm and <out-dir>/timeline.json (captions with
// start times in seconds). scripts/make_demo_video.py turns them into the final MP4.
// Synthetic accounts and messages only (CLAUDE.md §10).
import { createRequire } from "node:module";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const [aliceUrl, bobUrl, out = "demo-out"] = process.argv.slice(2);
mkdirSync(out, { recursive: true });
const SIZE = { width: 960, height: 640 };
const PASS = "synthetic demo passphrase";

const browser = await chromium.launch();
const mk = async (name) => {
  const ctx = await browser.newContext({ viewport: SIZE, recordVideo: { dir: `${out}/${name}`, size: SIZE } });
  return [ctx, await ctx.newPage()];
};
const [actxA, alice] = await mk("alice");
const [actxB, bob] = await mk("bob");
const t0 = Date.now();
const timeline = [];
const caption = (text) => timeline.push({ t: (Date.now() - t0) / 1000, text });
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const type = (page, sel, text) => page.type(sel, text, { delay: 45 });

await Promise.all([alice.goto(aliceUrl), bob.goto(bobUrl)]);
await Promise.all([alice.waitForSelector("#lock:not([hidden])"), bob.waitForSelector("#lock:not([hidden])")]);

caption("Two clients (Alice, Bob) and an untrusted relay. All cryptography runs inside each client; the browser only shows text.");
await pause(4500);

caption("Alice creates her identity: Ed25519 + ML-DSA-65 signing keys and an X25519 key are generated on her device. The key store is encrypted with Argon2id + AES-256-GCM.");
await type(alice, "#username", "alice");
await type(alice, "#passphrase", PASS);
await alice.click("#unlock-btn");
await alice.waitForSelector("#app:not([hidden])", { timeout: 60000 });
await pause(2500);

caption("Bob does the same. Each client uploads only PUBLIC prekeys, every one signed with BOTH Ed25519 and ML-DSA-65.");
await type(bob, "#username", "bob");
await type(bob, "#passphrase", PASS);
await bob.click("#unlock-btn");
await bob.waitForSelector("#app:not([hidden])", { timeout: 60000 });
await pause(3500);

caption("Alice starts a chat with bob. Her client downloads Bob's prekey bundle and checks both signatures on every prekey.");
await alice.click("#new-chat-btn");
await pause(800);
await type(alice, "#new-name", "bob");
await alice.click('#new-chat button[value="ok"]');
await alice.waitForSelector("#composer:not([hidden])");
await pause(2500);

const first = "Hi Bob! This is our first post-quantum message.";
caption("First message = hybrid handshake: 4 X25519 values + an ML-KEM-768 encapsulation give one session key. It stays secret if EITHER X25519 OR ML-KEM holds.");
await type(alice, "#draft", first);
await alice.press("#draft", "Enter");
await alice.waitForSelector(`.b.out:has-text("${first}")`);
await pause(2500);

caption("Bob's client decapsulates, derives the same key, decrypts, and deletes the one-time prekeys that were used.");
await bob.waitForSelector('.conv:has-text("alice")', { timeout: 30000 });
await pause(1200);
await bob.click('.conv:has-text("alice")');
await bob.waitForSelector(`.b.in:has-text("${first}")`);
await pause(3000);

const reply = "Got it! And <b>this</b> stays plain text, not HTML.";
caption("Bob replies at once on the double ratchet: every message gets a fresh key, and used keys are deleted (forward secrecy). Message text is never treated as HTML.");
await type(bob, "#draft", reply);
await bob.press("#draft", "Enter");
await alice.waitForSelector('.b.in:has-text("stays plain text")', { timeout: 30000 });
await pause(3000);

caption("Every 4 ratchet steps a fresh ML-KEM secret is mixed in, so the chat heals after a device theft even against a quantum attacker.");
const lines = [
  [alice, "Message 1 on the double ratchet."],
  [bob, "Each message here uses a brand-new key."],
  [alice, "And the relay only ever sees ciphertext."],
  [bob, "Padded to fixed sizes, so length leaks less too."],
];
for (const [page, text] of lines) {
  await type(page, "#draft", text);
  await page.press("#draft", "Enter");
  const other = page === alice ? bob : alice;
  await other.waitForSelector(`.b.in:has-text("${text}")`, { timeout: 30000 });
  await pause(900);
}
await pause(1500);

caption("Safety numbers: both sides compute the same 60 digits from both identity keys. Comparing them in person or on a call proves nobody is in the middle.");
await alice.click("#info-btn");
await bob.click("#info-btn");
await pause(5500);

caption("Alice confirms the numbers match and marks Bob as verified. If Bob's identity key ever changes, sending is paused until she re-checks.");
await alice.click("#verify-btn");
await alice.waitForSelector('#peer-status .ok:has-text("verified")');
await pause(4500);

const total = (Date.now() - t0) / 1000;
writeFileSync(`${out}/timeline.json`, JSON.stringify({ duration: total, captions: timeline }, null, 2));
const pa = await alice.video().path();
const pb = await bob.video().path();
await actxA.close();
await actxB.close();
await browser.close();
renameSync(pa, `${out}/alice.webm`);
renameSync(pb, `${out}/bob.webm`);
console.log(JSON.stringify({ duration: total, captions: timeline.length }));
