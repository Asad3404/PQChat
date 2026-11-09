// End-to-end browser test of the PQ-Chat web UI (M6 "done when": two users chat in the browser).
//
// Usage (with `docker compose up` running):
//   node scripts/e2e_browser.mjs "<alice UI link>" "<bob UI link>" evidence/m6
// The links are printed by the clients: docker compose logs alice bob | grep "PQ-Chat UI"
//
// Needs Playwright with Chromium (a test tool, not a runtime dependency of PQ-Chat).
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright"); // resolved via NODE_PATH or a local install

const [aliceUrl, bobUrl, out = "evidence/m6"] = process.argv.slice(2);
const PASS = "synthetic demo passphrase"; // synthetic test account only (CLAUDE.md §10)

const browser = await chromium.launch();
const mk = async () => (await browser.newContext({ viewport: { width: 1180, height: 720 }, deviceScaleFactor: 2 })).newPage();
const alice = await mk();
const bob = await mk();
const errors = [];
for (const p of [alice, bob]) p.on("pageerror", (e) => errors.push(e.message));

async function create(page, url, name, shot) {
  await page.goto(url);
  await page.waitForSelector("#lock:not([hidden])");
  if (shot) await page.screenshot({ path: `${out}/1-create-identity.png` });
  await page.fill("#username", name);
  await page.fill("#passphrase", PASS);
  await page.click("#unlock-btn");
  await page.waitForSelector("#app:not([hidden])", { timeout: 60000 });
}

await create(alice, aliceUrl, "alice", true);
await create(bob, bobUrl, "bob", false);

// Alice starts a chat with bob (fetches and verifies his bundle, runs the hybrid handshake).
await alice.click("#new-chat-btn");
await alice.fill("#new-name", "bob");
await alice.click('#new-chat button[value="ok"]');
await alice.waitForSelector("#composer:not([hidden])");
const first = "Hi Bob, this message is end-to-end encrypted with X25519 + ML-KEM-768.";
await alice.fill("#draft", first);
await alice.press("#draft", "Enter");
await alice.waitForSelector(`.b.out:has-text("${first}")`);

// Bob receives it, opens the chat and answers.
await bob.waitForSelector('.conv:has-text("alice")', { timeout: 30000 });
await bob.click('.conv:has-text("alice")');
await bob.waitForSelector(`.b.in:has-text("${first}")`);
const reply = "Got it. And <b>this</b> stays plain text, not HTML.";
await bob.fill("#draft", reply);
await bob.press("#draft", "Enter");
await alice.waitForSelector('.b.in:has-text("stays plain text")', { timeout: 30000 });
for (let i = 1; i <= 3; i++) {
  await alice.fill("#draft", `Message ${i} on the double ratchet.`);
  await alice.press("#draft", "Enter");
}
await bob.waitForSelector('.b.in:has-text("Message 3 on the double ratchet.")', { timeout: 30000 });
await alice.screenshot({ path: `${out}/2-alice-chat.png` });
await bob.screenshot({ path: `${out}/3-bob-chat.png` });

// Safety numbers must match on both sides.
await alice.click("#info-btn");
await bob.click("#info-btn");
const sa = (await alice.textContent("#safety")).trim();
const sb = (await bob.textContent("#safety")).trim();
await alice.click("#verify-btn");
await alice.waitForSelector('#peer-status .ok:has-text("verified")');
await alice.screenshot({ path: `${out}/4-alice-safety-number-verified.png` });

const boldInjected = await alice.$("#msgs b");
const result = {
  ok: sa === sb && sa.length === 60 && !boldInjected && errors.length === 0,
  safety_numbers_match: sa === sb,
  safety_number_digits: sa.length,
  html_injected: Boolean(boldInjected),
  page_errors: errors,
};
console.log(JSON.stringify(result));
await browser.close();
process.exit(result.ok ? 0 : 1);
