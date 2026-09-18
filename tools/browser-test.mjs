#!/usr/bin/env node
/*
 * 브라우저 자동 검사 — Chromium · Firefox · WebKit(사파리 엔진) 세 곳에서 실제 페이지를 조작한다.
 *
 *   npm install && npx playwright install chromium firefox webkit
 *   node tools/browser-test.mjs                 # 셋 다
 *   BROWSERS=firefox node tools/browser-test.mjs
 *
 * 한 엔진에서만 검사하다 다른 엔진에서 깨지는 일이 실제로 있었다
 * (Firefox는 WebCrypto PBKDF2로 256바이트까지만 뽑아 준다). 그래서 셋 다 돈다.
 */
import { chromium, firefox, webkit } from 'playwright';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENGINES = { chromium, firefox, webkit };
const WANT = (process.env.BROWSERS || 'chromium,firefox,webkit').split(',').map((s) => s.trim());
const PYTHON = process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3');

// ── 작은 정적 서버 ─────────────────────────────────────────────
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.woff2': 'font/woff2', '.json': 'application/json',
  '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8' };

const server = createServer(async (req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p.endsWith('/')) p += 'index.html';
  const file = path.join(ROOT, p);
  if (!file.startsWith(ROOT)) { res.writeHead(403); res.end(); return; }
  try {
    const body = await readFile(file);
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  } catch { res.writeHead(404); res.end(); }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://127.0.0.1:${server.address().port}`;

// ── Python 쪽 벡터 (교차 해독용) ──────────────────────────────
function py(code, input) {
  return execFileSync(PYTHON, ['-c', code], {
    cwd: ROOT, input, encoding: 'utf-8',
    env: { ...process.env, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8' },
  });
}
const PY = JSON.parse(py(`
import json, hangul_crypt as hc
sk, pk = hc.generate_keypair()
t = '파이썬이 봉인한 글입니다. 브라우저에서 풀려야 합니다.'
print(json.dumps({
  'text': t,
  'pw': hc.to_hangul(hc.encrypt(t, '파이썬-pw')),
  'pwPad': hc.to_hangul(hc.encrypt(t, '파이썬-pw', pad=True)),
  'sk': sk, 'pk': pk, 'fp': hc.key_fingerprint(pk),
}, ensure_ascii=False))
`));

function pyDecrypt(token, { password = null, secret = null } = {}) {
  return py(`
import sys, json, hangul_crypt as hc
a = json.loads(sys.stdin.read())
print(hc.decrypt(hc.decode_token(a['t']), a['p'], secret=a['s']), end='')
`, JSON.stringify({ t: token, p: password, s: secret })).trim();
}

function pySealTo(pub, text) {
  return py(`
import sys, json, hangul_crypt as hc
a = json.loads(sys.stdin.read())
print(hc.to_hangul(hc.encrypt(a['x'], to=a['k'])), end='')
`, JSON.stringify({ k: pub, x: text })).trim();
}

// ── 검사 ───────────────────────────────────────────────────────
let total = 0, failed = 0;
function check(ok, msg) {
  total++;
  if (!ok) failed++;
  console.log((ok ? '  OK   ' : '  FAIL ') + msg);
}

async function runEngine(name) {
  const browser = await ENGINES[name].launch();
  const context = await browser.newContext();
  // 복사를 가로채 검사에서 읽는다
  await context.addInitScript(() => {
    window.__clip = [];
    const fake = { writeText: (s) => { window.__clip.push(s); return Promise.resolve(); } };
    try { Object.defineProperty(Navigator.prototype, 'clipboard', { configurable: true, get: () => fake }); }
    catch (e) { /* 무시 */ }
  });
  const page = await context.newPage();
  page.setDefaultTimeout(90000);
  const errors = [], foreign = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('request', (r) => { if (!r.url().startsWith(ORIGIN) && !r.url().startsWith('data:')) foreign.push(r.url()); });
  page.on('dialog', (d) => d.accept());

  const $ = (id) => page.locator('#' + id);
  const settle = () => page.waitForFunction(() =>
    document.getElementById('result').classList.contains('show') ||
    document.getElementById('error').classList.contains('show'));
  async function go() {
    await page.evaluate(() => {
      document.getElementById('result').classList.remove('show');
      document.getElementById('error').classList.remove('show');
    });
    await $('go').click();
    await settle();
    const err = await $('error').evaluate((e) => e.classList.contains('show') ? e.textContent : null);
    return err ? { error: err } : { out: await $('output').inputValue() };
  }
  const lastClip = () => page.evaluate(() => window.__clip[window.__clip.length - 1]);
  // 링크는 보통 새 탭에서 열리므로, 매번 빈 페이지를 거쳐 새로 불러온다
  const open = async (hash = '') => {
    await page.goto('about:blank');
    await page.goto(ORIGIN + '/index.html' + hash);
    await page.waitForFunction(() => document.getElementById('meterText').textContent.length > 0 ||
                                      document.getElementById('notice').classList.contains('show'));
  };

  const version = browser.version();
  console.log(`\n══ ${name} ${version} ══`);

  // 1. 기본 · CSP · 외부 요청
  await open();
  const pwned = await page.evaluate(() => {
    window.__pwned = false;
    const s = document.createElement('script');
    s.textContent = 'window.__pwned = true;';
    document.body.appendChild(s);
    return new Promise((r) => setTimeout(() => r(window.__pwned), 100));
  });
  check(pwned === false, 'CSP가 주입된 인라인 스크립트를 막음');

  // 2. 열쇠말 봉인 · 해독
  await $('inputText').fill('아무 글이나 적어 봅니다');
  await $('pw').fill('asdf');
  let r = await go();
  check(!r.error, '열쇠말 봉인' + (r.error ? ': ' + r.error : ''));
  const sealed = r.out || '';
  const pyGot = sealed ? pyDecrypt(sealed, { password: 'asdf' }) : '';
  check(pyGot === '아무 글이나 적어 봅니다', '브라우저가 봉인한 글을 Python이 해독');
  await $('tab-dec').click();
  await $('inputText').fill(sealed);
  await $('pw').fill('asdf');
  r = await go();
  check(r.out === '아무 글이나 적어 봅니다', '열쇠말 해독');
  await $('pw').fill('wrong');
  r = await go();
  check(/인증 실패/.test(r.error || ''), '틀린 열쇠말 거부');
  for (const [tok, label] of [[PY.pw, 'Python 암호문'], [PY.pwPad, 'Python 암호문(길이 감추기)']]) {
    await $('inputText').fill(tok);
    await $('pw').fill('파이썬-pw');
    r = await go();
    check(r.out === PY.text, label + ' 해독');
  }

  // 3. 길이 감추기 · 링크
  await $('tab-enc').click();
  await $('inputText').fill('링크로 보낼 글');
  await $('pw').fill('link-pw');
  await $('padBox').check();
  r = await go();
  const padLen = await page.evaluate((t) => HangulCrypt.decodeToken(t).length, r.out);
  check(padLen === 32, '길이 감추기 → 32바이트');
  await $('copyLink').click();
  const link = await lastClip();
  check(/#s=[A-Za-z0-9_-]+$/.test(link || ''), '링크 만들기');
  await open(link.slice(link.indexOf('#')));
  check(await page.evaluate(() => location.hash === '' &&
        document.getElementById('notice').classList.contains('show')), '링크로 열면 알림·주소창 정리');
  await $('pw').fill('link-pw');
  r = await go();
  check(r.out === '링크로 보낼 글', '링크로 받은 글 해독');

  // 4. 공개키 — 열쇠 만들기
  await open();
  await $('tab-key').click();
  await $('vaultPw').fill('보관 열쇠말 강물 연필');
  await $('keyGen').click();
  await page.waitForFunction(() => !document.getElementById('keyHave').hidden ||
                                   document.getElementById('keyError').classList.contains('show'));
  const myPub = (await $('myPub').inputValue()).replace(/\s/g, '');
  check(myPub.length === 23, '내 열쇠 만들기 (공개키 ' + myPub.length + '자)');
  const myFp = (await $('myFp').textContent()).match(/지문 (\S+ \S+)/);
  const fpFromPy = py(`import sys, hangul_crypt as hc; print(hc.key_fingerprint(sys.stdin.read().strip()), end='')`, myPub);
  check(myFp && myFp[1] === fpFromPy, '지문이 Python과 같음 (' + (myFp && myFp[1]) + ')');

  // 5. 공개키 — 「내게 보내기」 링크로 들어와 봉인
  await $('pubLink').click();
  const keyLink = await lastClip();
  check(/#k=[A-Za-z0-9_-]+$/.test(keyLink || ''), '내게 보내기 링크');
  await open(keyLink.slice(keyLink.indexOf('#')));
  await page.waitForFunction(() => /지문/.test(document.getElementById('toFp').textContent));
  check(await page.evaluate(() => document.getElementById('viaPk').getAttribute('aria-pressed') === 'true' &&
        document.getElementById('pwField').hidden), '링크로 열면 공개키 봉인 화면');
  await $('inputText').fill('공개키로 나에게 보내는 밀서');
  r = await go();
  check(!r.error, '공개키로 봉인' + (r.error ? ': ' + r.error : ''));
  const pkSealed = r.out || '';

  // 6. 공개키 — 해독 (보관 열쇠말로 / 틀린 보관 열쇠말 / Python이 보낸 글)
  await $('tab-dec').click();
  await $('inputText').fill(pkSealed);
  check((await $('pwLabel').textContent()) === '보관 열쇠말', '공개키 암호문을 알아보고 칸 이름이 바뀜');
  await $('pw').fill('보관 열쇠말 강물 연필');
  r = await go();
  check(r.out === '공개키로 나에게 보내는 밀서', '보관 열쇠말로 공개키 암호문 해독');
  await $('pw').fill('틀린 보관 열쇠말');
  r = await go();
  check(/보관 열쇠말이 맞지 않습니다/.test(r.error || ''), '틀린 보관 열쇠말 거부');
  await $('inputText').fill(pySealTo(myPub, 'Python이 브라우저 공개키로 보낸 글'));
  await $('pw').fill('보관 열쇠말 강물 연필');
  r = await go();
  check(r.out === 'Python이 브라우저 공개키로 보낸 글', 'Python이 봉인 → 브라우저 해독');

  // 7. 공개키 — Python 열쇠로 보내기, 백업, 개인 열쇠 직접 붙이기
  await $('tab-enc').click();
  await $('viaPk').click();
  await $('toKey').fill(PY.pk);
  await page.waitForFunction(() => /지문/.test(document.getElementById('toFp').textContent));
  check((await $('toFp').textContent()).includes(PY.fp), '받는 사람 지문 표시 (Python과 같음)');
  await $('inputText').fill('브라우저가 Python 공개키로 보낸 글');
  r = await go();
  check(r.out && pyDecrypt(r.out, { secret: PY.sk }) === '브라우저가 Python 공개키로 보낸 글',
        '브라우저가 봉인 → Python 해독');
  await $('toKey').fill(PY.pk.slice(0, -2));
  await page.waitForFunction(() => document.getElementById('toFp').classList.contains('bad'));
  check(true, '잘린 공개키를 알아챔: ' + (await $('toFp').textContent()));

  const unfold = (sel) => page.evaluate((q) => { document.querySelector(q).open = true; }, sel);
  await $('tab-key').click();
  await unfold('#keyHave details');
  await $('backupPw').fill('보관 열쇠말 강물 연필');
  await $('backupShow').click();
  await page.waitForFunction(() => !document.getElementById('backupOut').hidden ||
                                   document.getElementById('keyError').classList.contains('show'));
  const secret = (await $('backupOut').inputValue()).trim();
  const pubFromPy = py(`import sys, hangul_crypt as hc; print(hc.public_from_secret(sys.stdin.read().strip()), end='')`, secret);
  check(pubFromPy === myPub, '개인 열쇠 백업 (Python이 같은 공개키를 되살림)');
  await $('tab-dec').click();
  await $('inputText').fill(pkSealed);
  await $('pw').fill(secret);
  r = await go();
  check(r.out === '공개키로 나에게 보내는 밀서', '개인 열쇠를 그대로 붙여 해독');

  await $('tab-key').click();
  await unfold('#keyHave details');
  await $('keyForget').click();
  await page.waitForFunction(() => !document.getElementById('keyNone').hidden);
  check(true, '이 기기에서 열쇠 지우기');
  await $('tab-dec').click();
  await $('inputText').fill(pkSealed);
  await $('pw').fill('보관 열쇠말 강물 연필');
  r = await go();
  check(/열쇠가 없습니다/.test(r.error || ''), '열쇠가 없을 때 안내');

  // 8. 가져오기 — 백업한 개인 열쇠로 되살리기
  await $('tab-key').click();
  await $('vaultPw').fill('새 보관 열쇠말 겨울 사다리');
  await unfold('#keyNone details');
  await $('importSecret').fill(secret);
  await $('keyImport').click();
  await page.waitForFunction(() => !document.getElementById('keyHave').hidden ||
                                   document.getElementById('keyError').classList.contains('show'));
  check((await $('myPub').inputValue()).replace(/\s/g, '') === myPub, '백업한 개인 열쇠 불러오기');

  check(errors.length === 0, '페이지 오류 없음' + (errors.length ? ': ' + errors.join(' | ') : ''));
  check(foreign.length === 0, '외부 요청 없음' + (foreign.length ? ': ' + foreign.join(', ') : ''));
  await browser.close();
}

for (const name of WANT) {
  try { await runEngine(name); }
  catch (e) { failed++; total++; console.log(`  FAIL ${name}: ${e.message.split('\n')[0]}`); }
}
server.close();
console.log(`\n${total}건 중 실패 ${failed}건`);
process.exit(failed ? 1 : 0);
