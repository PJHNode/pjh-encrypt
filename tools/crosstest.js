#!/usr/bin/env node
/*
 * Python 구현과 JS 구현이 실제로 호환되는지 검사한다.
 *
 *   python tools/crosstest.py        # 벡터 생성 → JS 검증 → 역방향 검증까지 한 번에
 *
 * 이 파일은 보통 crosstest.py가 불러 쓰지만 직접 실행할 수도 있다.
 *   node tools/crosstest.js <vectors.json> <out.json>
 */
'use strict';
const fs = require('fs');
const path = require('path');
const HC = require(path.join(__dirname, '..', 'hangul_crypt.js'));

const b64 = (u8) => Buffer.from(u8).toString('base64');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));

async function main() {
  const vecPath = process.argv[2];
  const outPath = process.argv[3];
  const vectors = JSON.parse(fs.readFileSync(vecPath, 'utf8'));

  const results = { compress: [], decrypt: [], encrypt: [], token: [] };
  let fail = 0;
  const say = (ok, msg) => { if (!ok) fail++; console.log((ok ? '  OK   ' : '  FAIL ') + msg); };

  // 1) 압축기 출력이 바이트 단위로 같은가 (가장 중요 — 여기가 어긋나면 전부 깨진다)
  console.log('[1] CM 압축기 바이트 일치');
  for (const v of vectors.compress) {
    const got = HC.cmCompress(new TextEncoder().encode(v.text));
    const ok = b64(got) === v.cm;
    say(ok, `${JSON.stringify(v.text.slice(0, 22))} → ${got.length}B` +
            (ok ? '' : `  (Python ${unb64(v.cm).length}B)`));
    results.compress.push(ok);
    // 자기 자신 왕복
    const back = HC.cmDecompress(got, new TextEncoder().encode(v.text).length);
    say(new TextDecoder().decode(back) === v.text, `  ↳ JS 자체 왕복`);
  }

  // 2) base85 인코딩이 Python과 같은가
  console.log('\n[2] base85 인코딩 일치');
  for (const v of vectors.token) {
    const got = HC.toToken(unb64(v.blob));
    say(got === v.token, `${v.token.length}자 토큰`);
    const round = b64(HC.fromToken(v.token)) === v.blob;
    say(round, `  ↳ 디코딩 왕복`);
    results.token.push(got === v.token && round);
  }

  // 3) Python이 암호화한 것을 JS가 푸는가
  console.log('\n[3] Python 암호화 → JS 복호화');
  for (const v of vectors.decrypt) {
    let ok = false, note = '';
    try {
      const got = await HC.decrypt(HC.fromToken(v.token), v.password);
      ok = got === v.text;
      if (!ok) note = ` (받은 값: ${JSON.stringify(got.slice(0, 30))})`;
    } catch (e) { note = ' — ' + e.message; }
    say(ok, `${JSON.stringify(v.text.slice(0, 22))}${note}`);
    results.decrypt.push(ok);
  }

  // 4) 변조 / 틀린 비밀번호 거부
  console.log('\n[4] 인증 동작');
  {
    const v = vectors.decrypt.find((x) => x.password);
    const blob = HC.fromToken(v.token);
    blob[blob.length - 1] ^= 1;
    let rejected = false;
    try { await HC.decrypt(blob, v.password); } catch (e) { rejected = true; }
    say(rejected, '변조된 데이터 거부');

    let rejected2 = false;
    try { await HC.decrypt(HC.fromToken(v.token), v.password + 'x'); } catch (e) { rejected2 = true; }
    say(rejected2, '틀린 비밀번호 거부');
    if (!rejected || !rejected2) fail++;
  }

  // 5) JS가 암호화한 것을 파일로 내보내 Python이 풀게 한다
  console.log('\n[5] JS 암호화 → (Python이 검증할 토큰 생성)');
  const produced = [];
  for (const v of vectors.encrypt) {
    const blob = await HC.encrypt(v.text, v.password, v.opts || {});
    const token = HC.toToken(blob);
    // JS 자체 왕복부터 확인
    let selfOk = false;
    try { selfOk = (await HC.decrypt(HC.fromToken(token), v.password)) === v.text; } catch (e) {}
    say(selfOk, `${JSON.stringify(v.text.slice(0, 22))} → ${blob.length}B  (JS 자체 왕복)`);
    produced.push({ text: v.text, password: v.password, token });
    results.encrypt.push(selfOk);
  }

  fs.writeFileSync(outPath, JSON.stringify({ produced }, null, 1), 'utf8');
  console.log(`\nJS 단계 실패: ${fail}건`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
