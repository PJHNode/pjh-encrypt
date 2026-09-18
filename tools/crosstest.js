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
  console.log('[1] CM 압축기 바이트 일치 (v1 / v2)');
  for (const v of vectors.compress) {
    const raw = new TextEncoder().encode(v.text);
    const g1 = HC.cmCompress(raw, HC.CFG_V1), g2 = HC.cmCompress(raw, HC.CFG_V2);
    const ok1 = b64(g1) === v.cm, ok2 = b64(g2) === v.cm2;
    say(ok1 && ok2, `${JSON.stringify(v.text.slice(0, 20))}  v1 ${g1.length}B / v2 ${g2.length}B` +
        (ok1 && ok2 ? '' : `  ← Python과 다름 (v1 ${ok1}, v2 ${ok2})`));
    results.compress.push(ok1 && ok2);
    const b1 = HC.cmDecompress(g1, raw.length, HC.CFG_V1);
    const b2 = HC.cmDecompress(g2, raw.length, HC.CFG_V2);
    say(new TextDecoder().decode(b1) === v.text && new TextDecoder().decode(b2) === v.text,
        `  ↳ JS 자체 왕복 (v1·v2)`);
  }

  // 2) 표기(base85 / 한글)가 Python과 같은가
  console.log('\n[2] 표기 일치 (base85 / 한글)');
  for (const v of vectors.token) {
    const blob = unb64(v.blob);
    const okB = HC.toToken(blob) === v.token;
    const okH = HC.toHangul(blob) === v.hangul;
    const rtB = b64(HC.fromToken(v.token)) === v.blob;
    const rtH = b64(HC.fromHangul(v.hangul)) === v.blob;
    const auto = b64(HC.decodeToken(v.hangul)) === v.blob &&
                 (blob.length === 0 || b64(HC.decodeToken(v.token)) === v.blob);
    say(okB && okH && rtB && rtH && auto,
        `${blob.length}B → base85 ${v.token.length}자 / 한글 ${v.hangul.length}자` +
        (okB && okH && rtB && rtH && auto ? '' :
         `  ← b85=${okB}/${rtB} 한글=${okH}/${rtH} 자동인식=${auto}`));
    results.token.push(okB && okH && rtB && rtH && auto);
  }

  // 3) Python이 암호화한 것을 JS가 푸는가 (v1·v2, 한글·base85 섞어서)
  console.log('\n[3] Python 암호화 → JS 복호화');
  let v1n = 0, v2n = 0;
  for (const v of vectors.decrypt) {
    let ok = false, note = '';
    try {
      const got = await HC.decrypt(HC.decodeToken(v.token), v.password);
      ok = got === v.text;
      if (!ok) note = ` (받은 값: ${JSON.stringify(got.slice(0, 30))})`;
    } catch (e) { note = ' — ' + e.message; }
    if (ok) { if (v.version === 1) v1n++; else v2n++; }
    if (!ok) say(false, `v${v.version} ${JSON.stringify(v.text.slice(0, 22))}${note}`);
    results.decrypt.push(ok);
  }
  say(results.decrypt.every(Boolean), `v1 ${v1n}건, v2 ${v2n}건 모두 복호화됨`);

  // 4) 변조 / 틀린 비밀번호 거부
  console.log('\n[4] 인증 동작');
  {
    const v = vectors.decrypt.find((x) => x.password);
    const blob = HC.decodeToken(v.token);
    blob[blob.length - 1] ^= 1;
    let rejected = false;
    try { await HC.decrypt(blob, v.password); } catch (e) { rejected = true; }
    say(rejected, '변조된 데이터 거부');

    let rejected2 = false;
    try { await HC.decrypt(HC.decodeToken(v.token), v.password + 'x'); } catch (e) { rejected2 = true; }
    say(rejected2, '틀린 비밀번호 거부');
    if (!rejected || !rejected2) fail++;
  }

  // 5) JS가 암호화한 것을 파일로 내보내 Python이 풀게 한다
  console.log('\n[5] JS 암호화 → (Python이 검증할 토큰 생성)');
  const produced = [];
  for (const v of vectors.encrypt) {
    const blob = await HC.encrypt(v.text, v.password, v.opts || {});
    // 한글 표기로 내보내서 Python이 그걸 읽을 수 있는지까지 본다
    const token = HC.toHangul(blob);
    let selfOk = false;
    try { selfOk = (await HC.decrypt(HC.decodeToken(token), v.password)) === v.text; } catch (e) {}
    const ver = (blob[0] & 0x80) ? 2 : 1;
    say(selfOk, `v${ver} ${JSON.stringify(v.text.slice(0, 20))} → ${blob.length}B / ` +
        `한글 ${token.length}자 (base85라면 ${HC.toToken(blob).length}자)`);
    produced.push({ text: v.text, password: v.password, token });
    results.encrypt.push(selfOk);
  }

  fs.writeFileSync(outPath, JSON.stringify({ produced }, null, 1), 'utf8');
  console.log(`\nJS 단계 실패: ${fail}건`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
