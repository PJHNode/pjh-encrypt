/*
 * 무거운 계산(코퍼스 예열 · scrypt 열쇠 유도 · 압축)을 화면과 다른 스레드에서 돌린다.
 * 이렇게 해야 긴 글을 봉인하는 동안에도 화면이 멈추지 않는다.
 *
 * 주고받는 말:  { id, op: 'prime' | 'encrypt' | 'decrypt', ... }
 *   → 성공 { id, value }   실패 { id, error: 메시지 }
 */
importScripts('hangul_crypt.js');
var HC = self.HangulCrypt;

self.onmessage = async function (e) {
  var m = e.data;
  try {
    var value;
    if (m.op === 'prime') {
      HC._prime();          // 예열만 미리 해 둔다 — 첫 봉인이 빨라진다
      value = true;
    } else if (m.op === 'encrypt') {
      value = await HC.encrypt(m.text, m.password, m.opts);
    } else if (m.op === 'decrypt') {
      value = await HC.decrypt(m.blob, m.password);
    } else {
      throw new Error('알 수 없는 작업입니다: ' + m.op);
    }
    self.postMessage({ id: m.id, value: value });
  } catch (err) {
    self.postMessage({ id: m.id, error: err && err.message ? err.message : String(err) });
  }
};
