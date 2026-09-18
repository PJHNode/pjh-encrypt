/* 밀서 — 화면 동작. CSP 때문에 인라인 대신 파일로 둔다. */
(function () {
'use strict';
var HC = window.HangulCrypt;

var $ = function (id) { return document.getElementById(id); };
var tabEnc = $('tab-enc'), tabDec = $('tab-dec');
var inputText = $('inputText'), inputLabel = $('inputLabel');
var pw = $('pw'), pwToggle = $('pwToggle');
var modeField = $('modeField'), go = $('go');
var result = $('result'), output = $('output'), outputLabel = $('outputLabel');
var stats = $('stats'), note = $('note'), errorBox = $('error');
var copy = $('copy'), copyLink = $('copyLink'), notice = $('notice');
var segWrap = $('segWrap'), segHan = $('segHan'), segB85 = $('segB85');
var meter = $('meter'), meterFill = $('meterFill'), meterText = $('meterText');
  var padBox = $('padBox');

var mode = 'enc';
var lastToken = '';   // 화면에는 다섯 자씩 끊어 보이지만, 베낄 때는 원본 그대로
var lastBlob = null;  // 표기를 바꾸거나 링크를 만들 때 다시 암호화하지 않으려고 들고 있는다
var lastMs = 0;
var encoding = 'han'; // 'han'(한글) | 'b85'(base85)

// ════════════════════════════════════════════════════════════════
//  계산 엔진 — 무거운 계산은 Web Worker에서 돌려 화면이 멈추지 않게 한다.
//  Worker를 띄울 수 없는 환경에서는 이 스레드에서 그대로 계산한다.
// ════════════════════════════════════════════════════════════════
var engine = (function () {
  var worker = null, seq = 0, pending = {};

  function direct(msg) {
    if (msg.op === 'encrypt') return HC.encrypt(msg.text, msg.password, msg.opts);
    if (msg.op === 'decrypt') return HC.decrypt(msg.blob, msg.password);
    return Promise.resolve(true);   // prime — 이 스레드에서는 미리 예열하지 않는다
  }

  // Worker가 죽으면 걸려 있던 일을 이 스레드에서 마저 처리한다
  function fallBack() {
    worker = null;
    var jobs = pending;
    pending = {};
    Object.keys(jobs).forEach(function (id) {
      direct(jobs[id].msg).then(jobs[id].resolve, jobs[id].reject);
    });
  }

  try {
    worker = new Worker('worker.js');
    worker.onmessage = function (e) {
      var job = pending[e.data.id];
      if (!job) return;
      delete pending[e.data.id];
      if (e.data.error !== undefined) job.reject(new Error(e.data.error));
      else job.resolve(e.data.value);
    };
    worker.onerror = function (e) { e.preventDefault(); fallBack(); };
  } catch (e) {
    worker = null;   // file:// 등에서는 Worker를 만들 수 없다
  }

  function call(msg) {
    if (!worker) return direct(msg);
    return new Promise(function (resolve, reject) {
      msg.id = ++seq;
      pending[msg.id] = { msg: msg, resolve: resolve, reject: reject };
      worker.postMessage(msg);
    });
  }

  return {
    encrypt: function (text, password, opts) {
      return call({ op: 'encrypt', text: text, password: password, opts: opts });
    },
    decrypt: function (blob, password) {
      return call({ op: 'decrypt', blob: blob, password: password });
    },
    prime: function () { return call({ op: 'prime' }); },
    inWorker: function () { return worker !== null; }
  };
})();

// ════════════════════════════════════════════════════════════════
//  링크 — 암호문을 주소의 # 뒤에 싣는다.
//  # 뒤는 서버로 전송되지 않는다. 한글을 그대로 넣으면 복사할 때
//  %EC%B0%8C… 로 바뀌어 9배로 길어지므로, 주소에는 base64url로 싣는다.
// ════════════════════════════════════════════════════════════════
function toB64url(u8) {
  var s = '';
  for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(str) {
  var s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  var bin;
  try { bin = atob(s); } catch (e) { throw new Error('링크가 손상되어 읽을 수 없습니다.'); }
  var u8 = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

function pageUrl() { return location.href.split('#')[0]; }
function linkFor(blob) { return pageUrl() + '#s=' + toB64url(blob); }

var LINK_RE = /#s=([A-Za-z0-9_-]+)/;

// 해독 칸에 무엇이 들어오든 받아 준다 — 링크 통째, 한글 암호문, 영문 암호문
function blobFromText(text) {
  var m = LINK_RE.exec(text);
  return m ? fromB64url(m[1]) : HC.decodeToken(text);
}

// ════════════════════════════════════════════════════════════════
//  열쇠말 굳기 — 대입 공격으로 뚫는 데 드는 시간을 대략 어림한다.
//  한글은 글자가 아니라 낱말로 센다. 사람은 무작위 음절이 아니라 낱말을
//  열쇠말로 쓰기 때문에, 글자마다 13비트를 쳐 주면 크게 부풀려진다.
// ════════════════════════════════════════════════════════════════
var COMMON = [
  '1234', '12345', '123456', '1234567', '12345678', '123456789', '1234567890',
  '0000', '1111', '111111', '000000', '654321', '1q2w3e', '1q2w3e4r', '1q2w3e4r5t',
  'qwerty', 'qwer1234', 'qwertyuiop', 'asdf', 'asdf1234', 'password', 'passw0rd',
  'iloveyou', 'admin', 'abc123', 'letmein', 'welcome', 'dragon', 'monkey', 'sunshine',
  'football', 'baseball', 'master', 'hello', 'test', 'guest', 'love', 'secret',
  '사랑해', '사랑', '비밀번호', '비번', '암호', '안녕', '안녕하세요', '하나둘셋',
  '가나다라', '가나다라마바사', '열쇠말', '밀서', '대한민국', '비밀', '행복', 'ㅁㄴㅇㄹ', 'ㅋㅋㅋ'
];
var KEYSEQ = ['qwer', 'wert', 'asdf', 'sdfg', 'zxcv', 'qaz', 'wsx', '1q2w', 'abcd', 'bcde'];

function log2(x) { return Math.log(x) / Math.LN2; }

function isSequential(digits) {
  if (digits.length < 3) return false;
  var step = digits.charCodeAt(1) - digits.charCodeAt(0);
  if (step !== 1 && step !== -1) return false;
  for (var i = 2; i < digits.length; i++)
    if (digits.charCodeAt(i) - digits.charCodeAt(i - 1) !== step) return false;
  return true;
}

function runBits(r) {
  var n = r.length, low = r.toLowerCase();
  if (/^\s+$/.test(r)) return 1;
  if (COMMON.indexOf(low) >= 0) return 4;
  if (n > 1 && /^(.)\1+$/.test(r)) return runBits(r[0]) + log2(n);   // 같은 글자 되풀이

  if (/^[가-힣]+$/.test(r)) return Math.min(13.4 * n, 8 + 3.5 * n);  // 한글 낱말
  if (/^[ㄱ-ㆎ]+$/.test(r)) return 4.5 * n;                          // 자모
  if (/^[0-9]+$/.test(r)) {
    if (isSequential(r)) return 4 + log2(n);
    if (/^(19|20)\d\d(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])$/.test(r) ||
        /^\d\d(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])$/.test(r)) return 15;    // 날짜
    if (/^(19|20)\d\d$/.test(r)) return 7;                                   // 연도
    return 3.32 * n;
  }
  if (/^[A-Za-z]+$/.test(r)) {
    for (var i = 0; i < KEYSEQ.length; i++)
      if (low.indexOf(KEYSEQ[i]) >= 0) return 6 + 2 * Math.max(0, n - 4);
    // 짧은 조각은 무작위로 본다. 네 글자가 넘으면 사전 낱말일 가능성이 높으므로
    // 길이에 비례해 쳐 주지 않는다 (낱말 하나 ≈ 사전 5만 개 ≈ 15비트).
    // 무작위 영문 긴 열은 낮게 잡히지만, 부풀리는 쪽보다는 안전한 쪽으로 틀린다.
    var b = n <= 3 ? 4.7 * n : Math.min(4.7 * n, 12 + 1.2 * (n - 4));
    if (/[a-z]/.test(r.slice(1)) && /[A-Z]/.test(r.slice(1))) b += 1;  // 중간에 섞인 대문자
    return b;
  }
  return 5 * n;   // 기호
}

function passwordBits(p) {
  var low = p.toLowerCase().trim();
  if (COMMON.indexOf(low) >= 0 || COMMON.indexOf(low.replace(/\s+/g, '')) >= 0) return 3;
  var rep = /^(.+?)\1+$/.exec(p);   // abcabc, 사랑사랑 처럼 통째로 되풀이
  if (rep) return passwordBits(rep[1]) + log2(p.length / rep[1].length);

  var runs = p.match(/[가-힣]+|[ㄱ-ㆎ]+|[A-Za-z]+|[0-9]+|\s+|[^가-힣ㄱ-ㆎA-Za-z0-9\s]+/g) || [];
  var bits = 0, pieces = 0;
  runs.forEach(function (r) {
    bits += runBits(r);
    if (!/^\s+$/.test(r)) pieces++;
  });
  // 조각이 어떤 종류로 어떤 순서로 이어지는지도 공격자는 모른다
  bits += 1.5 * Math.max(0, pieces - 1);
  return Math.max(1, bits);
}

// OWASP는 scrypt(N=2^16, r=8, p=2)를 PBKDF2-SHA256 60만 회와 같은 강도로 본다.
  // GPU 한 장 ≈ 초당 5만 번(PBKDF2 20만 회 기준)의 1/3 ≈ 1.7만 번, 이를 100장.
  var GUESSES_PER_SEC = 1.7e6;

function humanTime(sec) {
  if (sec < 1) return '1초도 안 걸림';
  if (sec < 60) return Math.round(sec) + '초';
  if (sec < 3600) return Math.round(sec / 60) + '분';
  if (sec < 86400) return Math.round(sec / 3600) + '시간';
  var y = sec / 31536000;
  if (y < 1) return Math.round(sec / 86400) + '일';
  if (y < 1e4) return Math.round(y).toLocaleString('ko-KR') + '년';
  if (y < 1e8) return Math.round(y / 1e4).toLocaleString('ko-KR') + '만 년';
  if (y < 1e12) return Math.round(y / 1e8).toLocaleString('ko-KR') + '억 년';
  return '1조 년 넘게';
}

function strength(p) {
  if (!p) return { level: 0, fill: 0, label: '자물쇠 없음',
                   detail: '코드만 있으면 누구나 풉니다. 압축만 됩니다.' };
  var bits = passwordBits(p);
  var level = bits < 28 ? 1 : bits < 40 ? 2 : bits < 50 ? 3 : bits < 64 ? 4 : 5;
  var sec = Math.pow(2, bits - 1) / GUESSES_PER_SEC;
  var detail = level === 5 ? '사실상 뚫을 수 없음' : '뚫는 데 대략 ' + humanTime(sec);
  if (level <= 2) detail += ' · 낱말 네댓 개를 띄어 쓰면 강해집니다';
  return {
    level: level, bits: bits,
    fill: Math.max(6, Math.min(100, bits / 72 * 100)),
    label: ['', '매우 약함', '약함', '보통', '강함', '매우 강함'][level],
    detail: detail
  };
}

function updateMeter() {
  if (mode !== 'enc') { meter.style.display = 'none'; return; }
  meter.style.display = '';
  var s = strength(pw.value);
  meter.setAttribute('data-level', String(s.level));
  meterFill.style.width = s.fill + '%';
  meterText.textContent = '';
  var b = document.createElement('b');
  b.textContent = s.label;
  meterText.appendChild(b);
  meterText.appendChild(document.createTextNode(' — ' + s.detail));
}

pw.addEventListener('input', updateMeter);

// ════════════════════════════════════════════════════════════════
//  화면
// ════════════════════════════════════════════════════════════════
function setMode(next) {
  mode = next;
  var enc = mode === 'enc';
  tabEnc.setAttribute('aria-selected', String(enc));
  tabDec.setAttribute('aria-selected', String(!enc));
  inputLabel.textContent = enc ? '숨길 글' : '받은 암호문';
  inputText.placeholder = enc ? '여기에 적으십시오'
                              : '암호문이나 받은 링크를 붙여 넣으십시오';
  inputText.classList.toggle('cipher', !enc);
  outputLabel.textContent = enc ? '봉인된 글' : '풀어낸 글';
  output.classList.toggle('cipher', enc);
  modeField.style.display = enc ? '' : 'none';
  segWrap.style.display = enc ? '' : 'none';
  copyLink.style.display = enc ? '' : 'none';
  go.textContent = enc ? '봉인하기' : '해독하기';
  pw.placeholder = enc ? '비워 두면 자물쇠 없이 눌러 담기만 합니다' : '봉인할 때 쓴 열쇠말';
  notice.classList.remove('show');
  hide();
  updateMeter();
}

tabEnc.onclick = function () { setMode('enc'); };
tabDec.onclick = function () { setMode('dec'); };

pwToggle.onclick = function () {
  var showing = pw.type === 'text';
  pw.type = showing ? 'password' : 'text';
  pwToggle.textContent = showing ? '보임' : '감춤';
};

function hide() {
  result.classList.remove('show');
  errorBox.classList.remove('show');
}

function fail(message) {
  result.classList.remove('show');
  errorBox.textContent = message;
  errorBox.classList.add('show');
}

// 전신 암호문처럼 다섯 자씩 끊는다. 두 구현 모두 공백을 버리고 읽으므로
// 이대로 붙여 넣어도 그대로 풀린다.
function group(token) {
  return token.replace(/.{1,5}/g, '$& ').trim();
}

var MODE_OPTS = {
  normal: { seedLen: 6, tagLen: 4 },
  min: { seedLen: 0, tagLen: 0 },
  strong: { seedLen: 8, tagLen: 16 }
};

function selectedMode() {
  return document.querySelector('input[name="mode"]:checked').value;
}

// Worker 없이 이 스레드에서 계산할 때만, "봉인하는 중"을 먼저 그리도록 한 프레임 양보한다
function nextFrame() {
  if (engine.inWorker()) return Promise.resolve();
  return new Promise(function (r) { requestAnimationFrame(function () { setTimeout(r, 0); }); });
}

// 봉인 결과를 현재 표기로 다시 그린다 (다시 암호화하지 않는다)
function renderSealed() {
  if (!lastBlob) return;
  var token = encoding === 'han' ? HC.toHangul(lastBlob) : HC.toToken(lastBlob);
  lastToken = token;
  output.value = group(token);
  note.textContent = encoding === 'han'
    ? '한글 음절 하나에 13비트를 담았습니다. 다섯 자씩 끊어 두었고, 공백은 버리고 읽습니다.'
    : '영문·숫자만 받는 곳에 붙일 때 쓰십시오. 공백은 버리고 읽습니다.';
  var rawLen = new TextEncoder().encode(inputText.value).length;
  var other = encoding === 'han' ? HC.toToken(lastBlob).length : HC.toHangul(lastBlob).length;
  stats.innerHTML =
    '원문 <b>' + rawLen + '자</b>' +
    '　→　봉인 <b>' + lastBlob.length + '자</b>' +
    (rawLen ? '　(<b>' + Math.round(lastBlob.length / rawLen * 100) + '%</b>)' : '') +
    '　·　<b>' + token.length + '글자</b>' +
    '<span class="alt"> (' + (encoding === 'han' ? '영문이면' : '한글이면') +
    ' ' + other + '글자)</span>' +
    '　·　<b>' + lastMs + 'ms</b>';
  segHan.setAttribute('aria-pressed', String(encoding === 'han'));
  segB85.setAttribute('aria-pressed', String(encoding === 'b85'));
}

segHan.onclick = function () { encoding = 'han'; renderSealed(); };
segB85.onclick = function () { encoding = 'b85'; renderSealed(); };

async function run() {
  hide();
  var text = inputText.value;
  var password = pw.value ? pw.value : null;

  if (mode === 'dec' && !text.trim()) { fail('풀어낼 암호문을 붙여 넣으십시오.'); return; }

  var label = go.textContent;
  go.disabled = true;
  go.textContent = mode === 'enc' ? '봉인하는 중…' : '해독하는 중…';
  await nextFrame();

  var t0 = performance.now();
  try {
    if (mode === 'enc') {
      lastBlob = await engine.encrypt(text, password,
          Object.assign({ pad: padBox.checked }, MODE_OPTS[selectedMode()]));
      lastMs = Math.round(performance.now() - t0);
      renderSealed();
    } else {
      var plain = await engine.decrypt(blobFromText(text), password);
      lastBlob = null;
      lastToken = plain;
      output.value = plain;
      note.textContent = '';
      stats.innerHTML = '봉인을 풀었습니다.　·　<b>' + plain.length + '자</b>' +
        '　·　<b>' + Math.round(performance.now() - t0) + 'ms</b>';
      notice.classList.remove('show');
    }
    result.classList.add('show');
  } catch (e) {
    fail(e && e.message ? e.message : String(e));
  } finally {
    go.disabled = false;
    go.textContent = label;
  }
}

go.onclick = run;

// Ctrl/Cmd + Enter 로 실행
inputText.addEventListener('keydown', function (e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); run(); }
});
pw.addEventListener('keydown', function (e) {
  if (e.key === 'Enter') { e.preventDefault(); run(); }
});

async function copyText(s) {
  try { await navigator.clipboard.writeText(s); return; } catch (e) { /* 아래로 */ }
  var ta = document.createElement('textarea');
  ta.value = s;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); } finally { document.body.removeChild(ta); }
}

function flash(btn, done, normal) {
  btn.textContent = done;
  setTimeout(function () { btn.textContent = normal; }, 1400);
}

copy.onclick = async function () {
  await copyText(lastToken);
  flash(copy, '베꼈음', '베끼기');
};

copyLink.onclick = async function () {
  if (!lastBlob) return;
  await copyText(linkFor(lastBlob));
  flash(copyLink, '베꼈음', '링크');
  note.textContent = '링크를 베꼈습니다. 링크에는 암호문만 들어 있으니, ' +
    '열쇠말은 반드시 다른 길로 전하십시오.';
};

// ── 링크로 들어왔을 때 ─────────────────────────────────────────
function receiveFromHash() {
  var m = /^#s=([A-Za-z0-9_-]+)$/.exec(location.hash);
  if (!m) return;
  // 주소창과 방문 기록에서 암호문을 걷어낸다
  try { history.replaceState(null, '', pageUrl()); } catch (e) { /* 무시 */ }
  setMode('dec');
  var blob;
  try { blob = fromB64url(m[1]); } catch (e) { fail(e.message); return; }
  inputText.value = group(HC.toHangul(blob));
  var keyed = !!(blob[0] & 0x40);
  notice.textContent = keyed
    ? '링크로 받은 밀서입니다. 열쇠말을 넣고 해독하십시오.'
    : '링크로 받은 밀서입니다. 자물쇠가 채워지지 않은 글이라 바로 풀었습니다.';
  notice.classList.add('show');
  if (keyed) pw.focus();
  else run();
}

window.addEventListener('hashchange', receiveFromHash);

setMode('enc');
receiveFromHash();

// 첫 봉인을 기다리지 않도록 뒤에서 예열을 미리 해 둔다 (Worker일 때만)
if (engine.inWorker()) engine.prime().catch(function () { /* 봉인할 때 다시 한다 */ });
})();
