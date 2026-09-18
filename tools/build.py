#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""만들어지는 파일 두 개를 원본에서 다시 만든다.

    python tools/build.py          # 만들기
    python tools/build.py --check  # 원본과 맞는지만 본다 (CI용, 다르면 실패)

  milseo.html — 한 파일 판. CSS·JS를 모두 안에 넣었다. 내려받아 두면 인터넷 없이,
                그리고 사이트가 바뀌어도 지금 판 그대로 쓸 수 있다. 글꼴은 넣지 않아
                (3MB) 기기의 명조체로 보인다. Worker 없이 화면 쪽에서 계산한다.
                인라인 스크립트는 CSP 해시로 허용하므로 다른 스크립트는 여전히 막힌다.
  sw.js       — 서비스 워커. 담아 둘 파일 목록과, 그 내용으로 만든 판 번호를 넣는다.
                파일이 하나라도 바뀌면 판 번호가 바뀌어 브라우저가 새로 받는다.

순서: milseo.html → 그 해시를 index.html에 적음 → index.html까지 포함해 sw.js.
"""
import base64
import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def read(name):
    return (ROOT / name).read_text(encoding='utf-8')


def csp_hash(text):
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode('utf-8')).digest()).decode() + "'"


def build_single():
    html = read('index.html')
    css = read('style.css')
    lib = read('hangul_crypt.js')
    app = read('app.js')

    # 한 파일 판은 Worker 파일이 없으므로 처음부터 화면 쪽에서 계산한다
    app = app.replace("worker = new Worker('worker.js');",
                      "throw new Error('한 파일 판은 Worker 없이 돈다');")
    assert 'Worker 없이 돈다' in app

    icon = base64.b64encode((ROOT / 'icons/icon.svg').read_bytes()).decode()
    head_old = html[html.index('<link rel="icon"'):html.index('</head>')]
    csp = ("default-src 'none'; script-src " + csp_hash(lib) + ' ' + csp_hash(app) +
           '; style-src ' + csp_hash(css) + "; img-src data:; connect-src 'none'; "
           "base-uri 'none'; form-action 'none'")
    head_new = (f'<link rel="icon" href="data:image/svg+xml;base64,{icon}">\n'
                f'<meta http-equiv="Content-Security-Policy" content="{csp}">\n'
                f'<style>{css}</style>\n')
    out = html.replace(head_old, head_new)
    # 한 파일 판에서 스스로를 내려받으라는 안내는 뜻이 없다
    out = re.sub(r'\s*<li>한 번 열면 <b>인터넷 없이도</b>.*?</li>', '', out, flags=re.S)
    out = out.replace('<script src="hangul_crypt.js"></script>', f'<script>{lib}</script>')
    out = out.replace('<script src="app.js"></script>', f'<script>{app}</script>')
    out = out.replace('<title>밀서 密書</title>', '<title>밀서 密書 (한 파일 판)</title>')
    # 밖에서 불러오는 것이 하나도 남지 않아야 한다
    head = out.split('<body>')[0]
    for leftover in ('href="style.css"', 'href="fonts/', 'rel="manifest"', 'href="icons/'):
        assert leftover not in head, leftover
    assert '<script src=' not in out
    return out


def with_single_hash(html, digest):
    return re.sub(r'(<code class="hash" id="singleHash">)[^<]*(</code>)',
                  lambda m: m.group(1) + digest + m.group(2), html)


def sw_files():
    files = ['index.html', 'app.js', 'style.css', 'hangul_crypt.js', 'worker.js',
             'manifest.webmanifest', 'icons/icon.svg', 'icons/icon-192.png',
             'icons/icon-512.png', 'fonts/fonts.css']
    files += sorted('fonts/' + p.name for p in (ROOT / 'fonts').glob('*.woff2'))
    return files


TEXT_EXT = ('.html', '.js', '.css', '.webmanifest', '.svg', '.json', '.txt')


def file_bytes(name):
    """판 번호 계산용 내용. 텍스트 파일은 줄바꿈을 LF로 맞춘다.

    Windows 작업본은 git 설정에 따라 CRLF일 수 있고 레포·배포본은 LF다. 바이트를 그대로
    해시하면 운영체제마다 판 번호가 달라져 CI의 --check가 실패한다(실제로 그랬다).
    """
    data = (ROOT / name).read_bytes()
    return data.replace(b'\r\n', b'\n') if name.endswith(TEXT_EXT) else data


def build_sw(index_html):
    h = hashlib.sha256()
    for name in sw_files():
        data = index_html.encode('utf-8') if name == 'index.html' else file_bytes(name)
        h.update(name.encode() + b'\0' + data + b'\0')
    version = h.hexdigest()[:12]
    listing = ',\n'.join(f"  '{f}'" for f in sw_files())
    return f"""/*
 * 밀서 — 서비스 워커. tools/build.py 가 만든다. 손으로 고치지 말 것.
 *
 * 페이지와 글꼴을 모두 담아 두어 인터넷 없이도 열리게 한다. 담아 둔 파일이 있으면
 * 그것을 먼저 쓰고(cache-first), 없는 것만 네트워크로 받는다. 파일이 하나라도
 * 바뀌면 아래 판 번호가 바뀌고, 브라우저는 새 판을 받아 다음에 열 때부터 쓴다.
 */
const VERSION = '{version}';
const CACHE = 'milseo-' + VERSION;
const FILES = [
{listing}
];

self.addEventListener('install', (e) => {{
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES)).then(() => self.skipWaiting()));
}});

self.addEventListener('activate', (e) => {{
  e.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys
      .filter((k) => k.startsWith('milseo-') && k !== CACHE)
      .map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
}});

self.addEventListener('fetch', (e) => {{
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  const key = url.pathname.endsWith('/') ? new URL('index.html', url).href : url.origin + url.pathname;
  e.respondWith(caches.open(CACHE)
    .then((c) => c.match(key))
    .then((hit) => hit || fetch(req)));
}});
"""


def main():
    check = '--check' in sys.argv
    single = build_single()
    digest = hashlib.sha256(single.encode('utf-8')).hexdigest()
    index = with_single_hash(read('index.html'), digest)
    sw = build_sw(index)

    outputs = {'milseo.html': single, 'index.html': index, 'sw.js': sw}
    stale = [n for n, text in outputs.items()
             if not (ROOT / n).exists() or (ROOT / n).read_text(encoding='utf-8') != text]
    if check:
        if stale:
            print('만들어진 파일이 원본과 다릅니다: ' + ', '.join(stale))
            print('python tools/build.py 를 돌리고 함께 올리세요.')
            return 1
        print('만들어진 파일이 모두 최신입니다.')
        return 0
    for n in stale:
        (ROOT / n).write_text(outputs[n], encoding='utf-8', newline='\n')
    print(f'milseo.html {len(single.encode()) / 1024:.0f}KB  sha256 {digest[:16]}…')
    print(f'sw.js 판 {sw.split(chr(39))[1]}, 담아 둘 파일 {len(sw_files())}개')
    print('바뀐 파일: ' + (', '.join(stale) if stale else '없음'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
