#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""밀서 웹 페이지를 PJH Hub의 encrypt/ 폴더로 내보낸다.

    python tools/export_hub.py ../PJH-hub            # 내보내기
    python tools/export_hub.py ../PJH-hub --check    # 허브 사본이 최신인지만 본다

원본은 이 레포다. 허브 사본은 손으로 고치지 말고, 여기서 고친 뒤 다시 내보낸다.
허브에 맞춰 바꾸는 것은 index.html 머리말 몇 줄뿐이다:
  - 허브로 돌아가는 「← PJH Hub」 링크 (허브의 다른 앱들과 같은 관례)
  - 제목 「밀서 — PJH Hub」와 링크 미리보기용 og 태그
암호 코드(hangul_crypt.js)와 한 파일 판(milseo.html)은 한 바이트도 바꾸지 않는다.
한 파일 판은 인라인 스크립트의 CSP 해시로 돌고, 페이지에 그 파일의 SHA-256을 적어
두었기 때문이다. 허브 빌드(build-dist.mjs)도 encrypt/는 그대로 복사하게 해 두었다.
"""
import filecmp
import pathlib
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

FILES = ['index.html', 'app.js', 'style.css', 'hangul_crypt.js', 'worker.js', 'sw.js',
         'manifest.webmanifest', 'milseo.html']
DIRS = ['icons', 'fonts']

BACK = '''    <a class="hub-back" href="../">← PJH Hub</a>
'''
OG = '''<meta property="og:site_name" content="PJH Hub">
<meta property="og:type" content="website">
<meta property="og:title" content="밀서 密書 — PJH Hub">
<meta property="og:description" content="한글을 잘게 눌러 담아 암호로 봉인합니다. 열쇠말·공개키로 잠그고 링크로 보냅니다. 모든 처리는 이 기기 안에서만 이루어집니다.">
<meta property="og:image" content="icons/icon-512.png">
'''


def hub_index(src):
    out = src.replace('<title>밀서 密書</title>', '<title>밀서 密書 — PJH Hub</title>\n' + OG.rstrip('\n'), 1)
    out = out.replace('  <header>\n', '  <header>\n' + BACK, 1)
    assert '← PJH Hub' in out and 'og:title' in out, 'index.html 모양이 예상과 다릅니다'
    return out


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    if not args:
        print(__doc__)
        return 2
    hub = pathlib.Path(args[0]).resolve()
    if not (hub / 'build-dist.mjs').exists():
        print(f'{hub} 는 PJH Hub 저장소가 아닌 것 같습니다 (build-dist.mjs 없음).')
        return 2
    dest = hub / 'encrypt'
    check = '--check' in sys.argv

    want = {}
    for name in FILES:
        if name == 'index.html':
            want[name] = hub_index((ROOT / name).read_text(encoding='utf-8')).encode('utf-8')
        else:
            want[name] = (ROOT / name).read_bytes()
    for d in DIRS:
        for f in sorted((ROOT / d).iterdir()):
            want[f'{d}/{f.name}'] = f.read_bytes()

    stale = [n for n, data in want.items()
             if not (dest / n).exists() or (dest / n).read_bytes() != data]
    extra = [str(p.relative_to(dest)).replace('\\', '/') for p in dest.rglob('*')
             if p.is_file() and str(p.relative_to(dest)).replace('\\', '/') not in want] \
        if dest.exists() else []

    if check:
        if stale or extra:
            print('허브 사본이 원본과 다릅니다.')
            for n in stale: print('  바뀜  ', n)
            for n in extra: print('  남는 것', n)
            return 1
        print(f'허브 사본이 최신입니다 ({len(want)}개 파일).')
        return 0

    for n in stale:
        (dest / n).parent.mkdir(parents=True, exist_ok=True)
        (dest / n).write_bytes(want[n])
    for n in extra:
        (dest / n).unlink()
    print(f'{dest} 로 내보냄 — 바뀐 파일 {len(stale)}개, 지운 파일 {len(extra)}개, 전체 {len(want)}개')
    return 0


if __name__ == '__main__':
    sys.exit(main())
