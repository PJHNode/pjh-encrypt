#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hangul_crypt.py의 CORPUS를 hangul_crypt.js로 복사한다.

두 구현이 같은 코퍼스를 써야만 서로 만든 데이터를 풀 수 있다.
코퍼스를 수정했다면 이 스크립트를 실행해 JS 쪽을 맞춰야 한다.

    python tools/sync_corpus.py

JS에는 \\uXXXX 로 이스케이프해서 넣는다. 파일이 순수 ASCII가 되므로
스크립트가 어떤 인코딩으로 해석되든 코퍼스 바이트가 달라지지 않는다.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY = ROOT / 'hangul_crypt.py'
JS = ROOT / 'hangul_crypt.js'

BEGIN = '  // >>> CORPUS-BEGIN (자동 생성) >>>'
END = '  // <<< CORPUS-END <<<'


def main():
    sys.path.insert(0, str(ROOT))
    import hangul_crypt

    corpus = hangul_crypt.CORPUS
    literal = json.dumps(corpus, ensure_ascii=True)

    js = JS.read_text(encoding='utf-8')
    block = f'{BEGIN}\n  var CORPUS = {literal};\n{END}'
    new, count = re.subn(
        re.escape(BEGIN) + r'.*?' + re.escape(END),
        lambda _: block,
        js,
        flags=re.S,
    )
    if count != 1:
        print(f'오류: CORPUS 블록 표시를 {count}개 찾았습니다 (1개여야 함).', file=sys.stderr)
        return 1

    if new == js:
        print('이미 동기화되어 있습니다.')
        return 0

    JS.write_text(new, encoding='utf-8')
    print(f'{JS.name} 갱신됨 — 코퍼스 {len(corpus)}자 '
          f'({len(corpus.encode("utf-8"))}바이트, 지문 0x{hangul_crypt.CORPUS_FP:02x})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
