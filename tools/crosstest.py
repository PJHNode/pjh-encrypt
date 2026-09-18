#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Python 구현과 JS 구현의 호환성을 양방향으로 검사한다.

    python tools/crosstest.py

절차
  1. Python으로 테스트 벡터를 만든다 (CM 압축 결과, base85 토큰, 암호문).
  2. node tools/crosstest.js 로 JS가 같은 결과를 내는지 확인한다.
  3. JS가 만든 토큰을 다시 Python으로 복호화해 역방향도 확인한다.
"""
import base64
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import hangul_crypt as hc  # noqa: E402

SAMPLES = [
    '안녕하세요',
    '내일 세 시에 강남역에서 만나요',
    '비밀번호는 내 생일이야. 절대 다른 사람한테 말하지 마.',
    '오늘 수학 숙제는 삼차함수의 극값을 구하는 문제였다. 처음에는 판별식만 쓰면 될 줄 '
    '알았는데, 매개변수가 두 개라 훨씬 복잡했다.',
    'Mixed 한글 and English 123 !@# 섞인 텍스트 테스트',
    '가' * 300,
    '',
    'ㅋㅋㅋ 이모지도 되나 🙂🎉 되는지 보자',
    '줄바꿈\n탭\t따옴표"백슬래시\\ 특수문자 테스트',
]


def main():
    print('테스트 벡터 생성 중 (Python)...')
    vectors = {'compress': [], 'token': [], 'decrypt': [], 'encrypt': []}

    for s in SAMPLES:
        raw = s.encode('utf-8')
        vectors['compress'].append({
            'text': s,
            'cm': base64.b64encode(hc.cm_compress(raw)).decode(),
        })

    # base85 벡터: 길이 % 4 가 0/1/2/3 인 경우를 모두 포함시킨다
    for n in (0, 1, 2, 3, 4, 5, 7, 11, 64):
        blob = bytes((i * 37 + 11) & 255 for i in range(n))
        vectors['token'].append({
            'blob': base64.b64encode(blob).decode(),
            'token': hc.to_token(blob),
        })

    # Python이 암호화 → JS가 복호화. lzma를 고르면 JS가 못 푸니 cm/raw로 강제한다.
    for s in SAMPLES:
        for pw, opts in (('테스트pw', {}), (None, {}),
                         ('pw', {'seed_len': 0, 'tag_len': 0}),
                         ('pw', {'seed_len': 8, 'tag_len': 16})):
            blob = hc.encrypt(s, pw, method='auto' if len(s) < 100 else 'cm', **opts)
            if blob[0] & 3 == 2:      # lzma가 이긴 경우는 cm으로 다시 만든다
                blob = hc.encrypt(s, pw, method='cm', **opts)
            vectors['decrypt'].append({
                'text': s, 'password': pw, 'token': hc.to_token(blob),
            })

    for s in SAMPLES:
        vectors['encrypt'].append({'text': s, 'password': '왕복-pw'})
        vectors['encrypt'].append({'text': s, 'password': None})
    vectors['encrypt'].append({'text': '최소 모드', 'password': 'pw',
                               'opts': {'seedLen': 0, 'tagLen': 0}})
    vectors['encrypt'].append({'text': '강화 모드', 'password': 'pw',
                               'opts': {'seedLen': 8, 'tagLen': 16}})

    with tempfile.TemporaryDirectory() as td:
        vec_path = pathlib.Path(td) / 'vectors.json'
        out_path = pathlib.Path(td) / 'produced.json'
        vec_path.write_text(json.dumps(vectors), encoding='utf-8')

        print(f'벡터 {sum(len(v) for v in vectors.values())}개 생성. JS 검증 시작...\n')
        r = subprocess.run(
            ['node', str(ROOT / 'tools' / 'crosstest.js'), str(vec_path), str(out_path)],
            cwd=str(ROOT),
        )
        js_failed = r.returncode != 0

        print('\n[6] JS 암호화 → Python 복호화')
        py_failed = 0
        if out_path.exists():
            produced = json.loads(out_path.read_text(encoding='utf-8'))['produced']
            for item in produced:
                try:
                    got = hc.decrypt(hc.from_token(item['token']), item['password'])
                    ok = got == item['text']
                    note = '' if ok else f'  (받은 값: {got[:30]!r})'
                except Exception as e:
                    ok, note = False, f'  — {e}'
                if not ok:
                    py_failed += 1
                print(('  OK   ' if ok else '  FAIL ') + repr(item['text'][:22]) + note)
        else:
            print('  (JS가 결과 파일을 만들지 못했습니다)')
            py_failed = 1

    print()
    if js_failed or py_failed:
        print(f'실패: JS 단계 {"실패" if js_failed else "통과"}, '
              f'Python 역방향 {py_failed}건 실패')
        return 1
    print('전체 결과: 통과 — Python과 JS가 완전히 호환됩니다.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
