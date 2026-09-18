#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hangul_crypt.py — 한글 텍스트 초압축 + 암호화 도구

설계 요약
  1) 압축: 한국어 코퍼스로 미리 '예열'한 문맥혼합(Context Mixing) 산술부호화기.
           gzip/bzip2/xz보다 한국어에서 2~3배 더 짧다.
  2) 암호: ChaCha20 스트림 암호(순수 파이썬) + HMAC-SHA256 인증 태그.
           스트림 암호라 암호화해도 길이가 전혀 늘지 않는다.
  3) 키:   비밀번호 → PBKDF2-HMAC-SHA256(200,000회)로 키 유도.

표준 라이브러리만 사용. 설치 불필요.

사용법
  python hangul_crypt.py enc -k 비밀번호 "숨길 내용"
  python hangul_crypt.py dec -k 비밀번호 "출력된토큰"
  python hangul_crypt.py enc -k pw -i 입력.txt -o 출력.bin
  python hangul_crypt.py dec -k pw -i 출력.bin
  python hangul_crypt.py selftest
"""

import sys, os, math, time, hmac, hashlib, struct, base64, argparse
from array import array

# ════════════════════════════════════════════════════════════════════
#  1. 예열 코퍼스 — 압축기가 한국어를 '미리 알고 있게' 만드는 부분
#     이 내용이 바뀌면 이전에 암호화한 데이터는 풀 수 없다.
#     (헤더에 지문 1바이트를 넣어 불일치를 감지한다)
# ════════════════════════════════════════════════════════════════════
CORPUS = """\
이 그 저 것 수 등 들 및 첫 한 두 세 네 때 곳 말 일 년 월 일 시 분 초 중 후 전 안 밖 위 아래 앞 뒤 옆 속 사이 동안 대로 만큼 처럼 보다 부터 까지 에게 에서 으로 로서 로써 와 과 하고 이나 거나 지만 는데 니까 어서 아서 면서 려고 도록 게끔 든지 라도 조차 마저 뿐 따름 때문 덕분 탓 경우 정도 무렵 즈음
하다 되다 있다 없다 같다 다르다 크다 작다 많다 적다 좋다 나쁘다 새롭다 오래되다 쉽다 어렵다 빠르다 느리다 높다 낮다 길다 짧다 넓다 좁다 깊다 얕다 밝다 어둡다 따뜻하다 차갑다 조용하다 시끄럽다 가볍다 무겁다 강하다 약하다 중요하다 필요하다 가능하다 불가능하다 분명하다 확실하다 자연스럽다 적절하다 충분하다 부족하다
합니다 습니다 입니다 했습니다 됩니다 있습니다 없습니다 갑니다 옵니다 봅니다 같습니다 드립니다 주십시오 바랍니다 하였다 이었다 하는 되는 있는 없는 하지만 그러나 그래서 따라서 그리고 또한 즉 다만 오히려 물론 사실 결국 마침내 비로소 이미 아직 벌써 곧 늘 항상 자주 가끔 때때로 거의 전혀 결코 반드시 아마 어쩌면 만약 비록 설령
나는 너는 우리는 그는 그녀는 사람들은 아이들은 학생들은 선생님은 부모님은 친구들과 동생과 형과 누나와 언니와 오빠와 가족과 이웃과 사회는 국가는 정부는 기업은 시장은 학교는 교실은 도서관에서 운동장에서 집에서 방에서 거리에서 공원에서 카페에서 회사에서 병원에서 역에서
오늘 아침에 일어나서 창문을 열었더니 바람이 선선하게 들어왔다. 어제보다 확실히 공기가 차가워진 느낌이었다. 간단하게 밥을 먹고 가방을 챙겨서 집을 나섰다. 버스 정류장까지 걸어가는 동안 낙엽이 발밑에서 바스락거렸다. 시간이 참 빠르게 지나간다는 생각이 들었다. 요즘은 하루하루가 비슷하게 흘러가는 것 같으면서도, 돌아보면 조금씩 달라져 있다.
학교에 도착해서 첫 수업을 들었다. 선생님께서 지난 시간에 배운 내용을 다시 정리해 주셨는데, 그제야 이해가 되는 부분이 있었다. 역시 한 번에 알아듣기는 어렵고, 여러 번 반복해서 봐야 한다는 걸 다시 느꼈다. 쉬는 시간에는 친구들과 이야기를 나누었다. 별것 아닌 대화였지만 웃으면서 시간을 보내니 기분이 나아졌다.
수학 문제를 풀 때는 먼저 조건을 정리하는 것이 중요하다. 주어진 식을 그대로 계산하려고 하면 복잡해지는 경우가 많다. 함수의 그래프를 그려보거나, 대칭성을 이용하거나, 변수를 치환하면 훨씬 간단해진다. 이차함수의 최댓값과 최솟값은 꼭짓점을 구하면 바로 알 수 있고, 삼차함수는 미분해서 극값을 찾아야 한다. 부등식을 다룰 때는 양변에 음수를 곱하면 부등호의 방향이 바뀐다는 점을 잊지 말아야 한다.
정답을 맞히는 것보다 왜 그렇게 되는지를 설명할 수 있는 것이 더 중요하다고 생각한다. 풀이 과정을 다시 써보면 자신이 어디에서 헷갈렸는지 알게 된다. 문제를 많이 푸는 것도 필요하지만, 틀린 문제를 제대로 분석하는 편이 훨씬 효율적이다. 개념을 정확히 알고 있으면 처음 보는 유형이 나와도 접근할 방법을 찾을 수 있다.
집합과 명제, 함수와 수열, 미분과 적분, 확률과 통계는 서로 연결되어 있다. 하나의 단원을 공부할 때도 다른 단원과 어떤 관계가 있는지 생각하면 이해가 깊어진다. 예를 들어 수열의 극한은 함수의 극한과 같은 아이디어를 공유하고, 적분은 넓이와 부피를 계산하는 도구로 쓰인다.
과학 시간에는 실험을 했다. 가설을 세우고, 변인을 통제하고, 결과를 기록하는 과정이 생각보다 까다로웠다. 예상과 다른 값이 나왔을 때 무엇이 잘못되었는지 찾는 것이 진짜 공부라는 말이 이해가 됐다. 온도와 압력, 부피의 관계, 힘과 운동의 법칙, 에너지의 보존, 세포와 유전, 물질의 상태 변화 같은 개념들이 하나씩 자리를 잡아가고 있다.
사회 문제에 관한 책을 읽었다. 저자는 개인의 노력만으로 해결할 수 없는 구조적인 문제들이 있다고 말했다. 교육 격차, 주거 불안정, 환경 오염, 정보 격차, 고령화, 청년 실업 같은 주제들이 다뤄졌다. 어느 하나도 단순한 원인으로 설명되지 않았다. 여러 요인이 복잡하게 얽혀 있고, 해결책 역시 여러 방향에서 동시에 접근해야 한다는 점이 인상적이었다.
특히 기억에 남는 것은 책임의 문제였다. 어떤 일이 잘못되었을 때 누구의 잘못인지를 따지는 것도 필요하지만, 그보다 먼저 어떤 조건이 그런 결과를 만들었는지를 살펴야 한다는 주장이었다. 개인을 탓하는 방식은 쉽고 빠르지만, 같은 문제가 반복되는 것을 막지는 못한다.
디지털 기술이 우리 삶을 바꾸고 있다는 이야기는 이제 새롭지 않다. 다만 그 변화가 모두에게 같은 방식으로 다가오지는 않는다. 어떤 사람에게는 편리함이지만, 다른 사람에게는 새로운 장벽이 되기도 한다. 기술을 어떻게 설계하고 누구를 기준으로 만드는지가 중요한 이유다.
인공지능에 관한 논의도 마찬가지다. 기술 자체의 성능만 이야기할 것이 아니라, 그것이 사회에서 어떤 역할을 하게 되는지, 누가 이익을 얻고 누가 불이익을 받는지를 함께 생각해야 한다. 편리해지는 만큼 놓치는 것도 생기기 때문이다.
저녁에는 가족들과 함께 밥을 먹었다. 오랜만에 다 같이 모여서 이런저런 이야기를 나누었다. 부모님은 예전 이야기를 하셨고, 동생은 학교에서 있었던 일을 신나게 말했다. 특별한 내용은 아니었지만 그런 시간이 편안하게 느껴졌다.
밤에는 조용히 음악을 들으면서 하루를 정리했다. 잘한 일도 있고 아쉬운 일도 있었다. 내일은 조금 더 일찍 일어나서 여유 있게 준비해야겠다고 생각했다. 계획을 세우는 것은 어렵지 않은데 지키는 것이 늘 문제다. 그래도 조금씩 나아지고 있다고 믿는다.
주말에는 친구와 만나기로 했다. 오랜만에 밖에서 걷고 이야기를 나눌 생각을 하니 기대가 된다. 날씨가 좋으면 공원에 가서 시간을 보내도 좋을 것 같다. 요즘은 바쁘다는 이유로 사람들을 잘 만나지 못했는데, 이런 시간이 결국 가장 오래 기억에 남는다.
안녕하세요. 문의드릴 내용이 있어 연락드립니다. 말씀해 주신 자료를 확인하였으며, 몇 가지 추가로 여쭙고 싶은 점이 있습니다. 가능하시다면 이번 주 중으로 답변 주시면 감사하겠습니다. 바쁘신 중에 시간 내주셔서 감사합니다. 좋은 하루 보내시기 바랍니다.
회의는 다음 주 화요일 오후 두 시에 진행될 예정입니다. 참석이 어려우신 경우 미리 알려주시기 바랍니다. 자료는 회의 전날까지 공유해 드리겠습니다. 논의할 안건은 크게 세 가지입니다. 첫째, 일정 조정에 관한 사항입니다. 둘째, 예산 사용 계획입니다. 셋째, 향후 진행 방향에 대한 의견 수렴입니다.
정부는 어제 관련 대책을 발표했다. 이번 조치는 최근 제기된 문제들에 대응하기 위한 것으로, 다음 달부터 순차적으로 시행된다. 전문가들은 실효성에 대해 엇갈린 평가를 내놓고 있다. 일부는 긍정적인 변화를 기대할 수 있다고 본 반면, 다른 쪽에서는 근본적인 해결에는 한계가 있다고 지적했다. 시민들의 반응도 다양하게 나타났다.
지난해 같은 기간과 비교하면 약 십 퍼센트 증가한 수치다. 조사 결과에 따르면 응답자의 절반 이상이 필요성에 공감한다고 답했다. 다만 구체적인 방법에 대해서는 의견이 나뉘었다. 연구진은 앞으로 더 많은 자료를 수집해 분석할 계획이라고 밝혔다.
그래 알았어 그럼 언제 볼까 나는 아무 때나 괜찮아 너 편한 시간으로 말해줘 오늘은 좀 힘들 것 같고 내일은 어때 응 좋아 그때 보자 고마워 미안해 괜찮아 정말 진짜 대박 아 맞다 그거 어떻게 됐어 잘 됐어 다행이다 수고했어 조심히 가 잘 자 내일 봐
무엇을 어떻게 왜 언제 어디서 누가 얼마나 어떤 그런 이런 저런 이렇게 그렇게 저렇게 아마도 혹시 역시 특히 예를 들어 다시 말해 한편 반면에 그럼에도 불구하고 이에 따라 그 결과 무엇보다 우선 마지막으로 정리하면 요약하자면 결론적으로
생각한다 느꼈다 알았다 몰랐다 배웠다 깨달았다 기억한다 잊었다 바란다 원한다 싫다 좋아한다 궁금하다 걱정된다 안심된다 기대된다 아쉽다 뿌듯하다 답답하다 편안하다 불안하다 즐겁다 지루하다 놀랍다 당황스럽다 고맙다 미안하다
시작하다 끝내다 계속하다 멈추다 바꾸다 고치다 만들다 부수다 늘리다 줄이다 모으다 나누다 찾다 잃다 얻다 주다 받다 보내다 가져오다 올리다 내리다 열다 닫다 넣다 빼다 쌓다 옮기다 정리하다 준비하다 확인하다 결정하다 선택하다 포기하다 도전하다
문제 해결 방법 과정 결과 원인 이유 목적 목표 계획 방향 기준 조건 상황 환경 관계 영향 변화 발전 성장 차이 공통점 특징 장점 단점 한계 가능성 필요성 중요성 의미 가치 기준 역할 책임 권리 의무 규칙 제도 정책 사회 문화 역사 경제 정치 교육 기술 과학 예술 언어 자연 인간
0123456789 abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ .,!?:;()[]"'-~/@#%&*+=<> http https www com net org co.kr
"""
CORPUS_BYTES = CORPUS.encode('utf-8')
CORPUS_FP = hashlib.sha256(CORPUS_BYTES).digest()[0]   # 지문 1바이트


# ════════════════════════════════════════════════════════════════════
#  2. 문맥혼합 압축기 (Context Mixing + 이진 산술부호화)
# ════════════════════════════════════════════════════════════════════
_SQUASH = array('h', [0]) * 4096
for _i in range(4096):
    _SQUASH[_i] = max(1, min(4094, int(4096.0 / (1.0 + math.exp(-(_i - 2048) / 256.0)))))

def _squash(x):
    if x < -2047: x = -2047
    elif x > 2047: x = 2047
    return _SQUASH[x + 2048]

_STRETCH = array('h', [0]) * 4096
_p = 0
for _x in range(-2047, 2048):
    _v = _squash(_x)
    for _j in range(_p, min(_v + 1, 4096)):
        _STRETCH[_j] = _x
    _p = _v + 1
for _j in range(_p, 4096):
    _STRETCH[_j] = 2047

_RATE = array('i', [int(65536 * 2.0 / (c + 2.0)) for c in range(64)])
_LIMIT = 60

ORDERS = [0, 1, 2, 3, 4, 6, 8]      # 직전 n바이트 문맥 (한글 1글자 = 3바이트)
NM = len(ORDERS) + 1                 # + 단어 모델
_BITS = 20
_MASK = (1 << _BITS) - 1
_M64 = (1 << 64) - 1
_MULT = [0x9E3779B97F4A7C15, 0x85EBCA6B, 0xC2B2AE35, 0x27D4EB2F,
         0x165667B19E3779F9, 0x9E3779B1, 0xD6E8FEB8, 0xA0761D6478BD642F]


class _Model:
    """여러 차수의 문맥 예측을 로지스틱 혼합으로 합치고 SSE로 보정한다."""

    def __init__(self):
        self.t = [array('H', [32768]) * (_MASK + 1) for _ in range(NM)]
        self.n = [bytearray(_MASK + 1) for _ in range(NM)]
        self.w = [array('i', [1 << 14]) * NM for _ in range(512)]
        self.apm = array('H', [0]) * (1024 * 33)
        for c in range(1024):
            base = c * 33
            for j in range(33):
                self.apm[base + j] = _squash((j - 16) * 128) * 16
        self.h = [0] * NM
        self.idx = [0] * NM
        self.st = [0] * NM
        self.c0 = 1          # 현재 바이트의 이미 처리된 비트들 (선두 1 포함)
        self.hist = 0        # 직전 8바이트
        self.wh = 0          # 현재 단어 해시
        self.pr = 2048
        self._ai = 0
        self._aw = 0
        self._set_ctx()

    def _set_ctx(self):
        h = self.hist
        for i, o in enumerate(ORDERS):
            self.h[i] = 0 if o == 0 else ((h & ((1 << (8 * o)) - 1)) * _MULT[i % 8]) & _M64
        self.h[NM - 1] = (self.wh * 0x9E3779B97F4A7C15) & _M64

    def predict(self):
        c0 = self.c0
        w = self.w[(c0 & 255) | (256 if self.hist & 128 else 0)]
        cm = c0 * 0x6F4F2F1F
        dot = 0
        for i in range(NM):
            j = (self.h[i] ^ cm) & _MASK
            self.idx[i] = j
            s = _STRETCH[self.t[i][j] >> 4]
            self.st[i] = s
            dot += w[i] * s
        p = _squash(dot >> 16)
        ctx = (c0 & 255) | ((self.hist & 3) << 8)
        s = _STRETCH[p]
        lo = (s + 2048) >> 7
        wt = (s + 2048) & 127
        i0 = ctx * 33 + lo
        self._ai = i0
        self._aw = wt
        pa = (self.apm[i0] * (128 - wt) + self.apm[i0 + 1] * wt) >> 11
        pr = (p + 3 * pa) >> 2
        if pr < 1: pr = 1
        elif pr > 4094: pr = 4094
        self.pr = pr
        return pr

    def update(self, bit):
        g = (bit << 16) + (bit << 4) - bit - bit
        i0 = self._ai; wt = self._aw
        self.apm[i0] += ((g - self.apm[i0]) * (128 - wt)) >> 12
        self.apm[i0 + 1] += ((g - self.apm[i0 + 1]) * wt) >> 12
        err = ((bit << 12) - self.pr) * 10
        w = self.w[(self.c0 & 255) | (256 if self.hist & 128 else 0)]
        tgt = bit << 16
        for i in range(NM):
            w[i] += (self.st[i] * err) >> 13
            j = self.idx[i]
            t = self.t[i]; n = self.n[i]
            c = n[j]
            t[j] += ((tgt - t[j]) * _RATE[c]) >> 17
            if c < _LIMIT: n[j] = c + 1
        self.c0 = (self.c0 << 1) | bit
        if self.c0 >= 256:
            b = self.c0 & 255
            self.hist = ((self.hist << 8) | b) & _M64
            if b >= 128 or 48 <= b <= 57 or 65 <= b <= 122:
                self.wh = (self.wh * 0x2F0FD693 + b + 1) & _M64
            else:
                self.wh = 0
            self.c0 = 1
            self._set_ctx()


class _Encoder:
    __slots__ = ('x1', 'x2', 'out')

    def __init__(self):
        self.x1 = 0; self.x2 = 0xFFFFFFFF; self.out = bytearray()

    def encode(self, bit, p):
        xmid = self.x1 + ((self.x2 - self.x1) >> 12) * p
        if bit: self.x2 = xmid
        else:   self.x1 = xmid + 1
        while (self.x1 ^ self.x2) & 0xFF000000 == 0:
            self.out.append(self.x2 >> 24)
            self.x1 = (self.x1 << 8) & 0xFFFFFFFF
            self.x2 = ((self.x2 << 8) | 255) & 0xFFFFFFFF

    def flush(self):
        # [x1, x2] 안에 들어가는 '뒤가 0인' 가장 짧은 값을 고른다 (최대 3바이트 절약)
        for n in range(1, 5):
            shift = 32 - 8 * n
            v = self.x1 if shift == 0 else (((self.x1 + (1 << shift) - 1) >> shift) << shift)
            if v <= self.x2:
                for i in range(n):
                    self.out.append((v >> (24 - 8 * i)) & 255)
                break
        return bytes(self.out)


class _Decoder:
    __slots__ = ('x1', 'x2', 'd', 'p', 'x')

    def __init__(self, data):
        self.x1 = 0; self.x2 = 0xFFFFFFFF; self.d = data; self.p = 0; self.x = 0
        for _ in range(4):
            self.x = (self.x << 8) | self._nb()

    def _nb(self):
        if self.p < len(self.d):
            b = self.d[self.p]; self.p += 1; return b
        return 0

    def decode(self, p):
        xmid = self.x1 + ((self.x2 - self.x1) >> 12) * p
        bit = 1 if self.x <= xmid else 0
        if bit: self.x2 = xmid
        else:   self.x1 = xmid + 1
        while (self.x1 ^ self.x2) & 0xFF000000 == 0:
            self.x1 = (self.x1 << 8) & 0xFFFFFFFF
            self.x2 = ((self.x2 << 8) | 255) & 0xFFFFFFFF
            self.x = ((self.x << 8) | self._nb()) & 0xFFFFFFFF
        return bit


def _primed_model():
    m = _Model()
    for byte in CORPUS_BYTES:
        for k in (7, 6, 5, 4, 3, 2, 1, 0):
            m.predict()
            m.update((byte >> k) & 1)
    return m


def cm_compress(data: bytes) -> bytes:
    m = _primed_model()
    e = _Encoder()
    for byte in data:
        for k in (7, 6, 5, 4, 3, 2, 1, 0):
            e.encode((byte >> k) & 1, m.predict())
            m.update((byte >> k) & 1)
    return e.flush()


def cm_decompress(blob: bytes, n: int) -> bytes:
    m = _primed_model()
    d = _Decoder(blob)
    out = bytearray()
    for _ in range(n):
        for _k in range(8):
            bit = d.decode(m.predict())
            m.update(bit)
        out.append(m.hist & 255)
    return bytes(out)


# ════════════════════════════════════════════════════════════════════
#  3. 암호 — ChaCha20 (RFC 8439) + HMAC-SHA256
# ════════════════════════════════════════════════════════════════════
def _chacha_block(key32, counter, nonce12):
    s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    s += list(struct.unpack('<8I', key32))
    s.append(counter & 0xFFFFFFFF)
    s += list(struct.unpack('<3I', nonce12))
    x = s[:]

    def qr(a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        v = x[d] ^ x[a]; x[d] = ((v << 16) | (v >> 16)) & 0xFFFFFFFF
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        v = x[b] ^ x[c]; x[b] = ((v << 12) | (v >> 20)) & 0xFFFFFFFF
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        v = x[d] ^ x[a]; x[d] = ((v << 8) | (v >> 24)) & 0xFFFFFFFF
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        v = x[b] ^ x[c]; x[b] = ((v << 7) | (v >> 25)) & 0xFFFFFFFF

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return struct.pack('<16I', *[(x[i] + s[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20(key32: bytes, nonce12: bytes, data: bytes, counter: int = 1) -> bytes:
    out = bytearray(len(data))
    for off in range(0, len(data), 64):
        ks = _chacha_block(key32, counter, nonce12)
        counter += 1
        chunk = data[off:off + 64]
        for i, b in enumerate(chunk):
            out[off + i] = b ^ ks[i]
    return bytes(out)


PBKDF2_ITERS = 200_000

def derive_keys(password: str, seed: bytes):
    """비밀번호 + 시드 → (암호키 32B, 인증키 32B). 코퍼스 지문도 함께 묶는다."""
    salt = b'HGC1' + bytes([CORPUS_FP]) + seed
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERS, 64)
    return dk[:32], dk[32:]


# ════════════════════════════════════════════════════════════════════
#  4. 컨테이너 포맷
#     헤더 1B | [시드 S B] | 암호문 | [태그 T B]
#
#     시드는 솔트와 논스를 겸한다. 메시지마다 시드가 다르면 유도되는 키도
#     달라지므로 별도의 논스를 저장할 필요가 없다 (그만큼 짧아진다).
#
#     헤더 비트:  0-1 방식(0=무압축, 1=CM, 2=lzma)
#                 2-3 시드 길이(0/4/6/8)
#                 4-5 태그 길이(0/4/8/16)
#                 6   키 사용 여부(0=내장 고정키 → 보안 없음, 단순 인코딩)
#                 7   예약
#
#     코퍼스 지문은 키 유도에 섞여 들어간다. 프로그램 버전이 다르면
#     키가 달라져 인증에서 걸러지므로 별도 바이트를 쓰지 않는다.
# ════════════════════════════════════════════════════════════════════
_SEED_OPT = [0, 4, 6, 8]
_TAG_OPT = [0, 4, 8, 16]
_NOKEY_PASSWORD = 'hangul-crypt-no-key'


def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: return bytes(out)


def _read_varint(data, i):
    n = 0; sh = 0
    while True:
        b = data[i]; i += 1
        n |= (b & 0x7F) << sh
        if not (b & 0x80): return n, i
        sh += 7


def encrypt(text: str, password: str = None, *, seed_len=6, tag_len=4,
            method='auto') -> bytes:
    import lzma
    raw = text.encode('utf-8')

    # --- 압축 방식 선택: 셋 다 해보고 가장 짧은 것을 고른다 ---
    cands = []
    if method in ('auto', 'raw'):
        cands.append((0, raw))
    if method in ('auto', 'cm'):
        cands.append((1, cm_compress(raw)))
    if method in ('auto', 'lzma'):
        cands.append((2, lzma.compress(raw, preset=9 | lzma.PRESET_EXTREME)))
    mid, body = min(cands, key=lambda p: len(p[1]))

    payload = body if mid == 0 else _varint(len(raw)) + body

    keyed = password is not None
    pw = password if keyed else _NOKEY_PASSWORD
    if seed_len not in _SEED_OPT: raise ValueError('시드 길이는 0/4/6/8')
    if tag_len not in _TAG_OPT:   raise ValueError('태그 길이는 0/4/8/16')

    seed = os.urandom(seed_len)
    ekey, akey = derive_keys(pw, seed)
    ct = chacha20(ekey, b'\0' * 12, payload)

    hdr = bytes([mid | (_SEED_OPT.index(seed_len) << 2) |
                 (_TAG_OPT.index(tag_len) << 4) | (0x40 if keyed else 0)])
    blob = hdr + seed + ct
    if tag_len:
        blob += hmac.new(akey, blob, hashlib.sha256).digest()[:tag_len]
    return blob


def decrypt(blob: bytes, password: str = None) -> str:
    import lzma
    if not blob: raise ValueError('빈 데이터입니다.')
    hdr = blob[0]
    mid = hdr & 3
    seed_len = _SEED_OPT[(hdr >> 2) & 3]
    tag_len = _TAG_OPT[(hdr >> 4) & 3]
    keyed = bool(hdr & 0x40)
    if mid == 3:
        raise ValueError('알 수 없는 형식입니다.')
    if keyed and password is None:
        raise ValueError('이 데이터는 비밀번호가 필요합니다. -k 로 지정하세요.')
    pw = password if keyed else _NOKEY_PASSWORD

    seed = blob[1:1 + seed_len]
    end = len(blob) - tag_len
    if end < 1 + seed_len:
        raise ValueError('데이터가 잘렸습니다.')
    ct = blob[1 + seed_len:end]

    ekey, akey = derive_keys(pw, seed)
    if tag_len:
        want = hmac.new(akey, blob[:end], hashlib.sha256).digest()[:tag_len]
        if not hmac.compare_digest(want, blob[end:]):
            raise ValueError('인증 실패: 비밀번호가 틀렸거나, 데이터가 손상되었거나, '
                             '프로그램 버전(코퍼스)이 다릅니다.')

    payload = chacha20(ekey, b'\0' * 12, ct)
    if mid == 0:
        raw = payload
    else:
        n, j = _read_varint(payload, 0)
        body = payload[j:]
        raw = cm_decompress(body, n) if mid == 1 else lzma.decompress(body)
        if len(raw) != n:
            raise ValueError('복호화 실패: 길이가 맞지 않습니다.')
    return raw.decode('utf-8')


# ---- 텍스트로 주고받기 위한 인코딩 (base85, 붙여넣기 안전) ----
def to_token(blob: bytes) -> str:
    return base64.b85encode(blob).decode('ascii')

def from_token(token: str) -> bytes:
    return base64.b85decode(''.join(token.split()))


# ════════════════════════════════════════════════════════════════════
#  5. CLI
# ════════════════════════════════════════════════════════════════════
def _selftest():
    import lzma, zlib, bz2
    samples = [
        '안녕하세요',
        '내일 세 시에 강남역에서 만나요',
        '비밀번호는 내 생일이야. 절대 다른 사람한테 말하지 마.',
        '오늘 수학 숙제는 삼차함수의 극값을 구하는 문제였다. 처음에는 판별식만 쓰면 될 줄 알았는데, '
        '매개변수가 두 개라 훨씬 복잡했다. 결국 미분해서 극값의 부호를 비교하는 방식으로 풀었다.',
        'Mixed 한글 and English 123 !@# 섞인 텍스트 테스트',
        '가' * 300,
        '',
    ]
    print(f"{'원문':>6} {'gzip':>6} {'bz2':>6} {'xz':>6} {'이도구':>7} {'토큰':>6}  내용")
    print('-' * 74)
    ok = True
    for s in samples:
        raw = s.encode('utf-8')
        blob = encrypt(s, 'test-비밀번호')
        tok = to_token(blob)
        try:
            back = decrypt(from_token(tok), 'test-비밀번호')
            good = (back == s)
        except Exception as e:
            good = False; print('  오류:', e)
        ok &= good
        g = len(zlib.compress(raw, 9)) if raw else 0
        b = len(bz2.compress(raw, 9)) if raw else 0
        x = len(lzma.compress(raw, preset=9)) if raw else 0
        mark = '' if good else '  ← 실패!'
        print(f'{len(raw):6d} {g:6d} {b:6d} {x:6d} {len(blob):7d} {len(tok):6d}  {s[:24]!r}{mark}')
    # 변조 감지
    blob = bytearray(encrypt('테스트 메시지입니다', 'pw'))
    blob[-1] ^= 1
    try:
        decrypt(bytes(blob), 'pw'); print('변조 감지 실패!'); ok = False
    except ValueError:
        print('\n변조 감지: 정상')
    try:
        decrypt(encrypt('테스트', 'pw1'), 'pw2'); print('틀린 비밀번호 거부 실패!'); ok = False
    except ValueError:
        print('틀린 비밀번호 거부: 정상')
    print('\n전체 결과:', '통과' if ok else '실패')
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description='한글 텍스트 초압축 + 암호화')
    sub = ap.add_subparsers(dest='cmd', required=True)

    for name, help_ in (('enc', '압축 + 암호화'), ('dec', '복호화 + 압축 해제')):
        p = sub.add_parser(name, help=help_)
        p.add_argument('text', nargs='?', help='입력 텍스트 (또는 -i 사용)')
        p.add_argument('-k', '--key', help='비밀번호 (생략하면 암호 보호 없음)')
        p.add_argument('-i', '--in', dest='infile', help='입력 파일')
        p.add_argument('-o', '--out', dest='outfile', help='출력 파일')
        if name == 'enc':
            p.add_argument('--min', action='store_true',
                           help='최소 크기 모드 (논스/태그/솔트 제거 — 짧지만 변조 감지 불가)')
            p.add_argument('--strong', action='store_true',
                           help='강화 모드 (논스 12B, 태그 16B)')
            p.add_argument('--binary', action='store_true', help='토큰 대신 원시 바이트로 출력')
    sub.add_parser('selftest', help='자체 검증 및 압축률 비교')

    a = ap.parse_args(argv)
    if a.cmd == 'selftest':
        return _selftest()

    if a.infile:
        data = open(a.infile, 'rb').read()
    elif a.text is not None:
        data = a.text.encode('utf-8')
    else:
        data = sys.stdin.buffer.read()

    if a.cmd == 'enc':
        text = data.decode('utf-8')
        kw = dict(seed_len=6, tag_len=4)
        if a.min:    kw = dict(seed_len=0, tag_len=0)
        if a.strong: kw = dict(seed_len=8, tag_len=16)
        t0 = time.time()
        blob = encrypt(text, a.key, **kw)
        dt = time.time() - t0
        if a.outfile:
            mode_bin = a.binary or a.outfile.endswith(('.bin', '.hgc'))
            with open(a.outfile, 'wb') as f:
                f.write(blob if mode_bin else to_token(blob).encode())
            print(f'{a.outfile} 저장됨', file=sys.stderr)
        elif a.binary:
            sys.stdout.buffer.write(blob)
        else:
            print(to_token(blob))
        r = len(blob) / max(1, len(data))
        print(f'[원문 {len(data)}B → {len(blob)}B  ({r:.1%}, {dt:.1f}초)]', file=sys.stderr)
    else:
        text = None
        errs = []
        for blob in _input_candidates(data):
            try:
                text = decrypt(blob, a.key); break
            except Exception as e:
                errs.append(str(e))
        if text is None:
            print('복호화 실패: ' + (errs[0] if errs else '입력 형식을 인식할 수 없습니다.'),
                  file=sys.stderr)
            return 1
        if a.outfile:
            open(a.outfile, 'w', encoding='utf-8').write(text)
            print(f'{a.outfile} 저장됨', file=sys.stderr)
        else:
            print(text)
    return 0


def _input_candidates(data: bytes):
    """입력이 base85 토큰인지 원시 바이트인지 모를 때 둘 다 시도한다."""
    try:
        yield from_token(data.decode('ascii').strip())
    except Exception:
        pass
    yield data


if __name__ == '__main__':
    try:
        sys.exit(main())
    except BrokenPipeError:
        os._exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
