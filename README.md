# pjh-encrypt

한글 텍스트 **초압축 + 암호화** 도구. 표준 라이브러리만 사용하며, 설치 없이 파일 하나로 동작합니다.

한국어 코퍼스로 미리 예열한 문맥혼합(Context Mixing) 압축기를 쓰기 때문에,
짧은 한글 문장에서도 gzip/bzip2/xz보다 훨씬 작게 줄어듭니다.

**웹에서 바로 쓰기 → [pjhnode.github.io/pjh-encrypt](https://pjhnode.github.io/pjh-encrypt/)**

Python 구현(`hangul_crypt.py`)과 JavaScript 구현(`hangul_crypt.js`)이 있으며, 둘은
바이트 단위로 호환됩니다. 웹에서 만든 토큰을 CLI로 풀 수 있고 그 반대도 됩니다.

## 압축률 (selftest 실측, 단위 = 바이트)

| 입력 | 원문 | gzip | bz2 | xz | **pjh-encrypt** |
|---|---:|---:|---:|---:|---:|
| `안녕하세요` | 15 | 24 | 54 | 72 | **16** |
| `내일 세 시에 강남역에서 만나요` | 43 | 54 | 79 | 100 | **26** |
| `비밀번호는 내 생일이야...` | 75 | 86 | 109 | 132 | **40** |
| 수학 숙제 문단 | 253 | 200 | 231 | 280 | **94** |
| `Mixed 한글 and English 123 !@#` | 59 | 62 | 104 | 116 | **51** |

일반 압축기는 짧은 글에서 오히려 커지지만, 이 도구는 암호화 오버헤드(11B)를 포함하고도
원문보다 작습니다. 긴 글 기준 원문의 약 30%, gzip 대비 절반 수준입니다.

## 빠른 시작

```bash
python hangul_crypt.py selftest                          # 자체 검증 + 압축률 비교

python hangul_crypt.py enc -k 비밀번호 "숨길 내용"          # base85 토큰 출력
python hangul_crypt.py dec -k 비밀번호 "출력된토큰"

python hangul_crypt.py enc -k pw -i 일기.txt -o 일기.hgc
python hangul_crypt.py dec -k pw -i 일기.hgc

python hangul_crypt.py enc --min    -k pw "..."          # 오버헤드 1바이트
python hangul_crypt.py enc --strong -k pw "..."          # 시드 8B, 태그 16B
```

`--min`은 시드와 태그를 빼서 가장 짧지만 **변조 감지가 안 되고, 같은 내용이 항상 같은 결과**가
됩니다. 정말 짧게 만들어야 할 때만 쓰세요.

## 라이브러리로 사용

```python
from hangul_crypt import encrypt, decrypt, to_token, from_token

blob  = encrypt('숨길 내용', '비밀번호')     # bytes
token = to_token(blob)                      # 붙여넣기 안전한 base85 문자열

원문 = decrypt(from_token(token), '비밀번호')
```

주요 함수:

| 함수 | 설명 |
|---|---|
| `encrypt(text, password=None, *, seed_len=6, tag_len=4, method='auto')` | 압축 + 암호화 → `bytes` |
| `decrypt(blob, password=None)` | 복호화 + 압축 해제 → `str` |
| `to_token(blob)` / `from_token(token)` | base85 텍스트 인코딩 |
| `cm_compress(data)` / `cm_decompress(blob, n)` | 암호화 없이 압축기만 사용 |

`method`는 `'auto'`(기본, 셋 다 해보고 최소 선택) / `'raw'` / `'cm'` / `'lzma'` 중 선택합니다.

## 웹 페이지

`index.html` + `hangul_crypt.js` 두 파일이 전부이며, 서버 없이 브라우저 안에서만 돌아갑니다.
입력한 내용과 비밀번호는 어디로도 전송되지 않습니다.

```html
<script src="hangul_crypt.js"></script>
<script>
  const blob  = await HangulCrypt.encrypt('숨길 내용', '비밀번호');
  const token = HangulCrypt.toToken(blob);
  const 원문  = await HangulCrypt.decrypt(HangulCrypt.fromToken(token), '비밀번호');
</script>
```

Node.js에서도 그대로 씁니다: `const HC = require('./hangul_crypt.js')`.

PBKDF2·HMAC·SHA-256은 WebCrypto를 쓰기 때문에 함수가 비동기이고, **보안 컨텍스트(HTTPS
또는 localhost)가 필요**합니다. `file://`로 열면 `crypto.subtle`이 없어 동작하지 않습니다.

### Python 구현과의 차이

브라우저에는 lzma 압축기가 없어 **압축 방식 후보에서 lzma를 제외**했습니다 (무압축과 CM만 사용).
한글 텍스트는 거의 항상 CM이 이기므로 실질적인 손해는 없고, JS가 만든 토큰은 Python에서
문제없이 풀립니다. 반대로 Python이 lzma를 골라 만든 드문 경우만 브라우저에서 풀 수 없으며,
그때는 안내 메시지가 나옵니다.

Python은 64비트 정수 연산을 임의정밀도로 하지만, 그 결과는 항상 하위 20비트(`_MASK`)만
쓰입니다. 곱셈의 하위 비트는 피연산자의 하위 비트에만 의존하므로 JS는 `Math.imul`로
하위 32비트만 계산해도 결과가 정확히 같습니다.

### 호환성 검사

```bash
python tools/crosstest.py     # 양방향 호환성 검사 (node 필요)
python tools/sync_corpus.py   # .py의 코퍼스를 .js로 복사
```

`crosstest.py`는 Python으로 테스트 벡터를 만들어 ① CM 압축기 출력이 바이트까지 같은지
② base85 인코딩이 같은지 ③ Python→JS 복호화 ④ JS→Python 복호화를 모두 확인합니다.

> 코퍼스는 두 구현이 반드시 같아야 합니다. `hangul_crypt.py`의 `CORPUS`를 고쳤다면
> `tools/sync_corpus.py`를 실행해 JS 쪽을 맞추세요. JS에는 `\uXXXX`로 이스케이프되어
> 들어가므로, 파일이 어떤 인코딩으로 해석되든 코퍼스 바이트는 달라지지 않습니다.

## 동작 방식

**압축** — 프로그램 안에 약 10KB의 한국어 코퍼스(조사·어미·상용어·여러 문체의 글)가 들어 있고,
압축할 때와 풀 때 양쪽이 이 코퍼스를 똑같이 먼저 학습합니다. 학습 결과는 출력에 한 바이트도
들어가지 않으므로, `안녕하세요` 같은 짧은 문장도 모델이 이미 아는 패턴이라 몇 비트로 표현됩니다.

엔진은 직접 구현한 문맥혼합 산술부호화기입니다. 직전 0·1·2·3·4·6·8바이트 문맥과 단어 단위
문맥까지 8개 모델이 각자 다음 비트를 예측하고, 로지스틱 혼합으로 가중 합산한 뒤 SSE 단계로
보정합니다. 한글 한 글자가 UTF-8에서 3바이트라 3·6바이트 문맥이 "직전 1·2글자"에 대응되도록
차수를 골랐습니다.

**암호** — ChaCha20(RFC 8439, 순수 파이썬) 스트림 암호 + HMAC-SHA256 인증 태그.
스트림 암호라 암호화해도 길이가 전혀 늘지 않습니다. 비밀번호는 PBKDF2-HMAC-SHA256
20만 회로 키를 유도합니다.

길이를 줄이려고 솔트와 논스를 하나의 시드로 합쳤습니다. 메시지마다 시드가 다르면 유도되는 키
자체가 달라지므로 논스를 따로 저장할 이유가 없고, 그만큼 6바이트를 아꼈습니다.

## 컨테이너 포맷

```
헤더 1B | [시드 S B] | 암호문 | [태그 T B]
```

기본 오버헤드는 헤더 1 + 시드 6 + 태그 4 = **11바이트**입니다.

헤더 비트 구성:

| 비트 | 의미 |
|---|---|
| 0–1 | 압축 방식 (0=무압축, 1=CM, 2=lzma) |
| 2–3 | 시드 길이 (0/4/6/8) |
| 4–5 | 태그 길이 (0/4/8/16) |
| 6 | 키 사용 여부 (0 = 내장 고정키 → 보안 없음, 단순 인코딩) |
| 7 | 예약 |

코퍼스 지문은 키 유도에 섞여 들어갑니다. 버전이 다르면 키가 달라져 인증 단계에서 걸러지므로
별도 바이트를 쓰지 않습니다.

## 주의사항

- **코퍼스를 수정하면 이전에 암호화한 데이터를 풀 수 없습니다.** 코퍼스 지문이 키 유도에 섞여
  있어 인증 단계에서 걸러지며, 에러 메시지로 알려줍니다. 대신 본인 글로 코퍼스를 교체하면
  압축률은 더 올라갑니다.
- **속도** — 예열과 PBKDF2 20만 회 때문에 호출당 Python 0.6초, 브라우저 0.45초 정도
  걸립니다. 수십 KB 이상 파일에서는 길이에 비례해 늘어납니다. JS는 예열 상태를 캐시하므로
  두 번째 호출부터 예열 비용이 84ms → 16ms로 줄어듭니다.
- 웹 페이지는 계산을 메인 스레드에서 하므로, 아주 긴 글을 넣으면 그동안 화면이 잠시
  멈춥니다. 필요해지면 Web Worker로 옮기면 됩니다.
- 순수 파이썬 구현이므로 타이밍 부채널 공격에는 방어하지 않습니다. 개인 메모·일기 수준의
  용도를 전제로 만들었습니다.

## 요구 사항

- **Python 3.8+** — 표준 라이브러리만 사용, 외부 의존성 없음
- **브라우저** — WebCrypto를 지원하는 최신 브라우저, HTTPS 또는 localhost에서 접속
- **호환성 검사에만** Node.js 18+

## 파일

| 파일 | 설명 |
|---|---|
| `hangul_crypt.py` | Python 구현 + CLI |
| `hangul_crypt.js` | JavaScript 구현 (브라우저 / Node.js) |
| `index.html` | 웹 페이지 UI |
| `tools/crosstest.py`, `tools/crosstest.js` | Python ↔ JS 양방향 호환성 검사 |
| `tools/sync_corpus.py` | 코퍼스를 .py → .js 로 동기화 |
