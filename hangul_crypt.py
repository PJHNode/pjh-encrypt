#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hangul_crypt.py — 한글 텍스트 초압축 + 암호화 도구

설계 요약
  1) 압축: 23KB 한국어 코퍼스로 미리 '예열'한 문맥혼합(Context Mixing) 산술부호화기.
           gzip/bzip2/xz보다 한국어에서 2~3배 더 짧다.
  2) 암호: ChaCha20 스트림 암호(순수 파이썬) + HMAC-SHA256 인증 태그.
           스트림 암호라 암호화해도 길이가 전혀 늘지 않는다.
  3) 키:   비밀번호 → scrypt(N=2^16, r=8, p=2, 64MB)로 키 유도.
  4) 표기: 한글 음절 한 글자에 13비트를 담는다. base85(6.4비트/글자)의 절반 길이다.

표준 라이브러리만 사용. 설치 불필요.
hangul_crypt.js 와 바이트 단위로 호환된다 (tools/crosstest.py 가 검사).

사용법
  python hangul_crypt.py enc -k 비밀번호 "숨길 내용"
  python hangul_crypt.py dec -k 비밀번호 "출력된암호문"   # 한글·base85 자동 인식
  python hangul_crypt.py enc -k pw --base85 "..."      # 영문만 받는 곳에 붙일 때
  python hangul_crypt.py enc -k pw --pad "..."         # 길이 감추기
  python hangul_crypt.py keygen -o 내열쇠.txt            # 공개키 봉인용 열쇠 쌍
  python hangul_crypt.py enc --to 공개키 "..."          # 공개키로 봉인
  python hangul_crypt.py dec --secret-file 내열쇠.txt "암호문"
  python hangul_crypt.py enc -k pw -i 입력.txt -o 출력.hgc
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
지금 어디야 거의 다 왔어 오분이면 도착해 먼저 들어가 있어 자리 잡아놨어 입구에서 기다릴게 늦어서 미안 차가 너무 막혔어 다음에는 지하철 타야겠다 오늘 고마웠어 조심히 들어가 도착하면 연락 줘 잘 들어갔어 응 방금 도착 푹 쉬어 내일 봐
이번 주말에 시간 괜찮아? 토요일 오후면 좋을 것 같은데 일요일도 상관없어 편한 시간 말해줘 나는 언제든 괜찮으니까 정해지면 알려줘 장소는 그때 정하자 중간쯤에서 보는 게 낫겠다 거기 주차 되나 모르겠네 대중교통이 편할 것 같아
밥은 먹었어? 아직 안 먹었으면 같이 먹자 뭐 먹고 싶어 아무거나 상관없어 네가 정해 저번에 갔던 데 어때 거기 괜찮았잖아 그럼 거기로 하자 몇 시에 볼까 일곱 시쯤 어때 좋아 그때 보자
어머니 생신 선물 뭐가 좋을까 고민이야 작년에는 스카프 드렸는데 올해는 다른 걸로 하고 싶어 같이 식사하는 게 제일 좋아하실 것 같기도 하고 형이랑 상의해봐야겠다 다들 시간 되는 날로 잡아서 모이자고 해야지
아버지 병원 예약 다음 주 화요일 오전 열 시야 내가 모시고 갈게 검사 결과는 그날 바로 나온다고 했어 걱정하지 마시라고 말씀드렸는데 표정이 안 좋으시더라 결과 나오면 바로 연락할게
동생이 시험 때문에 요즘 예민해 괜히 건드리지 말고 그냥 두자 끝나면 좀 나아지겠지 고생 많이 했으니까 끝나고 맛있는 거 사주려고 해 뭘 좋아하는지 물어봐야겠다
할머니 댁에 다녀왔다. 마당에 감이 많이 열렸는데 따서 깎아 말려 두셨다고 하셨다. 가져가라고 한 봉지 챙겨 주셨다. 요즘 무릎이 아프셔서 멀리는 못 다니신다고 했다. 자주 찾아뵈어야겠다는 생각을 하면서도 막상 시간을 내기가 쉽지 않다.
오늘 좀 힘들었어 별일은 아닌데 그냥 지치네 이야기 들어줘서 고마워 말하고 나니까 좀 나아졌어 내일은 괜찮아질 거야 너무 걱정하지 마 혼자 끙끙대지 말고 힘들면 말해 언제든 들어줄게
축하해 진짜 잘됐다 그동안 고생한 거 아니까 더 기쁘다 한턱 쏴야겠는데 언제 시간 돼 날 잡자 다들 부르자 오랜만에 모이면 좋겠다
안녕하세요. 지난번에 말씀드린 자료 정리해서 첨부합니다. 검토하시고 수정할 부분 있으면 알려 주시기 바랍니다. 초안이라 부족한 점이 많을 것 같습니다. 의견 주시면 반영해서 다시 보내 드리겠습니다. 감사합니다.
말씀하신 일정은 확인했습니다. 다만 그 주에는 다른 일정이 있어 참석이 어려울 것 같습니다. 가능하시다면 다음 주로 옮길 수 있을지 여쭙고 싶습니다. 번거롭게 해 드려 죄송합니다. 조율이 어려우시면 회의록으로 대신 확인하겠습니다.
회의 결과를 정리해 공유드립니다. 첫째, 일정은 기존 계획대로 진행하기로 했습니다. 둘째, 예산은 항목별로 재검토한 뒤 다음 회의에서 확정하기로 했습니다. 셋째, 담당자는 각 팀에서 한 명씩 지정해 이번 주 내로 알려 주시기 바랍니다.
보고드립니다. 현재까지 진행률은 약 칠십 퍼센트이며, 예정된 일정보다 이틀 정도 앞서 있습니다. 다만 외부 업체 회신이 늦어지는 부분이 있어 다음 단계에서 지연될 가능성이 있습니다. 대비책을 함께 준비하고 있습니다.
휴가 신청 관련 안내드립니다. 다음 달 휴가 계획은 이번 주 금요일까지 제출해 주시기 바랍니다. 같은 팀에서 중복되는 날짜가 있을 경우 조정이 필요하니 미리 상의해 주십시오. 승인 결과는 다음 주 초에 개별 안내드리겠습니다.
계약서 검토 요청드립니다. 특히 삼 조 이 항의 위약금 조항과 오 조의 계약 해지 조건을 중점적으로 봐 주시면 감사하겠습니다. 서명 전에 반드시 확인이 필요한 사항입니다. 의견은 이번 주 목요일까지 부탁드립니다.
계좌번호는 만나서 알려줄게 문자로 보내는 건 좀 그래 은행 앱에서 확인하는 게 나을 것 같아 입금하면 확인하고 연락할게 계좌 비밀번호나 인증번호는 누구에게도 알려주면 안 돼 은행에서는 절대 그런 걸 묻지 않아
카드값이 이번 달에 생각보다 많이 나왔다. 명세서를 보니 구독 서비스가 여러 개 자동 결제되고 있었다. 안 쓰는 건 정리해야겠다. 매달 조금씩이라도 나가는 돈은 일 년이면 꽤 큰 금액이 된다.
적금 만기가 다음 달인데 어떻게 할지 고민이다. 금리가 예전만 못해서 다시 넣기가 망설여진다. 일부는 비상금으로 두고 나머지만 다시 묶어 둘 생각이다. 무리하게 굴리기보다는 안전하게 가는 편이 낫겠다.
비밀번호를 여기저기 같은 걸 쓰고 있었는데 바꾸기로 했다. 한 곳이 뚫리면 전부 위험해진다는 말을 듣고 나니 불안해졌다. 중요한 곳부터 하나씩 다르게 바꾸고 있다. 외우기 어려운 건 따로 적어서 안전한 곳에 두었다.
새 집 비밀번호는 만나서 말해줄게 문 앞에 택배 오면 경비실에 맡겨 달라고 했어 열쇠는 하나 더 만들어서 어머니께 드렸어 혹시 모르니까
오늘 아침에는 유난히 일어나기가 힘들었다. 알람을 세 번이나 미루다가 겨우 일어났다. 창밖은 아직 어둑했고 공기가 찼다. 따뜻한 물을 한 잔 마시고 나니 조금 정신이 들었다. 요즘 잠드는 시간이 자꾸 늦어져서 그런 것 같다.
저녁에 혼자 걸었다. 특별히 목적지를 정하지 않고 그냥 걷다 보니 평소에 지나치던 골목까지 들어가게 됐다. 오래된 간판과 낡은 계단이 그대로 남아 있었다. 사람들이 사는 모습은 크게 달라지지 않았구나 싶었다.
한동안 미뤄 두었던 책을 다시 펼쳤다. 절반쯤 읽다 만 채로 몇 달이 지났는데, 앞부분을 다시 훑으니 기억나는 문장이 꽤 있었다. 그때는 그냥 넘겼던 대목이 지금은 다르게 읽혔다. 같은 글도 읽는 시기에 따라 다르게 다가온다.
일이 뜻대로 되지 않은 날이었다. 준비한 만큼 결과가 나오지 않으면 허탈해진다. 그래도 과정에서 배운 게 없지는 않았다. 다음에는 같은 실수를 반복하지 않으면 그걸로 충분하다고 생각하기로 했다.
올해가 벌써 절반이나 지났다. 연초에 세운 계획을 다시 보니 지킨 것보다 못 지킨 것이 많다. 그래도 아예 손도 못 댄 건 아니어서 조금은 위안이 된다. 남은 기간에는 개수를 줄이고 하나라도 제대로 해 보려 한다.
정부는 어제 관련 법안의 시행 시기를 내년 상반기로 미루기로 했다고 밝혔다. 준비 기간이 부족하다는 현장의 의견을 반영한 결정이다. 다만 시행이 늦어지면서 제도의 실효성이 떨어질 수 있다는 지적도 나온다.
조사에 따르면 응답자의 절반 이상이 필요성에는 공감하지만 구체적인 방식에는 이견을 보였다. 특히 비용 부담 주체를 두고 의견이 크게 갈렸다. 연구진은 추가 조사를 통해 세부 방안을 마련할 계획이라고 밝혔다.
지난달 소비자물가는 전년 같은 달보다 이 점 삼 퍼센트 올랐다. 농산물 가격이 안정되면서 상승 폭은 전달보다 줄었다. 다만 외식비와 공공요금은 여전히 오름세를 이어갔다.
전문가들은 단기적인 대책보다 구조적인 접근이 필요하다고 입을 모았다. 원인이 하나가 아니기 때문에 해결책도 여러 방향에서 동시에 나와야 한다는 것이다. 무엇보다 지속적인 관찰과 자료 축적이 중요하다고 강조했다.
물은 섭씨 백 도에서 끓고 영 도에서 언다. 다만 압력이 낮아지면 끓는점도 함께 내려간다. 높은 산에서 밥이 설익는 이유가 여기에 있다. 압력솥은 반대로 내부 압력을 높여 끓는점을 올리는 도구다.
식물은 빛을 받아 이산화탄소와 물로 양분을 만든다. 이 과정에서 산소가 나온다. 밤에는 반대로 호흡만 하기 때문에 산소를 쓰고 이산화탄소를 내놓는다. 잎의 뒷면에 있는 작은 구멍으로 기체가 드나든다.
ㅋㅋㅋㅋ 진짜 웃겨 나 지금 혼자 웃고 있어 ㅠㅠ 아 배아파 그거 어디서 봤어 링크 좀 보내줘 나도 보고 싶어 ㅇㅇ 지금 보낼게 ㄱㄱ 봤어? 대박이지 ㅇㅈ 인정 완전 내 얘기잖아
헐 진짜? 언제 그랬대 나만 몰랐네 아니 왜 말 안 했어 서운하다 ㅋㅋ 미안미안 까먹었어 담엔 꼭 말할게 알겠어 넘어가줌 ㅎㅎ
아 맞다 그거 어떻게 됐어 잘 해결됐어? 응 다행히 잘 끝났어 다행이다 진짜 걱정했잖아 고마워 신경 써줘서 별말씀을 당연한 거지
오늘 진짜 피곤하다 그냥 집 가서 눕고 싶어 나도 ㅠㅠ 우리 둘 다 쉬어야 해 주말에 푹 자자 그래 그러자
서버가 새벽에 두 번 재시작됐다. 로그를 보니 메모리 사용량이 계속 올라가다가 한계에 부딪혀 종료된 흔적이었다. 어제 배포한 변경 중에 캐시를 비우지 않는 부분이 있었던 것 같다. 일단 되돌리고 원인을 더 확인하기로 했다.
빌드가 실패해서 확인해 보니 의존성 버전이 서로 충돌하고 있었다. 잠금 파일을 지우고 다시 설치하니 해결됐다. 다만 왜 갑자기 충돌이 생겼는지는 더 봐야 할 것 같다. 상위 패키지가 조용히 범위를 바꾼 듯하다.
데이터베이스 조회가 느려서 실행 계획을 확인했다. 인덱스를 타지 않고 전체를 훑고 있었다. 조건절에 함수를 씌운 탓이었다. 함수를 걷어내고 인덱스를 다시 잡으니 응답 시간이 크게 줄었다.
코드를 고치기 전에 왜 그렇게 되어 있는지부터 이해하는 편이 낫다. 이상해 보이는 부분에도 대개 이유가 있다. 이유를 모른 채 고치면 같은 문제가 다른 모양으로 다시 나타난다.
테스트를 먼저 써 두면 나중에 손볼 때 마음이 편하다. 무엇이 깨졌는지 바로 알 수 있기 때문이다. 처음에는 번거롭게 느껴지지만, 고칠 일이 반복될수록 이득이 커진다.
문제를 풀 때는 조건을 먼저 정리하는 게 중요하다. 주어진 것과 구하는 것을 나눠 적기만 해도 길이 보이는 경우가 많다. 막히면 비슷한 유형을 떠올려 보고, 그래도 안 되면 조건을 하나씩 바꿔 가며 어디서 걸리는지 확인한다.
외우는 것과 이해하는 것은 다르다. 외운 것은 조금만 형태가 바뀌어도 쓸 수 없지만, 이해한 것은 처음 보는 문제에도 적용할 수 있다. 시간이 걸리더라도 왜 그런지를 따져 보는 편이 결국 빠르다.
복습은 미루지 않는 게 좋다. 배운 날 다시 보면 십 분이면 될 것을, 일주일 뒤에 보면 처음부터 다시 해야 한다. 짧게라도 자주 보는 쪽이 오래 남는다.
계획은 크게 세우고 실행은 작게 쪼개는 편이 낫다. 오늘 할 일을 한 줄로 적어 두면 시작하기가 훨씬 수월하다. 완벽하게 하려다 아예 시작하지 못하는 경우가 제일 아깝다.
여행 일정 정리했어 첫날은 도착해서 숙소만 가고 둘째 날부터 움직이자 셋째 날은 좀 여유 있게 잡았어 너무 빡빡하면 힘들더라 마지막 날은 공항 가기 전에 근처만 둘러보면 될 것 같아
숙소는 역에서 걸어서 십 분 거리야 가격도 괜찮고 후기도 나쁘지 않아 조식은 포함 안 돼 있는데 근처에 먹을 데가 많아서 상관없을 것 같아 예약은 내가 할게 나중에 정산하자
비행기 시간이 이른 편이라 전날 일찍 자야 할 것 같아 짐은 미리 싸 두는 게 좋겠어 충전기랑 여권은 꼭 챙기고 우산도 하나 넣어 가자 날씨가 오락가락한다더라
날씨가 갑자기 추워졌다. 어제까지만 해도 얇은 옷으로 버텼는데 오늘은 도저히 안 되겠어서 두꺼운 걸 꺼냈다. 환절기라 감기 걸리기 쉬우니 조심해야겠다.
장을 보고 왔다. 이번 주에 해 먹을 것들을 대충 정해 놓고 사니 쓸데없는 걸 덜 사게 된다. 냉장고를 한 번 정리하고 넣었더니 훨씬 보기 좋아졌다. 유통기한 지난 것들도 몇 개 버렸다.
화분에 물을 주는 간격을 조금 늘렸다. 겨울에는 흙이 마르는 속도가 느려서 자주 주면 오히려 뿌리가 상한다고 한다. 손가락을 넣어 보고 속까지 말랐을 때만 주기로 했다.
집 정리를 했다. 버릴까 말까 망설이던 것들을 이번에는 과감하게 정리했다. 언젠가 쓸지도 모른다는 생각으로 두었던 것들은 결국 몇 년째 그대로였다. 비우고 나니 공간이 넓어 보인다.
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

# 문맥 표 크기. 2^20 이 0.7%쯤 더 좋지만 모형마다 3MB씩 먹는다.
# 2^19 면 9개 모형에 13.5MB — 휴대전화에서도 안전하고 예열도 빠르다.
_BITS = 19
_MASK = (1 << _BITS) - 1
_M32 = 0xFFFFFFFF
_M64 = (1 << 64) - 1

# 32비트 곱수 — JS의 Math.imul과 결과를 맞추려고 하위 32비트만 쓴다
_MULT32 = [0x7F4A7C15, 0x85EBCA6B, 0xC2B2AE35, 0x27D4EB2F,
           0x9E3779F9, 0x9E3779B1, 0xD6E8FEB8, 0x78BD642F,
           0x1B873593, 0xCC9E2D51, 0xE6546B64, 0x9E3779B9]


def _fin(x):
    """눈사태 마무리 — 상위 비트를 하위로 끌어내린다.

    문맥 해시는 곱셈 결과의 하위 20비트만 쓴다. 그런데 곱셈의 하위 비트는
    피연산자의 하위 비트에만 의존하므로, 이 단계가 없으면 3바이트 너머의 이력이
    해시에 전혀 닿지 못한다. (초기 판이 실제로 그랬고, 차수 4·6·8 모델이
    차수 2.5 모델과 똑같은 것을 보고 있었다.)
    """
    x &= _M32
    x ^= x >> 16
    x = (x * 0x7FEB352D) & _M32
    x ^= x >> 15
    x = (x * 0x846CA68B) & _M32
    x ^= x >> 16
    return x


def _low(v, bits):
    return v if bits >= 32 else (v & ((1 << bits) - 1))


class _Cfg:
    """압축기 구성.

    차수는 짧은 쪽(0~6)이 유리하다. 긴 문맥은 코퍼스 안에서 너무 희소해
    학습이 되지 않아, 차수를 늘려도 0.5% 안쪽이면서 예열만 느려진다.
    """
    __slots__ = ('orders', 'sparse', 'pos_mix', 'nm', 'nmix')

    def __init__(self, orders, sparse=(), pos_mix=True):
        self.orders = orders
        self.sparse = sparse
        self.pos_mix = pos_mix
        self.nm = len(orders) + len(sparse) + 1      # + 단어 모델
        self.nmix = 2048 if pos_mix else 512


CFG = _Cfg([0, 1, 2, 3, 4, 5, 6], sparse=((1, 2),))

# 일치 모델 — 지금까지 본 글(코퍼스 포함)에서 방금 쓴 부분과 길게 겹치는 곳을 찾아
# 그다음 바이트를 예측한다. 짧은 메시지에서는 1~2%지만, 같은 표현이 되풀이되는
# 긴 글에서는 17% 가까이 줄어든다. 겹침이 8바이트(한글 2~3글자) 이상일 때만 따른다.
_MATCH_MIN = 8
_MATCH_BITS = 16
_MATCH_SIZE = 1 << _MATCH_BITS
_MATCH_VERIFY = 32

ORDERS = CFG.orders
NM = CFG.nm


class _Model:
    """여러 차수의 문맥 예측을 로지스틱 혼합으로 합치고 SSE로 보정한다."""

    def __init__(self, cfg=CFG):
        self.cfg = cfg
        nm = cfg.nm
        self.nm = nm
        self.t = [array('H', [32768]) * (_MASK + 1) for _ in range(nm)]
        self.n = [bytearray(_MASK + 1) for _ in range(nm)]
        self.w = [array('i', [1 << 14]) * (nm + 1) for _ in range(cfg.nmix)]   # +일치 모델
        self.apm = array('H', [0]) * (1024 * 33)
        for c in range(1024):
            base = c * 33
            for j in range(33):
                self.apm[base + j] = _squash((j - 16) * 128) * 16
        self.h = [0] * nm
        self.idx = [0] * nm
        self.st = [0] * nm
        self.c0 = 1          # 현재 바이트의 이미 처리된 비트들 (선두 1 포함)
        self.hist = 0        # 직전 8바이트
        self.wh = 0          # 현재 단어 해시
        self.pos = 0         # UTF-8 연속바이트 위치
        self.buf = bytearray()                     # 지금까지 본 모든 바이트
        self.mt = array('i', [0]) * _MATCH_SIZE    # 해시 → 그 뒤에 올 바이트의 위치
        self.ms = array('H', [32768]) * 32         # 일치 길이별 "예측이 맞을" 확률
        self.mn = bytearray(32)
        self.mlen = 0; self.mptr = 0; self.mexp = 0
        self.mst = 0; self.mi = -1; self.mbit = 0
        self.pr = 2048
        self._ai = 0
        self._aw = 0
        self._set_ctx()

    def _set_ctx(self):
        cfg = self.cfg
        h = self.hist
        lo = h & _M32
        hi = (h >> 32) & _M32
        for i, o in enumerate(cfg.orders):
            if o == 0:
                self.h[i] = 0
                continue
            if o <= 4:
                a, b = _low(lo, 8 * o), 0
            else:
                a, b = lo, _low(hi, 8 * (o - 4))
            self.h[i] = _fin((a * _MULT32[i % 12]) & _M32
                             ^ (((b + 0x165667B1) & _M32) * _MULT32[(i + 5) % 12]) & _M32) & _MASK
        k = len(cfg.orders)
        for s in cfg.sparse:
            acc = 0x9E3779B9
            for off in s:
                acc = ((acc ^ ((lo >> (8 * off)) & 255)) * 0x85EBCA6B) & _M32
            self.h[k] = _fin(acc) & _MASK
            k += 1
        self.h[k] = _fin((self.wh * 0x7F4A7C15) & _M32) & _MASK

    def _mix_sel(self):
        base = (self.c0 & 255) | (256 if self.hist & 128 else 0)
        return base + 512 * self.pos if self.cfg.pos_mix else base

    def predict(self):
        c0 = self.c0
        w = self.w[self._mix_sel()]
        cm = c0 * 0x6F4F2F1F
        dot = 0
        for i in range(self.nm):
            j = (self.h[i] ^ cm) & _MASK
            self.idx[i] = j
            s = _STRETCH[self.t[i][j] >> 4]
            self.st[i] = s
            dot += w[i] * s
        self.mst = 0
        self.mi = -1
        if self.mlen:
            known = c0.bit_length() - 1          # 이 바이트에서 이미 본 비트 수
            if ((self.mexp | 256) >> (8 - known)) == c0:
                eb = (self.mexp >> (7 - known)) & 1
                mi = self.mlen if self.mlen < 31 else 31
                s = _STRETCH[self.ms[mi] >> 4]
                self.mbit = eb
                self.mi = mi
                self.mst = s if eb else -s
                dot += w[self.nm] * self.mst
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
        w = self.w[self._mix_sel()]
        tgt = bit << 16
        for i in range(self.nm):
            w[i] += (self.st[i] * err) >> 13
            j = self.idx[i]
            t = self.t[i]; n = self.n[i]
            c = n[j]
            t[j] += ((tgt - t[j]) * _RATE[c]) >> 17
            if c < _LIMIT: n[j] = c + 1
        w[self.nm] += (self.mst * err) >> 13
        mi = self.mi
        if mi >= 0:
            c = self.mn[mi]
            self.ms[mi] += ((((1 if bit == self.mbit else 0) << 16) - self.ms[mi]) * _RATE[c]) >> 17
            if c < _LIMIT: self.mn[mi] = c + 1
        self.c0 = (self.c0 << 1) | bit
        if self.c0 >= 256:
            b = self.c0 & 255
            self.hist = ((self.hist << 8) | b) & _M64
            if b >= 128 or 48 <= b <= 57 or 65 <= b <= 122:
                self.wh = (self.wh * 0x2F0FD693 + b + 1) & _M32
            else:
                self.wh = 0
            if self.cfg.pos_mix:
                if b < 0x80:     self.pos = 0
                elif b >= 0xF0:  self.pos = 3
                elif b >= 0xE0:  self.pos = 2
                elif b >= 0xC0:  self.pos = 1
                else:            self.pos = self.pos - 1 if self.pos > 0 else 0
            self._match_byte(b)
            self.c0 = 1
            self._set_ctx()

    def _match_byte(self, b):
        buf = self.buf
        buf.append(b)
        n = len(buf)
        if self.mlen:
            if buf[self.mptr] == b:
                self.mlen += 1
                self.mptr += 1
            else:
                self.mlen = 0
        if n >= _MATCH_MIN:
            acc = 0x811C9DC5                     # FNV-1a (32비트)
            for q in range(n - _MATCH_MIN, n):
                acc = ((acc ^ buf[q]) * 0x01000193) & _M32
            h = _fin(acc) & (_MATCH_SIZE - 1)
            if not self.mlen:
                cand = self.mt[h]
                if cand:
                    ln = 0
                    while (ln < _MATCH_VERIFY and cand - 1 - ln >= 0
                           and buf[cand - 1 - ln] == buf[n - 1 - ln]):
                        ln += 1
                    if ln >= _MATCH_MIN:
                        self.mlen = ln
                        self.mptr = cand
            self.mt[h] = n
        self.mexp = buf[self.mptr] if self.mlen else 0


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


def _prime_into(m, data):
    """예열 전용 고속 경로.

    예열은 예측값을 바깥으로 내보내지 않으므로 predict/update를 한 덩어리로 합치고
    상태를 전부 지역 변수로 끌어올 수 있다. 파이썬에서는 속성 조회를 없애는 것만으로
    크게 빨라진다. 결과는 predict/update를 번갈아 부른 것과 **완전히 같아야 하며**,
    tools/crosstest.py 가 그것을 검사한다.
    """
    cfg = m.cfg
    nm = m.nm
    tabs = m.t
    cnts = m.n
    ws = m.w
    apm = m.apm
    stretch = _STRETCH
    squash = _squash
    rate = _RATE
    mask = _MASK
    limit = _LIMIT
    pos_mix = cfg.pos_mix
    h = m.h
    st = [0] * nm
    idx = [0] * nm
    rng = range(nm)
    ms = m.ms
    mn = m.mn
    mbit = 0

    c0 = m.c0
    if not data:
        return m
    pr = i0 = wt = 0

    for byte in data:
        for k in (7, 6, 5, 4, 3, 2, 1, 0):
            bit = (byte >> k) & 1
            hist = m.hist

            sel = (c0 & 255) | (256 if hist & 128 else 0)
            if pos_mix:
                sel += 512 * m.pos
            w = ws[sel]

            cm = c0 * 0x6F4F2F1F
            dot = 0
            for i in rng:
                j = (h[i] ^ cm) & mask
                idx[i] = j
                s = stretch[tabs[i][j] >> 4]
                st[i] = s
                dot += w[i] * s

            mst = 0
            mi = -1
            mlen = m.mlen
            if mlen:
                known = c0.bit_length() - 1
                mexp = m.mexp
                if ((mexp | 256) >> (8 - known)) == c0:
                    mbit = (mexp >> (7 - known)) & 1
                    mi = mlen if mlen < 31 else 31
                    s = stretch[ms[mi] >> 4]
                    mst = s if mbit else -s
                    dot += w[nm] * mst

            p = squash(dot >> 16)
            ctx = (c0 & 255) | ((hist & 3) << 8)
            s = stretch[p]
            i0 = ctx * 33 + ((s + 2048) >> 7)
            wt = (s + 2048) & 127
            pa = (apm[i0] * (128 - wt) + apm[i0 + 1] * wt) >> 11
            pr = (p + 3 * pa) >> 2
            if pr < 1: pr = 1
            elif pr > 4094: pr = 4094

            # --- update ---
            g = (bit << 16) + (bit << 4) - bit - bit
            apm[i0] += ((g - apm[i0]) * (128 - wt)) >> 12
            apm[i0 + 1] += ((g - apm[i0 + 1]) * wt) >> 12
            err = ((bit << 12) - pr) * 10
            tgt = bit << 16
            for i in rng:
                w[i] += (st[i] * err) >> 13
                j = idx[i]
                t = tabs[i]
                n = cnts[i]
                c = n[j]
                t[j] += ((tgt - t[j]) * rate[c]) >> 17
                if c < limit: n[j] = c + 1
            w[nm] += (mst * err) >> 13
            if mi >= 0:
                c = mn[mi]
                ms[mi] += ((((1 if bit == mbit else 0) << 16) - ms[mi]) * rate[c]) >> 17
                if c < limit: mn[mi] = c + 1

            c0 = (c0 << 1) | bit
            if c0 >= 256:
                b = c0 & 255
                m.hist = ((hist << 8) | b) & _M64
                if b >= 128 or 48 <= b <= 57 or 65 <= b <= 122:
                    m.wh = (m.wh * 0x2F0FD693 + b + 1) & _M32
                else:
                    m.wh = 0
                if pos_mix:
                    if b < 0x80:     m.pos = 0
                    elif b >= 0xF0:  m.pos = 3
                    elif b >= 0xE0:  m.pos = 2
                    elif b >= 0xC0:  m.pos = 1
                    else:            m.pos = m.pos - 1 if m.pos > 0 else 0
                m._match_byte(b)
                c0 = 1
                m._set_ctx()

    m.c0 = c0
    m.pr = pr
    m._ai = i0
    m._aw = wt
    return m


_prime_cache = {}


def _snapshot(m):
    return (list(m.t), list(m.n), [array('i', w) for w in m.w], array('H', m.apm),
            list(m.h), m.c0, m.hist, m.wh, m.pos, m.pr, m._ai, m._aw,
            bytes(m.buf), array('i', m.mt), array('H', m.ms), bytes(m.mn),
            m.mlen, m.mptr, m.mexp)


def _primed_model(cfg=CFG):
    """예열이 끝난 모델을 준다.

    예열은 이 도구에서 가장 비싼 단계인데 결과는 늘 같다. 한 번만 돌려 두고
    이후로는 복사본을 내준다. 한 프로세스에서 여러 번 부를 때 크게 빨라진다.
    """
    key = id(cfg)
    snap = _prime_cache.get(key)
    if snap is None:
        base = _prime_into(_Model(cfg), CORPUS_BYTES)
        snap = _snapshot(base)
        _prime_cache[key] = snap

    (t, n, w, apm, h, c0, hist, wh, pos, pr, ai, aw,
     buf, mt, ms, mn, mlen, mptr, mexp) = snap
    m = _Model.__new__(_Model)
    m.cfg = cfg
    m.nm = cfg.nm
    m.t = [array('H', x) for x in t]
    m.n = [bytearray(x) for x in n]
    m.w = [array('i', x) for x in w]
    m.apm = array('H', apm)
    m.h = list(h)
    m.idx = [0] * cfg.nm
    m.st = [0] * cfg.nm
    m.c0, m.hist, m.wh, m.pos, m.pr = c0, hist, wh, pos, pr
    m._ai, m._aw = ai, aw
    m.buf = bytearray(buf)
    m.mt = array('i', mt)
    m.ms = array('H', ms)
    m.mn = bytearray(mn)
    m.mlen, m.mptr, m.mexp = mlen, mptr, mexp
    m.mst, m.mi, m.mbit = 0, -1, 0
    return m


def cm_compress(data: bytes, cfg=CFG) -> bytes:
    m = _primed_model(cfg)
    e = _Encoder()
    for byte in data:
        for k in (7, 6, 5, 4, 3, 2, 1, 0):
            e.encode((byte >> k) & 1, m.predict())
            m.update((byte >> k) & 1)
    return e.flush()


def cm_decompress(blob: bytes, n: int, cfg=CFG) -> bytes:
    m = _primed_model(cfg)
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


# 열쇠 유도 — scrypt.
#   실제 공격은 알고리즘이 아니라 열쇠말을 하나씩 넣어 보는 쪽으로 온다. scrypt는
#   시도 한 번마다 메모리를 64MB씩 쓰게 만들어, GPU·전용 칩으로 대량 병렬 공격하는
#   비용을 끌어올린다. N=2^16, r=8, p=2 는 OWASP가 N=2^17·r=8·p=1 과 같은 강도로
#   꼽는 값이며, 메모리를 절반만 써서 휴대전화 브라우저에서도 돌아간다.
SCRYPT_N = 1 << 16
SCRYPT_R = 8
SCRYPT_P = 2


def derive_keys(password: str, seed: bytes):
    """비밀번호 + 시드 → (암호키 32B, 인증키 32B). 코퍼스 지문도 함께 묶는다."""
    salt = b'HGC3' + bytes([CORPUS_FP]) + seed
    dk = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                        p=SCRYPT_P, maxmem=1 << 27, dklen=64)
    return dk[:32], dk[32:]


# ════════════════════════════════════════════════════════════════════
#  3-2. 공개키 — X25519 (RFC 7748) + HKDF-SHA256
#
#     받는 사람이 공개키를 한 번 알려 주면, 열쇠말을 따로 전하지 않고도 그 사람만
#     풀 수 있는 밀서를 보낼 수 있다. 봉인할 때마다 일회용 열쇠 쌍을 만들어 받는
#     사람의 공개키와 합의하고(ECDH), 합의된 비밀에서 HKDF로 열쇠를 뽑는다.
#     합의된 비밀은 이미 충분히 무작위이므로 scrypt처럼 일부러 느리게 할 필요가 없다.
#
#     표준 라이브러리에 X25519가 없어 RFC 7748의 몽고메리 사다리를 그대로 옮겼다.
#     공식 시험 벡터와 OpenSSL 결과로 검증한다. 정수 연산이 상수 시간이 아니므로
#     같은 기기에서 복호화 시간을 수없이 잴 수 있는 공격자에게는 약할 수 있다 —
#     개인 기기에서 쓰는 도구라는 전제다.
#
#     누가 보냈는지는 증명하지 않는다. 공개키만 알면 누구나 봉인해 보낼 수 있다.
# ════════════════════════════════════════════════════════════════════
_P25519 = (1 << 255) - 19
_A24 = 121665


def x25519(k: bytes, u: bytes) -> bytes:
    """RFC 7748 X25519. k: 32바이트 비밀 스칼라, u: 32바이트 u 좌표."""
    if len(k) != 32 or len(u) != 32:
        raise ValueError('X25519 입력은 32바이트여야 합니다.')
    kb = bytearray(k)
    kb[0] &= 248
    kb[31] &= 127
    kb[31] |= 64
    kn = int.from_bytes(kb, 'little')
    x1 = int.from_bytes(u, 'little') & ((1 << 255) - 1)
    P = _P25519
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (kn >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) * (da + cb) % P
        z3 = x1 * (da - cb) * (da - cb) % P
        x2 = aa * bb % P
        z2 = e * (aa + _A24 * e) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, 'little')


_X25519_BASE = (9).to_bytes(32, 'little')


def _hkdf(salt: bytes, ikm: bytes, info: bytes, length: int = 64) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b'', b'', 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def _pk_keys(shared: bytes, e_pub: bytes, r_pub: bytes):
    if shared == bytes(32):
        raise ValueError('공개키가 올바르지 않습니다.')   # 작은 부분군의 점
    okm = _hkdf(b'HGC3P' + bytes([CORPUS_FP]), shared, e_pub + r_pub, 64)
    return okm[:32], okm[32:]


# 열쇠 표기: 종류 1B + 열쇠 32B + 체크섬 2B → 한글 23자.
# 종류 바이트가 공개키와 개인 열쇠를 가르고, 체크섬이 오타와 잘못 붙여 넣기를 잡는다.
_KEY_PUBLIC = 0x70     # 'p'
_KEY_SECRET = 0x73     # 's'


def _key_token(kind: int, key: bytes) -> str:
    body = bytes([kind]) + key
    return to_hangul(body + hashlib.sha256(body).digest()[:2])


def _parse_key(token: str, kind: int) -> bytes:
    what = '공개키' if kind == _KEY_PUBLIC else '개인 열쇠'
    try:
        raw = decode_token(token)
    except Exception:
        raise ValueError(f'{what}를 읽을 수 없습니다.')
    if len(raw) != 35 or hashlib.sha256(raw[:33]).digest()[:2] != raw[33:]:
        raise ValueError(f'{what}가 손상되었습니다. 빠진 글자가 없는지 확인하세요.')
    if raw[0] != kind:
        other = '개인 열쇠' if kind == _KEY_PUBLIC else '공개키'
        raise ValueError(f'{what}가 아니라 {other}입니다.')
    return raw[1:33]


def generate_keypair():
    """새 열쇠 쌍 → (개인 열쇠 표기, 공개키 표기)."""
    sk = os.urandom(32)
    return _key_token(_KEY_SECRET, sk), _key_token(_KEY_PUBLIC, x25519(sk, _X25519_BASE))


def public_from_secret(secret: str) -> str:
    return _key_token(_KEY_PUBLIC, x25519(_parse_key(secret, _KEY_SECRET), _X25519_BASE))


def key_fingerprint(public: str) -> str:
    """공개키 지문 — 한글 네 자. 받은 공개키가 맞는지 목소리로 맞춰 보는 데 쓴다."""
    pk = _parse_key(public, _KEY_PUBLIC)
    n = int.from_bytes(hashlib.sha256(b'HGC3 fingerprint' + pk).digest()[:7], 'big') >> 4
    syl = [chr(_HAN_BASE + ((n >> (13 * (3 - i))) & 8191)) for i in range(4)]
    return syl[0] + syl[1] + ' ' + syl[2] + syl[3]


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
#                 7   길이 감추기 (1이면 본문 = varint(길이) + 본문 + 0 채움)
#
#     코퍼스 지문과 형식 표시('HGC3')는 키 유도 솔트에 섞여 들어간다. 판이
#     다르면 키가 달라져 인증에서 걸러지므로 별도 바이트를 쓰지 않는다.
#
#     공개키 봉인은 방식 값 3을 '확장 헤더'로 쓴다:
#       헤더 1B(방식=3) | 확장 1B(실제 방식 | 종류<<2, 종류 1=X25519) | 일회용 공개키 32B
#       | 암호문 | [태그 T B]
#     이때 헤더의 시드 길이는 0, 키 사용 비트는 1이다.
#
#     길이 감추기: 압축한 뒤 암호화하면 암호문 길이가 내용에 따라 달라진다
#     (되풀이가 많은 글은 짧고, 낯선 글은 길다). 전체 길이를 Padmé 방식으로
#     맞춰 채우면 길이가 드러내는 정보가 O(log log n) 비트로 줄고, 늘어나는
#     크기는 최대 12%다. 32바이트 이하는 모두 32바이트로 맞춘다.
# ════════════════════════════════════════════════════════════════════
_SEED_OPT = [0, 4, 6, 8]
_TAG_OPT = [0, 4, 8, 16]
_NOKEY_PASSWORD = 'hangul-crypt-no-key'
_PAD_MIN = 32


def _pad_target(n):
    """Padmé — n 이상에서 가장 가까운, 아래쪽 비트가 0인 길이."""
    if n <= _PAD_MIN:
        return _PAD_MIN
    e = n.bit_length() - 1          # floor(log2 n)
    s = e.bit_length()              # floor(log2 e) + 1
    mask = (1 << (e - s)) - 1
    return (n + mask) & ~mask


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
        if i >= len(data):
            raise ValueError('데이터가 잘렸습니다.')
        b = data[i]; i += 1
        n |= (b & 0x7F) << sh
        if not (b & 0x80): return n, i
        sh += 7


def encrypt(text: str, password: str = None, *, seed_len=6, tag_len=4,
            method='auto', pad=False, to=None) -> bytes:
    """to 에 받는 사람의 공개키를 주면 열쇠말 대신 공개키로 봉인한다."""
    import lzma
    raw = text.encode('utf-8')
    if to is not None and password is not None:
        raise ValueError('열쇠말과 공개키 중 하나만 쓰세요.')

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

    if to is not None:
        r_pub = _parse_key(to, _KEY_PUBLIC)
        e_sk = os.urandom(32)
        e_pub = x25519(e_sk, _X25519_BASE)
        ekey, akey = _pk_keys(x25519(e_sk, r_pub), e_pub, r_pub)
        prefix = bytes([3 | (_TAG_OPT.index(tag_len) << 4) | 0x40 | (0x80 if pad else 0),
                        mid | (1 << 2)]) + e_pub
    else:
        seed = os.urandom(seed_len)
        prefix = bytes([mid | (_SEED_OPT.index(seed_len) << 2) |
                        (_TAG_OPT.index(tag_len) << 4) | (0x40 if keyed else 0) |
                        (0x80 if pad else 0)]) + seed

    if pad:
        inner = _varint(len(payload)) + payload
        unpadded = len(prefix) + len(inner) + tag_len
        payload = inner + bytes(_pad_target(unpadded) - unpadded)

    if to is None:
        ekey, akey = derive_keys(pw, seed)
    ct = chacha20(ekey, b'\0' * 12, payload)
    blob = prefix + ct
    if tag_len:
        blob += hmac.new(akey, blob, hashlib.sha256).digest()[:tag_len]
    return blob


def is_public_key_blob(blob: bytes) -> bool:
    return len(blob) >= 2 and blob[0] & 3 == 3 and blob[1] >> 2 == 1


def decrypt(blob: bytes, password: str = None, *, secret: str = None) -> str:
    """secret 에 개인 열쇠를 주면 공개키로 봉인된 글을 푼다."""
    import lzma
    if not blob: raise ValueError('빈 데이터입니다.')
    hdr = blob[0]
    mid = hdr & 3
    tag_len = _TAG_OPT[(hdr >> 4) & 3]
    keyed = bool(hdr & 0x40)
    padded = bool(hdr & 0x80)

    if mid == 3:
        if not is_public_key_blob(blob):
            raise ValueError('알 수 없는 형식입니다.')
        if secret is None:
            raise ValueError('공개키로 봉인된 글입니다. 받는 사람의 개인 열쇠로 풀어야 합니다.')
        mid = blob[1] & 3
        head = 2 + 32
        end = len(blob) - tag_len
        if end < head:
            raise ValueError('데이터가 잘렸습니다.')
        e_pub = blob[2:head]
        sk = _parse_key(secret, _KEY_SECRET)
        ekey, akey = _pk_keys(x25519(sk, e_pub), e_pub, x25519(sk, _X25519_BASE))
        ct = blob[head:end]
    else:
        seed_len = _SEED_OPT[(hdr >> 2) & 3]
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
            raise ValueError('인증 실패: 비밀번호(또는 개인 열쇠)가 틀렸거나, 데이터가 '
                             '손상되었거나, 다른 판에서 만든 암호문입니다.')

    payload = chacha20(ekey, b'\0' * 12, ct)
    if padded:
        k, j = _read_varint(payload, 0)
        if j + k > len(payload):
            raise ValueError('데이터가 잘렸습니다.')
        payload = payload[j:j + k]
    if mid == 0:
        raw = payload
    else:
        n, j = _read_varint(payload, 0)
        body = payload[j:]
        raw = cm_decompress(body, n) if mid == 1 else lzma.decompress(body)
        if len(raw) != n:
            raise ValueError('복호화 실패: 길이가 맞지 않습니다.')
    return raw.decode('utf-8')


# ════════════════════════════════════════════════════════════════════
#  5. 텍스트로 주고받기 위한 인코딩
#
#     base85 — 4바이트를 5글자로 부풀린다 (1.25글자/바이트).
#     한글   — 음절 U+AC00..U+D7A3 은 11172자다. 그 중 8192자(2^13)만 쓰면
#              한 글자에 정확히 13비트가 들어간다 (0.62글자/바이트).
#              같은 내용을 절반 길이로 옮길 수 있다.
#
#     길이 되찾기: 글자 수 S에서 원래 바이트 수 N을 구할 때 후보가 둘(N, N+1)
#     생길 수 있다. 두 후보는 13으로 나눈 나머지가 반드시 다르므로, 맨 앞에
#     (N mod 13)을 담은 표시 글자 하나를 붙이면 모호함이 사라진다.
# ════════════════════════════════════════════════════════════════════
def to_token(blob: bytes) -> str:
    return base64.b85encode(blob).decode('ascii')

def from_token(token: str) -> bytes:
    return base64.b85decode(''.join(token.split()))


_HAN_BASE = 0xAC00      # '가'
_HAN_DATA = 8192        # 자료용 코드 0..8191
_HAN_MARK = _HAN_DATA   # 표시용 코드 8192..8204


def to_hangul(blob: bytes) -> str:
    n = len(blob)
    out = [chr(_HAN_BASE + _HAN_MARK + (n % 13))]
    acc = nbits = 0
    for b in blob:
        acc = (acc << 8) | b
        nbits += 8
        while nbits >= 13:
            nbits -= 13
            out.append(chr(_HAN_BASE + (acc >> nbits)))
            acc &= (1 << nbits) - 1
    if nbits:
        out.append(chr(_HAN_BASE + (acc << (13 - nbits))))   # 남는 비트는 0으로
    return ''.join(out)


def from_hangul(text: str) -> bytes:
    s = ''.join(text.split())
    if not s:
        raise ValueError('빈 글자열입니다.')
    mark = ord(s[0]) - _HAN_BASE
    if not (_HAN_MARK <= mark <= _HAN_MARK + 12):
        raise ValueError('한글 암호문이 아닙니다.')
    r = mark - _HAN_MARK
    cnt = len(s) - 1

    n = -1
    for cand in range(max(0, (13 * (cnt - 1)) // 8), (13 * cnt) // 8 + 1):
        if -(-8 * cand // 13) == cnt and cand % 13 == r:
            n = cand
            break
    if n < 0:
        raise ValueError('한글 암호문의 길이가 맞지 않습니다.')

    out = bytearray()
    acc = nbits = 0
    for ch in s[1:]:
        v = ord(ch) - _HAN_BASE
        if not (0 <= v < _HAN_DATA):
            raise ValueError(f'한글 암호문이 아닌 글자가 있습니다: {ch!r}')
        acc = (acc << 13) | v
        nbits += 13
        while nbits >= 8 and len(out) < n:
            nbits -= 8
            out.append((acc >> nbits) & 255)
            acc &= (1 << nbits) - 1
    if len(out) != n:
        raise ValueError('한글 암호문 복원에 실패했습니다.')
    return bytes(out)


def is_hangul_token(text: str) -> bool:
    s = ''.join(text.split())
    return bool(s) and _HAN_MARK <= (ord(s[0]) - _HAN_BASE) <= _HAN_MARK + 12


def decode_token(text: str) -> bytes:
    """한글이든 base85든 알아서 읽는다."""
    return from_hangul(text) if is_hangul_token(text) else from_token(text)


# ════════════════════════════════════════════════════════════════════
#  6. CLI
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
    print(f"{'원문':>6} {'gzip':>6} {'bz2':>6} {'xz':>6} {'이도구':>7} "
          f"{'base85':>7} {'한글':>5}  내용")
    print('-' * 84)
    ok = True
    for s in samples:
        raw = s.encode('utf-8')
        blob = encrypt(s, 'test-비밀번호')          # 기본은 v2
        tok = to_token(blob)
        han = to_hangul(blob)
        try:
            # 한글·base85 어느 표기로 적어도 똑같이 읽혀야 한다
            good = (decrypt(decode_token(han), 'test-비밀번호') == s
                    and decrypt(decode_token(tok), 'test-비밀번호') == s)
        except Exception as e:
            good = False; print('  오류:', e)
        ok &= good
        g = len(zlib.compress(raw, 9)) if raw else 0
        b = len(bz2.compress(raw, 9)) if raw else 0
        x = len(lzma.compress(raw, preset=9)) if raw else 0
        mark = '' if good else '  ← 실패!'
        print(f'{len(raw):6d} {g:6d} {b:6d} {x:6d} {len(blob):7d} '
              f'{len(tok):7d} {len(han):5d}  {s[:20]!r}{mark}')
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

    # 한글 표기 왕복 (모든 길이에서 바이트 수를 정확히 되찾아야 한다)
    han_ok = True
    for n in range(0, 120):
        blob = bytes((i * 37 + 11) & 255 for i in range(n))
        try:
            if from_hangul(to_hangul(blob)) != blob: han_ok = False
        except Exception:
            han_ok = False
    print('한글 표기 왕복(0~119바이트):', '정상' if han_ok else '실패!')
    ok &= han_ok

    # 길이 감추기: 풀리는 내용은 같고, 길이는 Padmé 단계에 맞춰져야 한다
    pad_ok = True
    for s in ('', '짧은 글', '내일 세 시에 강남역에서 만나요', '가나다라 ' * 200):
        blob = encrypt(s, 'pw', pad=True)
        pad_ok &= decrypt(blob, 'pw') == s and len(blob) == _pad_target(len(blob))
    print('길이 감추기 왕복:', '정상' if pad_ok else '실패!')
    ok &= pad_ok

    # 공개키: RFC 7748 시험 벡터, 왕복, 다른 열쇠 거부
    a_sk = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
    b_pk = bytes.fromhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
    pk_ok = x25519(a_sk, b_pk).hex() == ('4a5d9d5ba4ce2de1728e3bf480350f25'
                                          'e07e21c947d19e3376f09b3c1e161742')
    sk, pk = generate_keypair()
    for s in ('', '공개키로 봉인한 밀서'):
        pk_ok &= decrypt(encrypt(s, to=pk), secret=sk) == s
    try:
        decrypt(encrypt('남의 글', to=pk), secret=generate_keypair()[0])
        pk_ok = False
    except ValueError:
        pass
    print('공개키 봉인 (RFC 7748 · 왕복 · 다른 열쇠 거부):', '정상' if pk_ok else '실패!')
    ok &= pk_ok
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
            p.add_argument('--pad', action='store_true',
                           help='길이 감추기 — 길이로 내용을 짐작하지 못하게 채운다 (최대 12%% 늘어남)')
            p.add_argument('--base85', action='store_true',
                           help='한글 대신 base85로 출력 (영문만 받는 곳에 붙일 때)')
            p.add_argument('--to', metavar='공개키',
                           help='받는 사람의 공개키로 봉인 (열쇠말 대신)')
        else:
            p.add_argument('--secret', metavar='개인열쇠',
                           help='공개키로 봉인된 글을 내 개인 열쇠로 푼다')
            p.add_argument('--secret-file', metavar='파일',
                           help='개인 열쇠가 적힌 파일 (명령줄 기록에 남기지 않으려면 이쪽)')
    sub.add_parser('selftest', help='자체 검증 및 압축률 비교')
    kg = sub.add_parser('keygen', help='공개키 봉인용 새 열쇠 쌍 만들기')
    kg.add_argument('-o', '--out', dest='outfile', metavar='파일',
                    help='개인 열쇠를 이 파일에 저장 (화면에는 공개키만 보여 준다)')

    a = ap.parse_args(argv)
    if a.cmd == 'selftest':
        return _selftest()
    if a.cmd == 'keygen':
        sk, pk = generate_keypair()
        if a.outfile:
            with open(a.outfile, 'w', encoding='utf-8', newline='') as f:
                f.write(sk + '\n')
            print(f'개인 열쇠를 {a.outfile} 에 저장했습니다. 이 파일은 남에게 보이지 마세요.',
                  file=sys.stderr)
        else:
            print(f'개인 열쇠  {sk}   ← 남에게 절대 보이지 마세요')
        print(f'공개키     {pk}   ← 봉인해 받을 사람에게 알려 주세요')
        print(f'지문       {key_fingerprint(pk)}   ← 받은 쪽과 목소리로 맞춰 보세요')
        return 0

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
        if a.to and a.key:
            print('열쇠말(-k)과 공개키(--to) 중 하나만 쓰세요.', file=sys.stderr)
            return 2
        t0 = time.time()
        blob = encrypt(text, a.key, pad=a.pad, to=a.to, **kw)
        dt = time.time() - t0
        encode = to_token if a.base85 else to_hangul
        if a.outfile:
            mode_bin = a.binary or a.outfile.endswith(('.bin', '.hgc'))
            if mode_bin:
                with open(a.outfile, 'wb') as f:
                    f.write(blob)
            else:
                # newline='' — 윈도우에서 \n 이 \r\n 으로 바뀌면 안 된다
                with open(a.outfile, 'w', encoding='utf-8', newline='') as f:
                    f.write(encode(blob))
            print(f'{a.outfile} 저장됨', file=sys.stderr)
        elif a.binary:
            sys.stdout.buffer.write(blob)
        else:
            print(encode(blob))
        r = len(blob) / max(1, len(data))
        print(f'[원문 {len(data)}B → {len(blob)}B  ({r:.1%}, {dt:.1f}초, '
              f'{len(encode(blob))}글자)]', file=sys.stderr)
    else:
        secret = a.secret
        if a.secret_file:
            with open(a.secret_file, encoding='utf-8') as f:
                secret = f.read().strip()
        text = None
        errs = []
        for blob in _input_candidates(data):
            try:
                text = decrypt(blob, a.key, secret=secret); break
            except Exception as e:
                errs.append(str(e))
        if text is None:
            print('복호화 실패: ' + (errs[0] if errs else '입력 형식을 인식할 수 없습니다.'),
                  file=sys.stderr)
            return 1
        if a.outfile:
            # newline='' — 윈도우에서 \n 이 \r\n 으로 바뀌면 원문과 달라진다
            with open(a.outfile, 'w', encoding='utf-8', newline='') as f:
                f.write(text)
            print(f'{a.outfile} 저장됨', file=sys.stderr)
        else:
            print(text)
    return 0


def _input_candidates(data: bytes):
    """입력이 한글 토큰인지 base85인지 원시 바이트인지 모를 때 차례로 시도한다."""
    try:
        text = data.decode('utf-8').strip()
    except Exception:
        text = None
    if text:
        if is_hangul_token(text):
            try:
                yield from_hangul(text)
            except Exception:
                pass
        try:
            yield from_token(text)
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
