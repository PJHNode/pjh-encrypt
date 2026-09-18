/*!
 * hangul_crypt.js — hangul_crypt.py의 JavaScript 포팅 (브라우저 / Node.js)
 *
 * Python 버전과 바이트 단위로 호환된다. 단, 브라우저에는 lzma 압축기가 없으므로
 * 압축 방식 후보에서 lzma(mid=2)를 제외한다. 무압축(0)과 CM(1)만 만들고 읽는다.
 * Python이 lzma를 골라 만든 토큰은 여기서 풀 수 없으며, 명확한 오류로 알린다.
 *
 * 64비트 곱셈이 여럿 나오지만 결과는 항상 하위 20비트(_MASK)만 쓰인다.
 * 곱셈의 하위 비트는 피연산자의 하위 비트에만 의존하므로, 하위 32비트만
 * 계산해도(Math.imul) Python의 임의정밀도 결과와 정확히 일치한다.
 *
 * 비동기 함수는 PBKDF2/HMAC/SHA-256에 WebCrypto를 쓰기 때문이다.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.HangulCrypt = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var webcrypto = (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle)
    ? globalThis.crypto
    : (typeof require === 'function' ? require('crypto').webcrypto : null);
  if (!webcrypto) throw new Error('WebCrypto를 사용할 수 없습니다 (HTTPS 또는 localhost 필요).');

  // ══════════════════════════════════════════════════════════════════
  //  1. 예열 코퍼스 — hangul_crypt.py의 CORPUS와 반드시 바이트까지 같아야 한다.
  //     tools/sync_corpus.py 가 .py에서 읽어 아래 블록을 자동으로 갱신한다.
  //     손으로 고치지 말 것.
  // ══════════════════════════════════════════════════════════════════
  // >>> CORPUS-BEGIN (자동 생성) >>>
  var CORPUS = "\uc774 \uadf8 \uc800 \uac83 \uc218 \ub4f1 \ub4e4 \ubc0f \uccab \ud55c \ub450 \uc138 \ub124 \ub54c \uacf3 \ub9d0 \uc77c \ub144 \uc6d4 \uc77c \uc2dc \ubd84 \ucd08 \uc911 \ud6c4 \uc804 \uc548 \ubc16 \uc704 \uc544\ub798 \uc55e \ub4a4 \uc606 \uc18d \uc0ac\uc774 \ub3d9\uc548 \ub300\ub85c \ub9cc\ud07c \ucc98\ub7fc \ubcf4\ub2e4 \ubd80\ud130 \uae4c\uc9c0 \uc5d0\uac8c \uc5d0\uc11c \uc73c\ub85c \ub85c\uc11c \ub85c\uc368 \uc640 \uacfc \ud558\uace0 \uc774\ub098 \uac70\ub098 \uc9c0\ub9cc \ub294\ub370 \ub2c8\uae4c \uc5b4\uc11c \uc544\uc11c \uba74\uc11c \ub824\uace0 \ub3c4\ub85d \uac8c\ub054 \ub4e0\uc9c0 \ub77c\ub3c4 \uc870\ucc28 \ub9c8\uc800 \ubfd0 \ub530\ub984 \ub54c\ubb38 \ub355\ubd84 \ud0d3 \uacbd\uc6b0 \uc815\ub3c4 \ubb34\ub835 \uc988\uc74c\n\ud558\ub2e4 \ub418\ub2e4 \uc788\ub2e4 \uc5c6\ub2e4 \uac19\ub2e4 \ub2e4\ub974\ub2e4 \ud06c\ub2e4 \uc791\ub2e4 \ub9ce\ub2e4 \uc801\ub2e4 \uc88b\ub2e4 \ub098\uc058\ub2e4 \uc0c8\ub86d\ub2e4 \uc624\ub798\ub418\ub2e4 \uc27d\ub2e4 \uc5b4\ub835\ub2e4 \ube60\ub974\ub2e4 \ub290\ub9ac\ub2e4 \ub192\ub2e4 \ub0ae\ub2e4 \uae38\ub2e4 \uc9e7\ub2e4 \ub113\ub2e4 \uc881\ub2e4 \uae4a\ub2e4 \uc595\ub2e4 \ubc1d\ub2e4 \uc5b4\ub461\ub2e4 \ub530\ub73b\ud558\ub2e4 \ucc28\uac11\ub2e4 \uc870\uc6a9\ud558\ub2e4 \uc2dc\ub044\ub7fd\ub2e4 \uac00\ubccd\ub2e4 \ubb34\uac81\ub2e4 \uac15\ud558\ub2e4 \uc57d\ud558\ub2e4 \uc911\uc694\ud558\ub2e4 \ud544\uc694\ud558\ub2e4 \uac00\ub2a5\ud558\ub2e4 \ubd88\uac00\ub2a5\ud558\ub2e4 \ubd84\uba85\ud558\ub2e4 \ud655\uc2e4\ud558\ub2e4 \uc790\uc5f0\uc2a4\ub7fd\ub2e4 \uc801\uc808\ud558\ub2e4 \ucda9\ubd84\ud558\ub2e4 \ubd80\uc871\ud558\ub2e4\n\ud569\ub2c8\ub2e4 \uc2b5\ub2c8\ub2e4 \uc785\ub2c8\ub2e4 \ud588\uc2b5\ub2c8\ub2e4 \ub429\ub2c8\ub2e4 \uc788\uc2b5\ub2c8\ub2e4 \uc5c6\uc2b5\ub2c8\ub2e4 \uac11\ub2c8\ub2e4 \uc635\ub2c8\ub2e4 \ubd05\ub2c8\ub2e4 \uac19\uc2b5\ub2c8\ub2e4 \ub4dc\ub9bd\ub2c8\ub2e4 \uc8fc\uc2ed\uc2dc\uc624 \ubc14\ub78d\ub2c8\ub2e4 \ud558\uc600\ub2e4 \uc774\uc5c8\ub2e4 \ud558\ub294 \ub418\ub294 \uc788\ub294 \uc5c6\ub294 \ud558\uc9c0\ub9cc \uadf8\ub7ec\ub098 \uadf8\ub798\uc11c \ub530\ub77c\uc11c \uadf8\ub9ac\uace0 \ub610\ud55c \uc989 \ub2e4\ub9cc \uc624\ud788\ub824 \ubb3c\ub860 \uc0ac\uc2e4 \uacb0\uad6d \ub9c8\uce68\ub0b4 \ube44\ub85c\uc18c \uc774\ubbf8 \uc544\uc9c1 \ubc8c\uc368 \uace7 \ub298 \ud56d\uc0c1 \uc790\uc8fc \uac00\ub054 \ub54c\ub54c\ub85c \uac70\uc758 \uc804\ud600 \uacb0\ucf54 \ubc18\ub4dc\uc2dc \uc544\ub9c8 \uc5b4\uca4c\uba74 \ub9cc\uc57d \ube44\ub85d \uc124\ub839\n\ub098\ub294 \ub108\ub294 \uc6b0\ub9ac\ub294 \uadf8\ub294 \uadf8\ub140\ub294 \uc0ac\ub78c\ub4e4\uc740 \uc544\uc774\ub4e4\uc740 \ud559\uc0dd\ub4e4\uc740 \uc120\uc0dd\ub2d8\uc740 \ubd80\ubaa8\ub2d8\uc740 \uce5c\uad6c\ub4e4\uacfc \ub3d9\uc0dd\uacfc \ud615\uacfc \ub204\ub098\uc640 \uc5b8\ub2c8\uc640 \uc624\ube60\uc640 \uac00\uc871\uacfc \uc774\uc6c3\uacfc \uc0ac\ud68c\ub294 \uad6d\uac00\ub294 \uc815\ubd80\ub294 \uae30\uc5c5\uc740 \uc2dc\uc7a5\uc740 \ud559\uad50\ub294 \uad50\uc2e4\uc740 \ub3c4\uc11c\uad00\uc5d0\uc11c \uc6b4\ub3d9\uc7a5\uc5d0\uc11c \uc9d1\uc5d0\uc11c \ubc29\uc5d0\uc11c \uac70\ub9ac\uc5d0\uc11c \uacf5\uc6d0\uc5d0\uc11c \uce74\ud398\uc5d0\uc11c \ud68c\uc0ac\uc5d0\uc11c \ubcd1\uc6d0\uc5d0\uc11c \uc5ed\uc5d0\uc11c\n\uc624\ub298 \uc544\uce68\uc5d0 \uc77c\uc5b4\ub098\uc11c \ucc3d\ubb38\uc744 \uc5f4\uc5c8\ub354\ub2c8 \ubc14\ub78c\uc774 \uc120\uc120\ud558\uac8c \ub4e4\uc5b4\uc654\ub2e4. \uc5b4\uc81c\ubcf4\ub2e4 \ud655\uc2e4\ud788 \uacf5\uae30\uac00 \ucc28\uac00\uc6cc\uc9c4 \ub290\ub08c\uc774\uc5c8\ub2e4. \uac04\ub2e8\ud558\uac8c \ubc25\uc744 \uba39\uace0 \uac00\ubc29\uc744 \ucc59\uaca8\uc11c \uc9d1\uc744 \ub098\uc130\ub2e4. \ubc84\uc2a4 \uc815\ub958\uc7a5\uae4c\uc9c0 \uac78\uc5b4\uac00\ub294 \ub3d9\uc548 \ub099\uc5fd\uc774 \ubc1c\ubc11\uc5d0\uc11c \ubc14\uc2a4\ub77d\uac70\ub838\ub2e4. \uc2dc\uac04\uc774 \ucc38 \ube60\ub974\uac8c \uc9c0\ub098\uac04\ub2e4\ub294 \uc0dd\uac01\uc774 \ub4e4\uc5c8\ub2e4. \uc694\uc998\uc740 \ud558\ub8e8\ud558\ub8e8\uac00 \ube44\uc2b7\ud558\uac8c \ud758\ub7ec\uac00\ub294 \uac83 \uac19\uc73c\uba74\uc11c\ub3c4, \ub3cc\uc544\ubcf4\uba74 \uc870\uae08\uc529 \ub2ec\ub77c\uc838 \uc788\ub2e4.\n\ud559\uad50\uc5d0 \ub3c4\ucc29\ud574\uc11c \uccab \uc218\uc5c5\uc744 \ub4e4\uc5c8\ub2e4. \uc120\uc0dd\ub2d8\uaed8\uc11c \uc9c0\ub09c \uc2dc\uac04\uc5d0 \ubc30\uc6b4 \ub0b4\uc6a9\uc744 \ub2e4\uc2dc \uc815\ub9ac\ud574 \uc8fc\uc168\ub294\ub370, \uadf8\uc81c\uc57c \uc774\ud574\uac00 \ub418\ub294 \ubd80\ubd84\uc774 \uc788\uc5c8\ub2e4. \uc5ed\uc2dc \ud55c \ubc88\uc5d0 \uc54c\uc544\ub4e3\uae30\ub294 \uc5b4\ub835\uace0, \uc5ec\ub7ec \ubc88 \ubc18\ubcf5\ud574\uc11c \ubd10\uc57c \ud55c\ub2e4\ub294 \uac78 \ub2e4\uc2dc \ub290\uaf08\ub2e4. \uc26c\ub294 \uc2dc\uac04\uc5d0\ub294 \uce5c\uad6c\ub4e4\uacfc \uc774\uc57c\uae30\ub97c \ub098\ub204\uc5c8\ub2e4. \ubcc4\uac83 \uc544\ub2cc \ub300\ud654\uc600\uc9c0\ub9cc \uc6c3\uc73c\uba74\uc11c \uc2dc\uac04\uc744 \ubcf4\ub0b4\ub2c8 \uae30\ubd84\uc774 \ub098\uc544\uc84c\ub2e4.\n\uc218\ud559 \ubb38\uc81c\ub97c \ud480 \ub54c\ub294 \uba3c\uc800 \uc870\uac74\uc744 \uc815\ub9ac\ud558\ub294 \uac83\uc774 \uc911\uc694\ud558\ub2e4. \uc8fc\uc5b4\uc9c4 \uc2dd\uc744 \uadf8\ub300\ub85c \uacc4\uc0b0\ud558\ub824\uace0 \ud558\uba74 \ubcf5\uc7a1\ud574\uc9c0\ub294 \uacbd\uc6b0\uac00 \ub9ce\ub2e4. \ud568\uc218\uc758 \uadf8\ub798\ud504\ub97c \uadf8\ub824\ubcf4\uac70\ub098, \ub300\uce6d\uc131\uc744 \uc774\uc6a9\ud558\uac70\ub098, \ubcc0\uc218\ub97c \uce58\ud658\ud558\uba74 \ud6e8\uc52c \uac04\ub2e8\ud574\uc9c4\ub2e4. \uc774\ucc28\ud568\uc218\uc758 \ucd5c\ub313\uac12\uacfc \ucd5c\uc19f\uac12\uc740 \uaf2d\uc9d3\uc810\uc744 \uad6c\ud558\uba74 \ubc14\ub85c \uc54c \uc218 \uc788\uace0, \uc0bc\ucc28\ud568\uc218\ub294 \ubbf8\ubd84\ud574\uc11c \uadf9\uac12\uc744 \ucc3e\uc544\uc57c \ud55c\ub2e4. \ubd80\ub4f1\uc2dd\uc744 \ub2e4\ub8f0 \ub54c\ub294 \uc591\ubcc0\uc5d0 \uc74c\uc218\ub97c \uacf1\ud558\uba74 \ubd80\ub4f1\ud638\uc758 \ubc29\ud5a5\uc774 \ubc14\ub010\ub2e4\ub294 \uc810\uc744 \uc78a\uc9c0 \ub9d0\uc544\uc57c \ud55c\ub2e4.\n\uc815\ub2f5\uc744 \ub9de\ud788\ub294 \uac83\ubcf4\ub2e4 \uc65c \uadf8\ub807\uac8c \ub418\ub294\uc9c0\ub97c \uc124\uba85\ud560 \uc218 \uc788\ub294 \uac83\uc774 \ub354 \uc911\uc694\ud558\ub2e4\uace0 \uc0dd\uac01\ud55c\ub2e4. \ud480\uc774 \uacfc\uc815\uc744 \ub2e4\uc2dc \uc368\ubcf4\uba74 \uc790\uc2e0\uc774 \uc5b4\ub514\uc5d0\uc11c \ud5f7\uac08\ub838\ub294\uc9c0 \uc54c\uac8c \ub41c\ub2e4. \ubb38\uc81c\ub97c \ub9ce\uc774 \ud478\ub294 \uac83\ub3c4 \ud544\uc694\ud558\uc9c0\ub9cc, \ud2c0\ub9b0 \ubb38\uc81c\ub97c \uc81c\ub300\ub85c \ubd84\uc11d\ud558\ub294 \ud3b8\uc774 \ud6e8\uc52c \ud6a8\uc728\uc801\uc774\ub2e4. \uac1c\ub150\uc744 \uc815\ud655\ud788 \uc54c\uace0 \uc788\uc73c\uba74 \ucc98\uc74c \ubcf4\ub294 \uc720\ud615\uc774 \ub098\uc640\ub3c4 \uc811\uadfc\ud560 \ubc29\ubc95\uc744 \ucc3e\uc744 \uc218 \uc788\ub2e4.\n\uc9d1\ud569\uacfc \uba85\uc81c, \ud568\uc218\uc640 \uc218\uc5f4, \ubbf8\ubd84\uacfc \uc801\ubd84, \ud655\ub960\uacfc \ud1b5\uacc4\ub294 \uc11c\ub85c \uc5f0\uacb0\ub418\uc5b4 \uc788\ub2e4. \ud558\ub098\uc758 \ub2e8\uc6d0\uc744 \uacf5\ubd80\ud560 \ub54c\ub3c4 \ub2e4\ub978 \ub2e8\uc6d0\uacfc \uc5b4\ub5a4 \uad00\uacc4\uac00 \uc788\ub294\uc9c0 \uc0dd\uac01\ud558\uba74 \uc774\ud574\uac00 \uae4a\uc5b4\uc9c4\ub2e4. \uc608\ub97c \ub4e4\uc5b4 \uc218\uc5f4\uc758 \uadf9\ud55c\uc740 \ud568\uc218\uc758 \uadf9\ud55c\uacfc \uac19\uc740 \uc544\uc774\ub514\uc5b4\ub97c \uacf5\uc720\ud558\uace0, \uc801\ubd84\uc740 \ub113\uc774\uc640 \ubd80\ud53c\ub97c \uacc4\uc0b0\ud558\ub294 \ub3c4\uad6c\ub85c \uc4f0\uc778\ub2e4.\n\uacfc\ud559 \uc2dc\uac04\uc5d0\ub294 \uc2e4\ud5d8\uc744 \ud588\ub2e4. \uac00\uc124\uc744 \uc138\uc6b0\uace0, \ubcc0\uc778\uc744 \ud1b5\uc81c\ud558\uace0, \uacb0\uacfc\ub97c \uae30\ub85d\ud558\ub294 \uacfc\uc815\uc774 \uc0dd\uac01\ubcf4\ub2e4 \uae4c\ub2e4\ub85c\uc6e0\ub2e4. \uc608\uc0c1\uacfc \ub2e4\ub978 \uac12\uc774 \ub098\uc654\uc744 \ub54c \ubb34\uc5c7\uc774 \uc798\ubabb\ub418\uc5c8\ub294\uc9c0 \ucc3e\ub294 \uac83\uc774 \uc9c4\uc9dc \uacf5\ubd80\ub77c\ub294 \ub9d0\uc774 \uc774\ud574\uac00 \ub410\ub2e4. \uc628\ub3c4\uc640 \uc555\ub825, \ubd80\ud53c\uc758 \uad00\uacc4, \ud798\uacfc \uc6b4\ub3d9\uc758 \ubc95\uce59, \uc5d0\ub108\uc9c0\uc758 \ubcf4\uc874, \uc138\ud3ec\uc640 \uc720\uc804, \ubb3c\uc9c8\uc758 \uc0c1\ud0dc \ubcc0\ud654 \uac19\uc740 \uac1c\ub150\ub4e4\uc774 \ud558\ub098\uc529 \uc790\ub9ac\ub97c \uc7a1\uc544\uac00\uace0 \uc788\ub2e4.\n\uc0ac\ud68c \ubb38\uc81c\uc5d0 \uad00\ud55c \ucc45\uc744 \uc77d\uc5c8\ub2e4. \uc800\uc790\ub294 \uac1c\uc778\uc758 \ub178\ub825\ub9cc\uc73c\ub85c \ud574\uacb0\ud560 \uc218 \uc5c6\ub294 \uad6c\uc870\uc801\uc778 \ubb38\uc81c\ub4e4\uc774 \uc788\ub2e4\uace0 \ub9d0\ud588\ub2e4. \uad50\uc721 \uaca9\ucc28, \uc8fc\uac70 \ubd88\uc548\uc815, \ud658\uacbd \uc624\uc5fc, \uc815\ubcf4 \uaca9\ucc28, \uace0\ub839\ud654, \uccad\ub144 \uc2e4\uc5c5 \uac19\uc740 \uc8fc\uc81c\ub4e4\uc774 \ub2e4\ub904\uc84c\ub2e4. \uc5b4\ub290 \ud558\ub098\ub3c4 \ub2e8\uc21c\ud55c \uc6d0\uc778\uc73c\ub85c \uc124\uba85\ub418\uc9c0 \uc54a\uc558\ub2e4. \uc5ec\ub7ec \uc694\uc778\uc774 \ubcf5\uc7a1\ud558\uac8c \uc5bd\ud600 \uc788\uace0, \ud574\uacb0\ucc45 \uc5ed\uc2dc \uc5ec\ub7ec \ubc29\ud5a5\uc5d0\uc11c \ub3d9\uc2dc\uc5d0 \uc811\uadfc\ud574\uc57c \ud55c\ub2e4\ub294 \uc810\uc774 \uc778\uc0c1\uc801\uc774\uc5c8\ub2e4.\n\ud2b9\ud788 \uae30\uc5b5\uc5d0 \ub0a8\ub294 \uac83\uc740 \ucc45\uc784\uc758 \ubb38\uc81c\uc600\ub2e4. \uc5b4\ub5a4 \uc77c\uc774 \uc798\ubabb\ub418\uc5c8\uc744 \ub54c \ub204\uad6c\uc758 \uc798\ubabb\uc778\uc9c0\ub97c \ub530\uc9c0\ub294 \uac83\ub3c4 \ud544\uc694\ud558\uc9c0\ub9cc, \uadf8\ubcf4\ub2e4 \uba3c\uc800 \uc5b4\ub5a4 \uc870\uac74\uc774 \uadf8\ub7f0 \uacb0\uacfc\ub97c \ub9cc\ub4e4\uc5c8\ub294\uc9c0\ub97c \uc0b4\ud3b4\uc57c \ud55c\ub2e4\ub294 \uc8fc\uc7a5\uc774\uc5c8\ub2e4. \uac1c\uc778\uc744 \ud0d3\ud558\ub294 \ubc29\uc2dd\uc740 \uc27d\uace0 \ube60\ub974\uc9c0\ub9cc, \uac19\uc740 \ubb38\uc81c\uac00 \ubc18\ubcf5\ub418\ub294 \uac83\uc744 \ub9c9\uc9c0\ub294 \ubabb\ud55c\ub2e4.\n\ub514\uc9c0\ud138 \uae30\uc220\uc774 \uc6b0\ub9ac \uc0b6\uc744 \ubc14\uafb8\uace0 \uc788\ub2e4\ub294 \uc774\uc57c\uae30\ub294 \uc774\uc81c \uc0c8\ub86d\uc9c0 \uc54a\ub2e4. \ub2e4\ub9cc \uadf8 \ubcc0\ud654\uac00 \ubaa8\ub450\uc5d0\uac8c \uac19\uc740 \ubc29\uc2dd\uc73c\ub85c \ub2e4\uac00\uc624\uc9c0\ub294 \uc54a\ub294\ub2e4. \uc5b4\ub5a4 \uc0ac\ub78c\uc5d0\uac8c\ub294 \ud3b8\ub9ac\ud568\uc774\uc9c0\ub9cc, \ub2e4\ub978 \uc0ac\ub78c\uc5d0\uac8c\ub294 \uc0c8\ub85c\uc6b4 \uc7a5\ubcbd\uc774 \ub418\uae30\ub3c4 \ud55c\ub2e4. \uae30\uc220\uc744 \uc5b4\ub5bb\uac8c \uc124\uacc4\ud558\uace0 \ub204\uad6c\ub97c \uae30\uc900\uc73c\ub85c \ub9cc\ub4dc\ub294\uc9c0\uac00 \uc911\uc694\ud55c \uc774\uc720\ub2e4.\n\uc778\uacf5\uc9c0\ub2a5\uc5d0 \uad00\ud55c \ub17c\uc758\ub3c4 \ub9c8\ucc2c\uac00\uc9c0\ub2e4. \uae30\uc220 \uc790\uccb4\uc758 \uc131\ub2a5\ub9cc \uc774\uc57c\uae30\ud560 \uac83\uc774 \uc544\ub2c8\ub77c, \uadf8\uac83\uc774 \uc0ac\ud68c\uc5d0\uc11c \uc5b4\ub5a4 \uc5ed\ud560\uc744 \ud558\uac8c \ub418\ub294\uc9c0, \ub204\uac00 \uc774\uc775\uc744 \uc5bb\uace0 \ub204\uac00 \ubd88\uc774\uc775\uc744 \ubc1b\ub294\uc9c0\ub97c \ud568\uaed8 \uc0dd\uac01\ud574\uc57c \ud55c\ub2e4. \ud3b8\ub9ac\ud574\uc9c0\ub294 \ub9cc\ud07c \ub193\uce58\ub294 \uac83\ub3c4 \uc0dd\uae30\uae30 \ub54c\ubb38\uc774\ub2e4.\n\uc800\ub141\uc5d0\ub294 \uac00\uc871\ub4e4\uacfc \ud568\uaed8 \ubc25\uc744 \uba39\uc5c8\ub2e4. \uc624\ub79c\ub9cc\uc5d0 \ub2e4 \uac19\uc774 \ubaa8\uc5ec\uc11c \uc774\ub7f0\uc800\ub7f0 \uc774\uc57c\uae30\ub97c \ub098\ub204\uc5c8\ub2e4. \ubd80\ubaa8\ub2d8\uc740 \uc608\uc804 \uc774\uc57c\uae30\ub97c \ud558\uc168\uace0, \ub3d9\uc0dd\uc740 \ud559\uad50\uc5d0\uc11c \uc788\uc5c8\ub358 \uc77c\uc744 \uc2e0\ub098\uac8c \ub9d0\ud588\ub2e4. \ud2b9\ubcc4\ud55c \ub0b4\uc6a9\uc740 \uc544\ub2c8\uc5c8\uc9c0\ub9cc \uadf8\ub7f0 \uc2dc\uac04\uc774 \ud3b8\uc548\ud558\uac8c \ub290\uaef4\uc84c\ub2e4.\n\ubc24\uc5d0\ub294 \uc870\uc6a9\ud788 \uc74c\uc545\uc744 \ub4e4\uc73c\uba74\uc11c \ud558\ub8e8\ub97c \uc815\ub9ac\ud588\ub2e4. \uc798\ud55c \uc77c\ub3c4 \uc788\uace0 \uc544\uc26c\uc6b4 \uc77c\ub3c4 \uc788\uc5c8\ub2e4. \ub0b4\uc77c\uc740 \uc870\uae08 \ub354 \uc77c\ucc0d \uc77c\uc5b4\ub098\uc11c \uc5ec\uc720 \uc788\uac8c \uc900\ube44\ud574\uc57c\uaca0\ub2e4\uace0 \uc0dd\uac01\ud588\ub2e4. \uacc4\ud68d\uc744 \uc138\uc6b0\ub294 \uac83\uc740 \uc5b4\ub835\uc9c0 \uc54a\uc740\ub370 \uc9c0\ud0a4\ub294 \uac83\uc774 \ub298 \ubb38\uc81c\ub2e4. \uadf8\ub798\ub3c4 \uc870\uae08\uc529 \ub098\uc544\uc9c0\uace0 \uc788\ub2e4\uace0 \ubbff\ub294\ub2e4.\n\uc8fc\ub9d0\uc5d0\ub294 \uce5c\uad6c\uc640 \ub9cc\ub098\uae30\ub85c \ud588\ub2e4. \uc624\ub79c\ub9cc\uc5d0 \ubc16\uc5d0\uc11c \uac77\uace0 \uc774\uc57c\uae30\ub97c \ub098\ub20c \uc0dd\uac01\uc744 \ud558\ub2c8 \uae30\ub300\uac00 \ub41c\ub2e4. \ub0a0\uc528\uac00 \uc88b\uc73c\uba74 \uacf5\uc6d0\uc5d0 \uac00\uc11c \uc2dc\uac04\uc744 \ubcf4\ub0b4\ub3c4 \uc88b\uc744 \uac83 \uac19\ub2e4. \uc694\uc998\uc740 \ubc14\uc058\ub2e4\ub294 \uc774\uc720\ub85c \uc0ac\ub78c\ub4e4\uc744 \uc798 \ub9cc\ub098\uc9c0 \ubabb\ud588\ub294\ub370, \uc774\ub7f0 \uc2dc\uac04\uc774 \uacb0\uad6d \uac00\uc7a5 \uc624\ub798 \uae30\uc5b5\uc5d0 \ub0a8\ub294\ub2e4.\n\uc548\ub155\ud558\uc138\uc694. \ubb38\uc758\ub4dc\ub9b4 \ub0b4\uc6a9\uc774 \uc788\uc5b4 \uc5f0\ub77d\ub4dc\ub9bd\ub2c8\ub2e4. \ub9d0\uc500\ud574 \uc8fc\uc2e0 \uc790\ub8cc\ub97c \ud655\uc778\ud558\uc600\uc73c\uba70, \uba87 \uac00\uc9c0 \ucd94\uac00\ub85c \uc5ec\ucb59\uace0 \uc2f6\uc740 \uc810\uc774 \uc788\uc2b5\ub2c8\ub2e4. \uac00\ub2a5\ud558\uc2dc\ub2e4\uba74 \uc774\ubc88 \uc8fc \uc911\uc73c\ub85c \ub2f5\ubcc0 \uc8fc\uc2dc\uba74 \uac10\uc0ac\ud558\uaca0\uc2b5\ub2c8\ub2e4. \ubc14\uc058\uc2e0 \uc911\uc5d0 \uc2dc\uac04 \ub0b4\uc8fc\uc154\uc11c \uac10\uc0ac\ud569\ub2c8\ub2e4. \uc88b\uc740 \ud558\ub8e8 \ubcf4\ub0b4\uc2dc\uae30 \ubc14\ub78d\ub2c8\ub2e4.\n\ud68c\uc758\ub294 \ub2e4\uc74c \uc8fc \ud654\uc694\uc77c \uc624\ud6c4 \ub450 \uc2dc\uc5d0 \uc9c4\ud589\ub420 \uc608\uc815\uc785\ub2c8\ub2e4. \ucc38\uc11d\uc774 \uc5b4\ub824\uc6b0\uc2e0 \uacbd\uc6b0 \ubbf8\ub9ac \uc54c\ub824\uc8fc\uc2dc\uae30 \ubc14\ub78d\ub2c8\ub2e4. \uc790\ub8cc\ub294 \ud68c\uc758 \uc804\ub0a0\uae4c\uc9c0 \uacf5\uc720\ud574 \ub4dc\ub9ac\uaca0\uc2b5\ub2c8\ub2e4. \ub17c\uc758\ud560 \uc548\uac74\uc740 \ud06c\uac8c \uc138 \uac00\uc9c0\uc785\ub2c8\ub2e4. \uccab\uc9f8, \uc77c\uc815 \uc870\uc815\uc5d0 \uad00\ud55c \uc0ac\ud56d\uc785\ub2c8\ub2e4. \ub458\uc9f8, \uc608\uc0b0 \uc0ac\uc6a9 \uacc4\ud68d\uc785\ub2c8\ub2e4. \uc14b\uc9f8, \ud5a5\ud6c4 \uc9c4\ud589 \ubc29\ud5a5\uc5d0 \ub300\ud55c \uc758\uacac \uc218\ub834\uc785\ub2c8\ub2e4.\n\uc815\ubd80\ub294 \uc5b4\uc81c \uad00\ub828 \ub300\ucc45\uc744 \ubc1c\ud45c\ud588\ub2e4. \uc774\ubc88 \uc870\uce58\ub294 \ucd5c\uadfc \uc81c\uae30\ub41c \ubb38\uc81c\ub4e4\uc5d0 \ub300\uc751\ud558\uae30 \uc704\ud55c \uac83\uc73c\ub85c, \ub2e4\uc74c \ub2ec\ubd80\ud130 \uc21c\ucc28\uc801\uc73c\ub85c \uc2dc\ud589\ub41c\ub2e4. \uc804\ubb38\uac00\ub4e4\uc740 \uc2e4\ud6a8\uc131\uc5d0 \ub300\ud574 \uc5c7\uac08\ub9b0 \ud3c9\uac00\ub97c \ub0b4\ub193\uace0 \uc788\ub2e4. \uc77c\ubd80\ub294 \uae0d\uc815\uc801\uc778 \ubcc0\ud654\ub97c \uae30\ub300\ud560 \uc218 \uc788\ub2e4\uace0 \ubcf8 \ubc18\uba74, \ub2e4\ub978 \ucabd\uc5d0\uc11c\ub294 \uadfc\ubcf8\uc801\uc778 \ud574\uacb0\uc5d0\ub294 \ud55c\uacc4\uac00 \uc788\ub2e4\uace0 \uc9c0\uc801\ud588\ub2e4. \uc2dc\ubbfc\ub4e4\uc758 \ubc18\uc751\ub3c4 \ub2e4\uc591\ud558\uac8c \ub098\ud0c0\ub0ac\ub2e4.\n\uc9c0\ub09c\ud574 \uac19\uc740 \uae30\uac04\uacfc \ube44\uad50\ud558\uba74 \uc57d \uc2ed \ud37c\uc13c\ud2b8 \uc99d\uac00\ud55c \uc218\uce58\ub2e4. \uc870\uc0ac \uacb0\uacfc\uc5d0 \ub530\ub974\uba74 \uc751\ub2f5\uc790\uc758 \uc808\ubc18 \uc774\uc0c1\uc774 \ud544\uc694\uc131\uc5d0 \uacf5\uac10\ud55c\ub2e4\uace0 \ub2f5\ud588\ub2e4. \ub2e4\ub9cc \uad6c\uccb4\uc801\uc778 \ubc29\ubc95\uc5d0 \ub300\ud574\uc11c\ub294 \uc758\uacac\uc774 \ub098\ub258\uc5c8\ub2e4. \uc5f0\uad6c\uc9c4\uc740 \uc55e\uc73c\ub85c \ub354 \ub9ce\uc740 \uc790\ub8cc\ub97c \uc218\uc9d1\ud574 \ubd84\uc11d\ud560 \uacc4\ud68d\uc774\ub77c\uace0 \ubc1d\ud614\ub2e4.\n\uadf8\ub798 \uc54c\uc558\uc5b4 \uadf8\ub7fc \uc5b8\uc81c \ubcfc\uae4c \ub098\ub294 \uc544\ubb34 \ub54c\ub098 \uad1c\ucc2e\uc544 \ub108 \ud3b8\ud55c \uc2dc\uac04\uc73c\ub85c \ub9d0\ud574\uc918 \uc624\ub298\uc740 \uc880 \ud798\ub4e4 \uac83 \uac19\uace0 \ub0b4\uc77c\uc740 \uc5b4\ub54c \uc751 \uc88b\uc544 \uadf8\ub54c \ubcf4\uc790 \uace0\ub9c8\uc6cc \ubbf8\uc548\ud574 \uad1c\ucc2e\uc544 \uc815\ub9d0 \uc9c4\uc9dc \ub300\ubc15 \uc544 \ub9de\ub2e4 \uadf8\uac70 \uc5b4\ub5bb\uac8c \ub410\uc5b4 \uc798 \ub410\uc5b4 \ub2e4\ud589\uc774\ub2e4 \uc218\uace0\ud588\uc5b4 \uc870\uc2ec\ud788 \uac00 \uc798 \uc790 \ub0b4\uc77c \ubd10\n\ubb34\uc5c7\uc744 \uc5b4\ub5bb\uac8c \uc65c \uc5b8\uc81c \uc5b4\ub514\uc11c \ub204\uac00 \uc5bc\ub9c8\ub098 \uc5b4\ub5a4 \uadf8\ub7f0 \uc774\ub7f0 \uc800\ub7f0 \uc774\ub807\uac8c \uadf8\ub807\uac8c \uc800\ub807\uac8c \uc544\ub9c8\ub3c4 \ud639\uc2dc \uc5ed\uc2dc \ud2b9\ud788 \uc608\ub97c \ub4e4\uc5b4 \ub2e4\uc2dc \ub9d0\ud574 \ud55c\ud3b8 \ubc18\uba74\uc5d0 \uadf8\ub7fc\uc5d0\ub3c4 \ubd88\uad6c\ud558\uace0 \uc774\uc5d0 \ub530\ub77c \uadf8 \uacb0\uacfc \ubb34\uc5c7\ubcf4\ub2e4 \uc6b0\uc120 \ub9c8\uc9c0\ub9c9\uc73c\ub85c \uc815\ub9ac\ud558\uba74 \uc694\uc57d\ud558\uc790\uba74 \uacb0\ub860\uc801\uc73c\ub85c\n\uc0dd\uac01\ud55c\ub2e4 \ub290\uaf08\ub2e4 \uc54c\uc558\ub2e4 \ubab0\ub790\ub2e4 \ubc30\uc6e0\ub2e4 \uae68\ub2ec\uc558\ub2e4 \uae30\uc5b5\ud55c\ub2e4 \uc78a\uc5c8\ub2e4 \ubc14\ub780\ub2e4 \uc6d0\ud55c\ub2e4 \uc2eb\ub2e4 \uc88b\uc544\ud55c\ub2e4 \uad81\uae08\ud558\ub2e4 \uac71\uc815\ub41c\ub2e4 \uc548\uc2ec\ub41c\ub2e4 \uae30\ub300\ub41c\ub2e4 \uc544\uc27d\ub2e4 \ubfcc\ub4ef\ud558\ub2e4 \ub2f5\ub2f5\ud558\ub2e4 \ud3b8\uc548\ud558\ub2e4 \ubd88\uc548\ud558\ub2e4 \uc990\uac81\ub2e4 \uc9c0\ub8e8\ud558\ub2e4 \ub180\ub78d\ub2e4 \ub2f9\ud669\uc2a4\ub7fd\ub2e4 \uace0\ub9d9\ub2e4 \ubbf8\uc548\ud558\ub2e4\n\uc2dc\uc791\ud558\ub2e4 \ub05d\ub0b4\ub2e4 \uacc4\uc18d\ud558\ub2e4 \uba48\ucd94\ub2e4 \ubc14\uafb8\ub2e4 \uace0\uce58\ub2e4 \ub9cc\ub4e4\ub2e4 \ubd80\uc218\ub2e4 \ub298\ub9ac\ub2e4 \uc904\uc774\ub2e4 \ubaa8\uc73c\ub2e4 \ub098\ub204\ub2e4 \ucc3e\ub2e4 \uc783\ub2e4 \uc5bb\ub2e4 \uc8fc\ub2e4 \ubc1b\ub2e4 \ubcf4\ub0b4\ub2e4 \uac00\uc838\uc624\ub2e4 \uc62c\ub9ac\ub2e4 \ub0b4\ub9ac\ub2e4 \uc5f4\ub2e4 \ub2eb\ub2e4 \ub123\ub2e4 \ube7c\ub2e4 \uc313\ub2e4 \uc62e\uae30\ub2e4 \uc815\ub9ac\ud558\ub2e4 \uc900\ube44\ud558\ub2e4 \ud655\uc778\ud558\ub2e4 \uacb0\uc815\ud558\ub2e4 \uc120\ud0dd\ud558\ub2e4 \ud3ec\uae30\ud558\ub2e4 \ub3c4\uc804\ud558\ub2e4\n\ubb38\uc81c \ud574\uacb0 \ubc29\ubc95 \uacfc\uc815 \uacb0\uacfc \uc6d0\uc778 \uc774\uc720 \ubaa9\uc801 \ubaa9\ud45c \uacc4\ud68d \ubc29\ud5a5 \uae30\uc900 \uc870\uac74 \uc0c1\ud669 \ud658\uacbd \uad00\uacc4 \uc601\ud5a5 \ubcc0\ud654 \ubc1c\uc804 \uc131\uc7a5 \ucc28\uc774 \uacf5\ud1b5\uc810 \ud2b9\uc9d5 \uc7a5\uc810 \ub2e8\uc810 \ud55c\uacc4 \uac00\ub2a5\uc131 \ud544\uc694\uc131 \uc911\uc694\uc131 \uc758\ubbf8 \uac00\uce58 \uae30\uc900 \uc5ed\ud560 \ucc45\uc784 \uad8c\ub9ac \uc758\ubb34 \uaddc\uce59 \uc81c\ub3c4 \uc815\ucc45 \uc0ac\ud68c \ubb38\ud654 \uc5ed\uc0ac \uacbd\uc81c \uc815\uce58 \uad50\uc721 \uae30\uc220 \uacfc\ud559 \uc608\uc220 \uc5b8\uc5b4 \uc790\uc5f0 \uc778\uac04\n0123456789 abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ .,!?:;()[]\"'-~/@#%&*+=<> http https www com net org co.kr\n";
  // <<< CORPUS-END <<<

  var CORPUS_BYTES = new TextEncoder().encode(CORPUS);
  var CORPUS_FP = null; // sha256(CORPUS_BYTES)[0] — 최초 사용 시 계산

  async function corpusFingerprint() {
    if (CORPUS_FP === null) {
      var d = await webcrypto.subtle.digest('SHA-256', CORPUS_BYTES);
      CORPUS_FP = new Uint8Array(d)[0];
    }
    return CORPUS_FP;
  }

  // ══════════════════════════════════════════════════════════════════
  //  2. 문맥혼합 압축기
  // ══════════════════════════════════════════════════════════════════
  var SQUASH = new Int16Array(4096);
  for (var _i = 0; _i < 4096; _i++) {
    SQUASH[_i] = Math.max(1, Math.min(4094,
      Math.trunc(4096.0 / (1.0 + Math.exp(-(_i - 2048) / 256.0)))));
  }
  function squash(x) {
    if (x < -2047) x = -2047;
    else if (x > 2047) x = 2047;
    return SQUASH[x + 2048];
  }

  var STRETCH = new Int16Array(4096);
  (function () {
    var p = 0;
    for (var x = -2047; x < 2048; x++) {
      var v = squash(x), lim = Math.min(v + 1, 4096);
      for (var j = p; j < lim; j++) STRETCH[j] = x;
      p = v + 1;
    }
    for (var k = p; k < 4096; k++) STRETCH[k] = 2047;
  })();

  var RATE = new Int32Array(64);
  for (var _c = 0; _c < 64; _c++) RATE[_c] = Math.trunc(65536 * 2.0 / (_c + 2.0));
  var LIMIT = 60;

  var MASK = (1 << 20) - 1;

  // Python _MULT 각 상수의 하위 32비트
  var MULT_LO = [0x7F4A7C15 | 0, 0x85EBCA6B | 0, 0xC2B2AE35 | 0, 0x27D4EB2F | 0,
                 0x9E3779F9 | 0, 0x9E3779B1 | 0, 0xD6E8FEB8 | 0, 0x78BD642F | 0];
  var MULT32 = [0x7F4A7C15 | 0, 0x85EBCA6B | 0, 0xC2B2AE35 | 0, 0x27D4EB2F | 0,
                0x9E3779F9 | 0, 0x9E3779B1 | 0, 0xD6E8FEB8 | 0, 0x78BD642F | 0,
                0x1B873593 | 0, 0xCC9E2D51 | 0, 0xE6546B64 | 0, 0x9E3779B9 | 0];
  var GOLDEN_LO = 0x7F4A7C15 | 0;
  var WORD_MULT = 0x2F0FD693 | 0;
  var CM_MULT = 0x6F4F2F1F | 0;

  // 눈사태 마무리 — 상위 비트를 하위로 끌어내린다.
  // v1의 해시는 (이력 & 마스크) * 곱수 의 하위 20비트만 썼다. 곱셈의 하위 비트는
  // 피연산자의 하위 비트에만 의존하므로 3바이트 너머의 이력이 해시에 닿지 못했고,
  // 차수 4·6·8 모델이 차수 2.5 모델과 같은 것을 보고 있었다.
  function fin(x) {
    x ^= x >>> 16; x = Math.imul(x, 0x7FEB352D);
    x ^= x >>> 15; x = Math.imul(x, 0x846CA68B);
    x ^= x >>> 16;
    return x;
  }
  function lowMask(v, bits) { return bits >= 32 ? v : (v & ((1 << bits) - 1)); }

  function Cfg(orders, fixed, sparse, posMix) {
    this.orders = orders;
    this.fixed = fixed;
    this.sparse = sparse || [];
    this.posMix = !!posMix;
    this.nm = orders.length + this.sparse.length + 1;   // + 단어 모델
    this.nmix = posMix ? 2048 : 512;
  }

  //  v1 — 처음 배포한 구성. 이미 만들어 둔 암호문을 읽기 위해 그대로 남긴다.
  //  v2 — 해시 결함을 고치고 차수를 짧은 쪽으로 다시 잡았다. 약 4.8% 더 짧다.
  var CFG_V1 = new Cfg([0, 1, 2, 3, 4, 6, 8], false);
  var CFG_V2 = new Cfg([0, 1, 2, 3, 4, 5, 6], true, [[1, 2]], true);
  var ORDERS = CFG_V1.orders;
  var NM = CFG_V1.nm;

  function Model(cfg) {
    cfg = cfg || CFG_V1;
    this.cfg = cfg;
    var nm = cfg.nm;
    this.nm = nm;
    this.t = []; this.n = [];
    for (var i = 0; i < nm; i++) {
      var a = new Uint16Array(MASK + 1); a.fill(32768);
      this.t.push(a);
      this.n.push(new Uint8Array(MASK + 1));
    }
    this.w = [];
    for (var q = 0; q < cfg.nmix; q++) {
      var wv = new Int32Array(nm); wv.fill(1 << 14);
      this.w.push(wv);
    }
    this.apm = new Uint16Array(1024 * 33);
    for (var c = 0; c < 1024; c++) {
      var base = c * 33;
      for (var j = 0; j < 33; j++) this.apm[base + j] = squash((j - 16) * 128) * 16;
    }
    this.h = new Int32Array(nm);
    this.idx = new Int32Array(nm);
    this.st = new Int32Array(nm);
    this.c0 = 1;
    this.hist = 0;     // 직전 1~4바이트
    this.histHi = 0;   // 직전 5~8바이트 (v2만 사용)
    this.wh = 0;       // 단어 해시의 하위 32비트
    this.pos = 0;      // UTF-8 연속바이트 위치 (v2만 사용)
    this.pr = 2048;
    this._ai = 0;
    this._aw = 0;
    this._setCtx();
  }

  Model.prototype._setCtx = function () {
    var cfg = this.cfg, orders = cfg.orders, i, o;
    var h = this.hist;
    if (!cfg.fixed) {
      for (i = 0; i < orders.length; i++) {
        o = orders[i];
        if (o === 0) { this.h[i] = 0; continue; }
        // o가 4 이상이면 마스크가 32비트 이상 → 하위 32비트 전체가 그대로 남는다
        var masked = (o >= 4) ? h : (h & ((1 << (8 * o)) - 1));
        this.h[i] = Math.imul(masked, MULT_LO[i % 8]) & MASK;
      }
      this.h[this.nm - 1] = Math.imul(this.wh, GOLDEN_LO) & MASK;
      return;
    }
    var hi = this.histHi, a, b;
    for (i = 0; i < orders.length; i++) {
      o = orders[i];
      if (o === 0) { this.h[i] = 0; continue; }
      if (o <= 4) { a = lowMask(h, 8 * o); b = 0; }
      else { a = h; b = lowMask(hi, 8 * (o - 4)); }
      this.h[i] = fin(Math.imul(a, MULT32[i % 12]) ^
                      Math.imul(b + 0x165667B1, MULT32[(i + 5) % 12])) & MASK;
    }
    var k = orders.length;
    for (var s = 0; s < cfg.sparse.length; s++) {
      var acc = 0x9E3779B9 | 0;
      var offs = cfg.sparse[s];
      for (var t = 0; t < offs.length; t++)
        acc = Math.imul(acc ^ ((h >>> (8 * offs[t])) & 255), 0x85EBCA6B);
      this.h[k++] = fin(acc) & MASK;
    }
    this.h[k] = fin(Math.imul(this.wh, GOLDEN_LO)) & MASK;
  };

  Model.prototype._mixSel = function () {
    var base = (this.c0 & 255) | ((this.hist & 128) ? 256 : 0);
    return this.cfg.posMix ? base + 512 * this.pos : base;
  };

  Model.prototype.predict = function () {
    var c0 = this.c0;
    var w = this.w[this._mixSel()];
    var cm = Math.imul(c0, CM_MULT);
    var dot = 0;
    for (var i = 0; i < this.nm; i++) {
      var j = (this.h[i] ^ cm) & MASK;
      this.idx[i] = j;
      var s = STRETCH[this.t[i][j] >> 4];
      this.st[i] = s;
      dot += w[i] * s;
    }
    var p = squash(Math.floor(dot / 65536));
    var ctx = (c0 & 255) | ((this.hist & 3) << 8);
    var st = STRETCH[p];
    var lo = (st + 2048) >> 7;
    var wt = (st + 2048) & 127;
    var i0 = ctx * 33 + lo;
    this._ai = i0;
    this._aw = wt;
    var pa = (this.apm[i0] * (128 - wt) + this.apm[i0 + 1] * wt) >> 11;
    var pr = (p + 3 * pa) >> 2;
    if (pr < 1) pr = 1;
    else if (pr > 4094) pr = 4094;
    this.pr = pr;
    return pr;
  };

  Model.prototype.update = function (bit) {
    var g = (bit << 16) + (bit << 4) - bit - bit;
    var i0 = this._ai, wt = this._aw;
    this.apm[i0] += ((g - this.apm[i0]) * (128 - wt)) >> 12;
    this.apm[i0 + 1] += ((g - this.apm[i0 + 1]) * wt) >> 12;
    var err = ((bit << 12) - this.pr) * 10;
    var w = this.w[this._mixSel()];
    var tgt = bit << 16;
    for (var i = 0; i < this.nm; i++) {
      w[i] += (this.st[i] * err) >> 13;
      var j = this.idx[i];
      var t = this.t[i], n = this.n[i];
      var c = n[j];
      // (tgt - t[j]) * RATE[c] 는 32비트를 넘을 수 있어 부동소수점으로 계산한다.
      // Python의 >> 17 은 음수에서 내림이므로 Math.floor 가 맞다.
      t[j] += Math.floor((tgt - t[j]) * RATE[c] / 131072);
      if (c < LIMIT) n[j] = c + 1;
    }
    this.c0 = (this.c0 << 1) | bit;
    if (this.c0 >= 256) {
      var b = this.c0 & 255;
      this.histHi = ((this.histHi << 8) | ((this.hist >>> 24) & 255)) >>> 0;
      this.hist = ((this.hist << 8) | b) >>> 0;
      if (b >= 128 || (b >= 48 && b <= 57) || (b >= 65 && b <= 122)) {
        this.wh = (Math.imul(this.wh, WORD_MULT) + b + 1) | 0;
      } else {
        this.wh = 0;
      }
      if (this.cfg.posMix) {
        if (b < 0x80) this.pos = 0;
        else if (b >= 0xF0) this.pos = 3;
        else if (b >= 0xE0) this.pos = 2;
        else if (b >= 0xC0) this.pos = 1;
        else this.pos = this.pos > 0 ? this.pos - 1 : 0;
      }
      this.c0 = 1;
      this._setCtx();
    }
  };

  function Encoder() { this.x1 = 0; this.x2 = 4294967295; this.out = []; }

  Encoder.prototype.encode = function (bit, p) {
    var xmid = this.x1 + Math.floor((this.x2 - this.x1) / 4096) * p;
    if (bit) this.x2 = xmid; else this.x1 = xmid + 1;
    while (((this.x1 ^ this.x2) >>> 24) === 0) {
      this.out.push(this.x2 >>> 24);
      this.x1 = (this.x1 << 8) >>> 0;
      this.x2 = ((this.x2 << 8) | 255) >>> 0;
    }
  };

  Encoder.prototype.flush = function () {
    for (var n = 1; n < 5; n++) {
      var shift = 32 - 8 * n;
      var pow = Math.pow(2, shift);
      var v = (shift === 0) ? this.x1 : Math.ceil(this.x1 / pow) * pow;
      if (v <= this.x2) {
        for (var i = 0; i < n; i++) {
          this.out.push(Math.floor(v / Math.pow(2, 24 - 8 * i)) & 255);
        }
        break;
      }
    }
    return new Uint8Array(this.out);
  };

  function Decoder(d) {
    this.x1 = 0; this.x2 = 4294967295; this.d = d; this.p = 0; this.x = 0;
    for (var i = 0; i < 4; i++) this.x = (this.x * 256) + this._nb();
  }

  Decoder.prototype._nb = function () {
    return this.p < this.d.length ? this.d[this.p++] : 0;
  };

  Decoder.prototype.decode = function (p) {
    var xmid = this.x1 + Math.floor((this.x2 - this.x1) / 4096) * p;
    var bit = this.x <= xmid ? 1 : 0;
    if (bit) this.x2 = xmid; else this.x1 = xmid + 1;
    while (((this.x1 ^ this.x2) >>> 24) === 0) {
      this.x1 = (this.x1 << 8) >>> 0;
      this.x2 = ((this.x2 << 8) | 255) >>> 0;
      this.x = ((this.x << 8) | this._nb()) >>> 0;
    }
    return bit;
  };

  // 예열은 코퍼스 전체를 한 번 학습하는 것이라 비용이 크다.
  // 결과 상태를 한 번만 만들어 두고 매번 복사해서 쓴다.
  var _primeCache = new Map();   // cfg → 예열이 끝난 상태

  function snapshot(m) {
    return {
      cfg: m.cfg, nm: m.nm,
      t: m.t.map(function (a) { return a.slice(); }),
      n: m.n.map(function (a) { return a.slice(); }),
      w: m.w.map(function (a) { return a.slice(); }),
      apm: m.apm.slice(), h: m.h.slice(), idx: m.idx.slice(), st: m.st.slice(),
      c0: m.c0, hist: m.hist, histHi: m.histHi, wh: m.wh, pos: m.pos,
      pr: m.pr, _ai: m._ai, _aw: m._aw
    };
  }

  function primedModel(cfg) {
    if (!_primeCache.has(cfg)) {
      var m = new Model(cfg);
      for (var i = 0; i < CORPUS_BYTES.length; i++) {
        var byte = CORPUS_BYTES[i];
        for (var k = 7; k >= 0; k--) {
          m.predict();
          m.update((byte >> k) & 1);
        }
      }
      _primeCache.set(cfg, snapshot(m));
    }
    return _primeCache.get(cfg);
  }

  function restore(s) {
    var m = Object.create(Model.prototype);
    m.cfg = s.cfg; m.nm = s.nm;
    m.t = s.t.map(function (a) { return a.slice(); });
    m.n = s.n.map(function (a) { return a.slice(); });
    m.w = s.w.map(function (a) { return a.slice(); });
    m.apm = s.apm.slice(); m.h = s.h.slice(); m.idx = s.idx.slice(); m.st = s.st.slice();
    m.c0 = s.c0; m.hist = s.hist; m.histHi = s.histHi; m.wh = s.wh; m.pos = s.pos;
    m.pr = s.pr; m._ai = s._ai; m._aw = s._aw;
    return m;
  }

  // 캐시가 오염되지 않도록 항상 복사본을 준다
  function newPrimed(cfg) { return restore(primedModel(cfg || CFG_V1)); }

  function cmCompress(data, cfg) {
    var m = newPrimed(cfg);
    var e = new Encoder();
    for (var i = 0; i < data.length; i++) {
      var byte = data[i];
      for (var k = 7; k >= 0; k--) {
        var bit = (byte >> k) & 1;
        e.encode(bit, m.predict());
        m.update(bit);
      }
    }
    return e.flush();
  }

  function cmDecompress(blob, n, cfg) {
    var m = newPrimed(cfg);
    var d = new Decoder(blob);
    var out = new Uint8Array(n);
    for (var i = 0; i < n; i++) {
      for (var k = 0; k < 8; k++) {
        var bit = d.decode(m.predict());
        m.update(bit);
      }
      out[i] = m.hist & 255;
    }
    return out;
  }

  // ══════════════════════════════════════════════════════════════════
  //  3. ChaCha20 (RFC 8439)
  // ══════════════════════════════════════════════════════════════════
  function rotl(v, c) { return ((v << c) | (v >>> (32 - c))) >>> 0; }

  function chachaBlock(key32, counter, nonce12) {
    var s = new Uint32Array(16);
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    var kv = new DataView(key32.buffer, key32.byteOffset, 32);
    for (var i = 0; i < 8; i++) s[4 + i] = kv.getUint32(i * 4, true);
    s[12] = counter >>> 0;
    var nv = new DataView(nonce12.buffer, nonce12.byteOffset, 12);
    for (var j = 0; j < 3; j++) s[13 + j] = nv.getUint32(j * 4, true);

    var x = s.slice();
    function qr(a, b, c, d) {
      x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 16);
      x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 12);
      x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 8);
      x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 7);
    }
    for (var r = 0; r < 10; r++) {
      qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
      qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
    }
    var out = new Uint8Array(64);
    var ov = new DataView(out.buffer);
    for (var m = 0; m < 16; m++) ov.setUint32(m * 4, (x[m] + s[m]) >>> 0, true);
    return out;
  }

  function chacha20(key32, nonce12, data, counter) {
    if (counter === undefined) counter = 1;
    var out = new Uint8Array(data.length);
    for (var off = 0; off < data.length; off += 64) {
      var ks = chachaBlock(key32, counter, nonce12);
      counter++;
      var end = Math.min(off + 64, data.length);
      for (var i = off; i < end; i++) out[i] = data[i] ^ ks[i - off];
    }
    return out;
  }

  // ══════════════════════════════════════════════════════════════════
  //  4. 키 유도 + 컨테이너
  // ══════════════════════════════════════════════════════════════════
  var PBKDF2_ITERS = 200000;
  var SEED_OPT = [0, 4, 6, 8];
  var TAG_OPT = [0, 4, 8, 16];
  var NOKEY_PASSWORD = 'hangul-crypt-no-key';

  function concatBytes(parts) {
    var total = 0, i;
    for (i = 0; i < parts.length; i++) total += parts[i].length;
    var out = new Uint8Array(total), off = 0;
    for (i = 0; i < parts.length; i++) { out.set(parts[i], off); off += parts[i].length; }
    return out;
  }

  async function deriveKeys(password, seed) {
    var fp = await corpusFingerprint();
    var salt = concatBytes([new Uint8Array([0x48, 0x47, 0x43, 0x31, fp]), seed]); // 'HGC1'
    var base = await webcrypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    var bits = await webcrypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' }, base, 512);
    var dk = new Uint8Array(bits);
    return [dk.slice(0, 32), dk.slice(32, 64)];
  }

  async function hmacSha256(key, data) {
    var k = await webcrypto.subtle.importKey(
      'raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await webcrypto.subtle.sign('HMAC', k, data));
  }

  function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function varint(n) {
    var out = [];
    for (;;) {
      var b = n & 0x7F;
      n >>>= 7;
      out.push(b | (n ? 0x80 : 0));
      if (!n) return new Uint8Array(out);
    }
  }

  function readVarint(data, i) {
    var n = 0, sh = 0;
    for (;;) {
      if (i >= data.length) throw new Error('데이터가 잘렸습니다.');
      var b = data[i]; i++;
      n |= (b & 0x7F) << sh;
      if (!(b & 0x80)) return [n >>> 0, i];
      sh += 7;
    }
  }

  async function encrypt(text, password, opts) {
    opts = opts || {};
    var seedLen = opts.seedLen === undefined ? 6 : opts.seedLen;
    var tagLen = opts.tagLen === undefined ? 4 : opts.tagLen;
    var method = opts.method || 'auto';
    var version = opts.version === undefined ? 2 : opts.version;
    if (version !== 1 && version !== 2) throw new Error('버전은 1 또는 2');
    var cfg = version === 2 ? CFG_V2 : CFG_V1;
    if (password === undefined) password = null;

    var raw = new TextEncoder().encode(text);

    // 압축 방식 선택. Python과 달리 lzma 후보가 없다 (브라우저에 압축기 없음).
    // 헤더에 방식이 기록되므로 Python 쪽에서 읽는 데는 문제가 없다.
    var mid = 0, body = raw;
    var cands = [];
    if (method === 'auto' || method === 'raw') cands.push([0, raw]);
    if (method === 'auto' || method === 'cm') cands.push([1, cmCompress(raw, cfg)]);
    if (method === 'lzma') throw new Error('브라우저에서는 lzma 방식을 만들 수 없습니다.');
    if (!cands.length) throw new Error('알 수 없는 method: ' + method);
    mid = cands[0][0]; body = cands[0][1];
    for (var i = 1; i < cands.length; i++) {
      if (cands[i][1].length < body.length) { mid = cands[i][0]; body = cands[i][1]; }
    }

    var payload = (mid === 0) ? body : concatBytes([varint(raw.length), body]);

    var keyed = password !== null;
    var pw = keyed ? password : NOKEY_PASSWORD;
    if (SEED_OPT.indexOf(seedLen) < 0) throw new Error('시드 길이는 0/4/6/8');
    if (TAG_OPT.indexOf(tagLen) < 0) throw new Error('태그 길이는 0/4/8/16');

    var seed = new Uint8Array(seedLen);
    if (seedLen) webcrypto.getRandomValues(seed);

    var keys = await deriveKeys(pw, seed);
    var ct = chacha20(keys[0], new Uint8Array(12), payload);

    var hdr = new Uint8Array([
      mid | (SEED_OPT.indexOf(seedLen) << 2) | (TAG_OPT.indexOf(tagLen) << 4) |
      (keyed ? 0x40 : 0) | (version === 2 ? 0x80 : 0)
    ]);
    var blob = concatBytes([hdr, seed, ct]);
    if (tagLen) {
      var tag = await hmacSha256(keys[1], blob);
      blob = concatBytes([blob, tag.slice(0, tagLen)]);
    }
    return blob;
  }

  async function decrypt(blob, password) {
    if (password === undefined) password = null;
    if (!blob || !blob.length) throw new Error('빈 데이터입니다.');
    var hdr = blob[0];
    var mid = hdr & 3;
    var seedLen = SEED_OPT[(hdr >> 2) & 3];
    var tagLen = TAG_OPT[(hdr >> 4) & 3];
    var keyed = !!(hdr & 0x40);
    var cfg = (hdr & 0x80) ? CFG_V2 : CFG_V1;
    if (mid === 3) throw new Error('알 수 없는 형식입니다.');
    if (mid === 2) {
      throw new Error('이 데이터는 lzma로 압축되어 있습니다. 브라우저에서는 풀 수 없으니 ' +
        'Python 버전(hangul_crypt.py dec)으로 복호화하세요.');
    }
    if (keyed && password === null) throw new Error('이 데이터는 비밀번호가 필요합니다.');
    var pw = keyed ? password : NOKEY_PASSWORD;

    var seed = blob.slice(1, 1 + seedLen);
    var end = blob.length - tagLen;
    if (end < 1 + seedLen) throw new Error('데이터가 잘렸습니다.');
    var ct = blob.slice(1 + seedLen, end);

    var keys = await deriveKeys(pw, seed);
    if (tagLen) {
      var full = await hmacSha256(keys[1], blob.slice(0, end));
      if (!timingSafeEqual(full.slice(0, tagLen), blob.slice(end))) {
        throw new Error('인증 실패: 비밀번호가 틀렸거나, 데이터가 손상되었거나, ' +
          '프로그램 버전(코퍼스)이 다릅니다.');
      }
    }

    var payload = chacha20(keys[0], new Uint8Array(12), ct);
    var raw;
    if (mid === 0) {
      raw = payload;
    } else {
      var r = readVarint(payload, 0);
      var n = r[0], j = r[1];
      raw = cmDecompress(payload.slice(j), n, cfg);
      if (raw.length !== n) throw new Error('복호화 실패: 길이가 맞지 않습니다.');
    }
    return new TextDecoder('utf-8', { fatal: true }).decode(raw);
  }

  // ══════════════════════════════════════════════════════════════════
  //  5. base85 — Python base64.b85encode/b85decode와 동일 (RFC 1924 알파벳)
  // ══════════════════════════════════════════════════════════════════
  var B85 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
            '!#$%&()*+-;<=>?@^_`{|}~';
  var B85_DEC = (function () {
    var m = new Int16Array(256); m.fill(-1);
    for (var i = 0; i < 85; i++) m[B85.charCodeAt(i)] = i;
    return m;
  })();

  function toToken(blob) {
    var padding = (-blob.length % 4 + 4) % 4;
    var b = blob;
    if (padding) { b = new Uint8Array(blob.length + padding); b.set(blob); }
    var out = '';
    for (var i = 0; i < b.length; i += 4) {
      var acc = ((b[i] * 16777216) + (b[i + 1] * 65536) + (b[i + 2] * 256) + b[i + 3]);
      var chunk = '';
      for (var k = 0; k < 5; k++) { chunk = B85[acc % 85] + chunk; acc = Math.floor(acc / 85); }
      out += chunk;
    }
    if (padding) out = out.slice(0, out.length - padding);
    return out;
  }

  function fromToken(token) {
    var s = token.replace(/\s+/g, '');
    var padding = (-s.length % 5 + 5) % 5;
    if (padding) s += '~'.repeat(padding);
    var out = new Uint8Array(s.length / 5 * 4);
    var o = 0;
    for (var i = 0; i < s.length; i += 5) {
      var acc = 0;
      for (var k = 0; k < 5; k++) {
        var v = B85_DEC[s.charCodeAt(i + k)];
        if (v < 0) throw new Error('base85가 아닌 문자가 있습니다: ' + JSON.stringify(s[i + k]));
        acc = acc * 85 + v;
      }
      if (acc > 4294967295) throw new Error('base85 overflow');
      out[o++] = Math.floor(acc / 16777216) & 255;
      out[o++] = Math.floor(acc / 65536) & 255;
      out[o++] = Math.floor(acc / 256) & 255;
      out[o++] = acc & 255;
    }
    return padding ? out.slice(0, out.length - padding) : out;
  }

  // ── 한글 표기 ──────────────────────────────────────────────────
  //  음절 U+AC00..U+D7A3 은 11172자다. 그 중 8192자(2^13)만 쓰면 한 글자에
  //  정확히 13비트가 들어간다. base85(1.25글자/바이트)의 절반이다.
  //
  //  길이 되찾기: 글자 수에서 원래 바이트 수를 구할 때 후보가 둘(N, N+1) 생길
  //  수 있다. 두 후보는 13으로 나눈 나머지가 반드시 다르므로, 맨 앞에 (N mod 13)
  //  을 담은 표시 글자 하나를 붙이면 모호함이 사라진다.
  var HAN_BASE = 0xAC00;   // '가'
  var HAN_DATA = 8192;
  var HAN_MARK = HAN_DATA; // 표시용 코드 8192..8204

  function toHangul(blob) {
    var n = blob.length;
    var out = String.fromCharCode(HAN_BASE + HAN_MARK + (n % 13));
    var acc = 0, nbits = 0;
    for (var i = 0; i < n; i++) {
      acc = acc * 256 + blob[i];
      nbits += 8;
      while (nbits >= 13) {
        nbits -= 13;
        var p = Math.pow(2, nbits);
        var v = Math.floor(acc / p);
        acc -= v * p;
        out += String.fromCharCode(HAN_BASE + v);
      }
    }
    if (nbits > 0) out += String.fromCharCode(HAN_BASE + acc * Math.pow(2, 13 - nbits));
    return out;
  }

  function fromHangul(text) {
    var s = text.replace(/\s+/g, '');
    if (!s.length) throw new Error('빈 글자열입니다.');
    var mark = s.charCodeAt(0) - HAN_BASE;
    if (mark < HAN_MARK || mark > HAN_MARK + 12) throw new Error('한글 암호문이 아닙니다.');
    var r = mark - HAN_MARK, cnt = s.length - 1, n = -1;
    for (var cand = Math.max(0, Math.floor(13 * (cnt - 1) / 8));
         cand <= Math.floor(13 * cnt / 8); cand++) {
      if (Math.ceil(8 * cand / 13) === cnt && cand % 13 === r) { n = cand; break; }
    }
    if (n < 0) throw new Error('한글 암호문의 길이가 맞지 않습니다.');

    var out = new Uint8Array(n), o = 0, acc = 0, nbits = 0;
    for (var i = 1; i < s.length; i++) {
      var v = s.charCodeAt(i) - HAN_BASE;
      if (v < 0 || v >= HAN_DATA)
        throw new Error('한글 암호문이 아닌 글자가 있습니다: ' + JSON.stringify(s[i]));
      acc = acc * 8192 + v;
      nbits += 13;
      while (nbits >= 8 && o < n) {
        nbits -= 8;
        var p = Math.pow(2, nbits);
        var b = Math.floor(acc / p);
        acc -= b * p;
        out[o++] = b;
      }
    }
    if (o !== n) throw new Error('한글 암호문 복원에 실패했습니다.');
    return out;
  }

  function isHangulToken(text) {
    var s = text.replace(/\s+/g, '');
    if (!s.length) return false;
    var m = s.charCodeAt(0) - HAN_BASE;
    return m >= HAN_MARK && m <= HAN_MARK + 12;
  }

  // 한글이든 base85든 알아서 읽는다
  function decodeToken(text) {
    return isHangulToken(text) ? fromHangul(text) : fromToken(text);
  }

  return {
    encrypt: encrypt,
    decrypt: decrypt,
    toToken: toToken,
    fromToken: fromToken,
    toHangul: toHangul,
    fromHangul: fromHangul,
    isHangulToken: isHangulToken,
    decodeToken: decodeToken,
    cmCompress: cmCompress,
    cmDecompress: cmDecompress,
    chacha20: chacha20,
    deriveKeys: deriveKeys,
    corpusFingerprint: corpusFingerprint,
    CORPUS: CORPUS,
    CFG_V1: CFG_V1,
    CFG_V2: CFG_V2,
    PBKDF2_ITERS: PBKDF2_ITERS,
    _prime: function (cfg) { return newPrimed(cfg); }
  };
});
