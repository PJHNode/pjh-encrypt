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
  var CORPUS = "\uc774 \uadf8 \uc800 \uac83 \uc218 \ub4f1 \ub4e4 \ubc0f \uccab \ud55c \ub450 \uc138 \ub124 \ub54c \uacf3 \ub9d0 \uc77c \ub144 \uc6d4 \uc77c \uc2dc \ubd84 \ucd08 \uc911 \ud6c4 \uc804 \uc548 \ubc16 \uc704 \uc544\ub798 \uc55e \ub4a4 \uc606 \uc18d \uc0ac\uc774 \ub3d9\uc548 \ub300\ub85c \ub9cc\ud07c \ucc98\ub7fc \ubcf4\ub2e4 \ubd80\ud130 \uae4c\uc9c0 \uc5d0\uac8c \uc5d0\uc11c \uc73c\ub85c \ub85c\uc11c \ub85c\uc368 \uc640 \uacfc \ud558\uace0 \uc774\ub098 \uac70\ub098 \uc9c0\ub9cc \ub294\ub370 \ub2c8\uae4c \uc5b4\uc11c \uc544\uc11c \uba74\uc11c \ub824\uace0 \ub3c4\ub85d \uac8c\ub054 \ub4e0\uc9c0 \ub77c\ub3c4 \uc870\ucc28 \ub9c8\uc800 \ubfd0 \ub530\ub984 \ub54c\ubb38 \ub355\ubd84 \ud0d3 \uacbd\uc6b0 \uc815\ub3c4 \ubb34\ub835 \uc988\uc74c\n\ud558\ub2e4 \ub418\ub2e4 \uc788\ub2e4 \uc5c6\ub2e4 \uac19\ub2e4 \ub2e4\ub974\ub2e4 \ud06c\ub2e4 \uc791\ub2e4 \ub9ce\ub2e4 \uc801\ub2e4 \uc88b\ub2e4 \ub098\uc058\ub2e4 \uc0c8\ub86d\ub2e4 \uc624\ub798\ub418\ub2e4 \uc27d\ub2e4 \uc5b4\ub835\ub2e4 \ube60\ub974\ub2e4 \ub290\ub9ac\ub2e4 \ub192\ub2e4 \ub0ae\ub2e4 \uae38\ub2e4 \uc9e7\ub2e4 \ub113\ub2e4 \uc881\ub2e4 \uae4a\ub2e4 \uc595\ub2e4 \ubc1d\ub2e4 \uc5b4\ub461\ub2e4 \ub530\ub73b\ud558\ub2e4 \ucc28\uac11\ub2e4 \uc870\uc6a9\ud558\ub2e4 \uc2dc\ub044\ub7fd\ub2e4 \uac00\ubccd\ub2e4 \ubb34\uac81\ub2e4 \uac15\ud558\ub2e4 \uc57d\ud558\ub2e4 \uc911\uc694\ud558\ub2e4 \ud544\uc694\ud558\ub2e4 \uac00\ub2a5\ud558\ub2e4 \ubd88\uac00\ub2a5\ud558\ub2e4 \ubd84\uba85\ud558\ub2e4 \ud655\uc2e4\ud558\ub2e4 \uc790\uc5f0\uc2a4\ub7fd\ub2e4 \uc801\uc808\ud558\ub2e4 \ucda9\ubd84\ud558\ub2e4 \ubd80\uc871\ud558\ub2e4\n\ud569\ub2c8\ub2e4 \uc2b5\ub2c8\ub2e4 \uc785\ub2c8\ub2e4 \ud588\uc2b5\ub2c8\ub2e4 \ub429\ub2c8\ub2e4 \uc788\uc2b5\ub2c8\ub2e4 \uc5c6\uc2b5\ub2c8\ub2e4 \uac11\ub2c8\ub2e4 \uc635\ub2c8\ub2e4 \ubd05\ub2c8\ub2e4 \uac19\uc2b5\ub2c8\ub2e4 \ub4dc\ub9bd\ub2c8\ub2e4 \uc8fc\uc2ed\uc2dc\uc624 \ubc14\ub78d\ub2c8\ub2e4 \ud558\uc600\ub2e4 \uc774\uc5c8\ub2e4 \ud558\ub294 \ub418\ub294 \uc788\ub294 \uc5c6\ub294 \ud558\uc9c0\ub9cc \uadf8\ub7ec\ub098 \uadf8\ub798\uc11c \ub530\ub77c\uc11c \uadf8\ub9ac\uace0 \ub610\ud55c \uc989 \ub2e4\ub9cc \uc624\ud788\ub824 \ubb3c\ub860 \uc0ac\uc2e4 \uacb0\uad6d \ub9c8\uce68\ub0b4 \ube44\ub85c\uc18c \uc774\ubbf8 \uc544\uc9c1 \ubc8c\uc368 \uace7 \ub298 \ud56d\uc0c1 \uc790\uc8fc \uac00\ub054 \ub54c\ub54c\ub85c \uac70\uc758 \uc804\ud600 \uacb0\ucf54 \ubc18\ub4dc\uc2dc \uc544\ub9c8 \uc5b4\uca4c\uba74 \ub9cc\uc57d \ube44\ub85d \uc124\ub839\n\ub098\ub294 \ub108\ub294 \uc6b0\ub9ac\ub294 \uadf8\ub294 \uadf8\ub140\ub294 \uc0ac\ub78c\ub4e4\uc740 \uc544\uc774\ub4e4\uc740 \ud559\uc0dd\ub4e4\uc740 \uc120\uc0dd\ub2d8\uc740 \ubd80\ubaa8\ub2d8\uc740 \uce5c\uad6c\ub4e4\uacfc \ub3d9\uc0dd\uacfc \ud615\uacfc \ub204\ub098\uc640 \uc5b8\ub2c8\uc640 \uc624\ube60\uc640 \uac00\uc871\uacfc \uc774\uc6c3\uacfc \uc0ac\ud68c\ub294 \uad6d\uac00\ub294 \uc815\ubd80\ub294 \uae30\uc5c5\uc740 \uc2dc\uc7a5\uc740 \ud559\uad50\ub294 \uad50\uc2e4\uc740 \ub3c4\uc11c\uad00\uc5d0\uc11c \uc6b4\ub3d9\uc7a5\uc5d0\uc11c \uc9d1\uc5d0\uc11c \ubc29\uc5d0\uc11c \uac70\ub9ac\uc5d0\uc11c \uacf5\uc6d0\uc5d0\uc11c \uce74\ud398\uc5d0\uc11c \ud68c\uc0ac\uc5d0\uc11c \ubcd1\uc6d0\uc5d0\uc11c \uc5ed\uc5d0\uc11c\n\uc624\ub298 \uc544\uce68\uc5d0 \uc77c\uc5b4\ub098\uc11c \ucc3d\ubb38\uc744 \uc5f4\uc5c8\ub354\ub2c8 \ubc14\ub78c\uc774 \uc120\uc120\ud558\uac8c \ub4e4\uc5b4\uc654\ub2e4. \uc5b4\uc81c\ubcf4\ub2e4 \ud655\uc2e4\ud788 \uacf5\uae30\uac00 \ucc28\uac00\uc6cc\uc9c4 \ub290\ub08c\uc774\uc5c8\ub2e4. \uac04\ub2e8\ud558\uac8c \ubc25\uc744 \uba39\uace0 \uac00\ubc29\uc744 \ucc59\uaca8\uc11c \uc9d1\uc744 \ub098\uc130\ub2e4. \ubc84\uc2a4 \uc815\ub958\uc7a5\uae4c\uc9c0 \uac78\uc5b4\uac00\ub294 \ub3d9\uc548 \ub099\uc5fd\uc774 \ubc1c\ubc11\uc5d0\uc11c \ubc14\uc2a4\ub77d\uac70\ub838\ub2e4. \uc2dc\uac04\uc774 \ucc38 \ube60\ub974\uac8c \uc9c0\ub098\uac04\ub2e4\ub294 \uc0dd\uac01\uc774 \ub4e4\uc5c8\ub2e4. \uc694\uc998\uc740 \ud558\ub8e8\ud558\ub8e8\uac00 \ube44\uc2b7\ud558\uac8c \ud758\ub7ec\uac00\ub294 \uac83 \uac19\uc73c\uba74\uc11c\ub3c4, \ub3cc\uc544\ubcf4\uba74 \uc870\uae08\uc529 \ub2ec\ub77c\uc838 \uc788\ub2e4.\n\ud559\uad50\uc5d0 \ub3c4\ucc29\ud574\uc11c \uccab \uc218\uc5c5\uc744 \ub4e4\uc5c8\ub2e4. \uc120\uc0dd\ub2d8\uaed8\uc11c \uc9c0\ub09c \uc2dc\uac04\uc5d0 \ubc30\uc6b4 \ub0b4\uc6a9\uc744 \ub2e4\uc2dc \uc815\ub9ac\ud574 \uc8fc\uc168\ub294\ub370, \uadf8\uc81c\uc57c \uc774\ud574\uac00 \ub418\ub294 \ubd80\ubd84\uc774 \uc788\uc5c8\ub2e4. \uc5ed\uc2dc \ud55c \ubc88\uc5d0 \uc54c\uc544\ub4e3\uae30\ub294 \uc5b4\ub835\uace0, \uc5ec\ub7ec \ubc88 \ubc18\ubcf5\ud574\uc11c \ubd10\uc57c \ud55c\ub2e4\ub294 \uac78 \ub2e4\uc2dc \ub290\uaf08\ub2e4. \uc26c\ub294 \uc2dc\uac04\uc5d0\ub294 \uce5c\uad6c\ub4e4\uacfc \uc774\uc57c\uae30\ub97c \ub098\ub204\uc5c8\ub2e4. \ubcc4\uac83 \uc544\ub2cc \ub300\ud654\uc600\uc9c0\ub9cc \uc6c3\uc73c\uba74\uc11c \uc2dc\uac04\uc744 \ubcf4\ub0b4\ub2c8 \uae30\ubd84\uc774 \ub098\uc544\uc84c\ub2e4.\n\uc218\ud559 \ubb38\uc81c\ub97c \ud480 \ub54c\ub294 \uba3c\uc800 \uc870\uac74\uc744 \uc815\ub9ac\ud558\ub294 \uac83\uc774 \uc911\uc694\ud558\ub2e4. \uc8fc\uc5b4\uc9c4 \uc2dd\uc744 \uadf8\ub300\ub85c \uacc4\uc0b0\ud558\ub824\uace0 \ud558\uba74 \ubcf5\uc7a1\ud574\uc9c0\ub294 \uacbd\uc6b0\uac00 \ub9ce\ub2e4. \ud568\uc218\uc758 \uadf8\ub798\ud504\ub97c \uadf8\ub824\ubcf4\uac70\ub098, \ub300\uce6d\uc131\uc744 \uc774\uc6a9\ud558\uac70\ub098, \ubcc0\uc218\ub97c \uce58\ud658\ud558\uba74 \ud6e8\uc52c \uac04\ub2e8\ud574\uc9c4\ub2e4. \uc774\ucc28\ud568\uc218\uc758 \ucd5c\ub313\uac12\uacfc \ucd5c\uc19f\uac12\uc740 \uaf2d\uc9d3\uc810\uc744 \uad6c\ud558\uba74 \ubc14\ub85c \uc54c \uc218 \uc788\uace0, \uc0bc\ucc28\ud568\uc218\ub294 \ubbf8\ubd84\ud574\uc11c \uadf9\uac12\uc744 \ucc3e\uc544\uc57c \ud55c\ub2e4. \ubd80\ub4f1\uc2dd\uc744 \ub2e4\ub8f0 \ub54c\ub294 \uc591\ubcc0\uc5d0 \uc74c\uc218\ub97c \uacf1\ud558\uba74 \ubd80\ub4f1\ud638\uc758 \ubc29\ud5a5\uc774 \ubc14\ub010\ub2e4\ub294 \uc810\uc744 \uc78a\uc9c0 \ub9d0\uc544\uc57c \ud55c\ub2e4.\n\uc815\ub2f5\uc744 \ub9de\ud788\ub294 \uac83\ubcf4\ub2e4 \uc65c \uadf8\ub807\uac8c \ub418\ub294\uc9c0\ub97c \uc124\uba85\ud560 \uc218 \uc788\ub294 \uac83\uc774 \ub354 \uc911\uc694\ud558\ub2e4\uace0 \uc0dd\uac01\ud55c\ub2e4. \ud480\uc774 \uacfc\uc815\uc744 \ub2e4\uc2dc \uc368\ubcf4\uba74 \uc790\uc2e0\uc774 \uc5b4\ub514\uc5d0\uc11c \ud5f7\uac08\ub838\ub294\uc9c0 \uc54c\uac8c \ub41c\ub2e4. \ubb38\uc81c\ub97c \ub9ce\uc774 \ud478\ub294 \uac83\ub3c4 \ud544\uc694\ud558\uc9c0\ub9cc, \ud2c0\ub9b0 \ubb38\uc81c\ub97c \uc81c\ub300\ub85c \ubd84\uc11d\ud558\ub294 \ud3b8\uc774 \ud6e8\uc52c \ud6a8\uc728\uc801\uc774\ub2e4. \uac1c\ub150\uc744 \uc815\ud655\ud788 \uc54c\uace0 \uc788\uc73c\uba74 \ucc98\uc74c \ubcf4\ub294 \uc720\ud615\uc774 \ub098\uc640\ub3c4 \uc811\uadfc\ud560 \ubc29\ubc95\uc744 \ucc3e\uc744 \uc218 \uc788\ub2e4.\n\uc9d1\ud569\uacfc \uba85\uc81c, \ud568\uc218\uc640 \uc218\uc5f4, \ubbf8\ubd84\uacfc \uc801\ubd84, \ud655\ub960\uacfc \ud1b5\uacc4\ub294 \uc11c\ub85c \uc5f0\uacb0\ub418\uc5b4 \uc788\ub2e4. \ud558\ub098\uc758 \ub2e8\uc6d0\uc744 \uacf5\ubd80\ud560 \ub54c\ub3c4 \ub2e4\ub978 \ub2e8\uc6d0\uacfc \uc5b4\ub5a4 \uad00\uacc4\uac00 \uc788\ub294\uc9c0 \uc0dd\uac01\ud558\uba74 \uc774\ud574\uac00 \uae4a\uc5b4\uc9c4\ub2e4. \uc608\ub97c \ub4e4\uc5b4 \uc218\uc5f4\uc758 \uadf9\ud55c\uc740 \ud568\uc218\uc758 \uadf9\ud55c\uacfc \uac19\uc740 \uc544\uc774\ub514\uc5b4\ub97c \uacf5\uc720\ud558\uace0, \uc801\ubd84\uc740 \ub113\uc774\uc640 \ubd80\ud53c\ub97c \uacc4\uc0b0\ud558\ub294 \ub3c4\uad6c\ub85c \uc4f0\uc778\ub2e4.\n\uacfc\ud559 \uc2dc\uac04\uc5d0\ub294 \uc2e4\ud5d8\uc744 \ud588\ub2e4. \uac00\uc124\uc744 \uc138\uc6b0\uace0, \ubcc0\uc778\uc744 \ud1b5\uc81c\ud558\uace0, \uacb0\uacfc\ub97c \uae30\ub85d\ud558\ub294 \uacfc\uc815\uc774 \uc0dd\uac01\ubcf4\ub2e4 \uae4c\ub2e4\ub85c\uc6e0\ub2e4. \uc608\uc0c1\uacfc \ub2e4\ub978 \uac12\uc774 \ub098\uc654\uc744 \ub54c \ubb34\uc5c7\uc774 \uc798\ubabb\ub418\uc5c8\ub294\uc9c0 \ucc3e\ub294 \uac83\uc774 \uc9c4\uc9dc \uacf5\ubd80\ub77c\ub294 \ub9d0\uc774 \uc774\ud574\uac00 \ub410\ub2e4. \uc628\ub3c4\uc640 \uc555\ub825, \ubd80\ud53c\uc758 \uad00\uacc4, \ud798\uacfc \uc6b4\ub3d9\uc758 \ubc95\uce59, \uc5d0\ub108\uc9c0\uc758 \ubcf4\uc874, \uc138\ud3ec\uc640 \uc720\uc804, \ubb3c\uc9c8\uc758 \uc0c1\ud0dc \ubcc0\ud654 \uac19\uc740 \uac1c\ub150\ub4e4\uc774 \ud558\ub098\uc529 \uc790\ub9ac\ub97c \uc7a1\uc544\uac00\uace0 \uc788\ub2e4.\n\uc0ac\ud68c \ubb38\uc81c\uc5d0 \uad00\ud55c \ucc45\uc744 \uc77d\uc5c8\ub2e4. \uc800\uc790\ub294 \uac1c\uc778\uc758 \ub178\ub825\ub9cc\uc73c\ub85c \ud574\uacb0\ud560 \uc218 \uc5c6\ub294 \uad6c\uc870\uc801\uc778 \ubb38\uc81c\ub4e4\uc774 \uc788\ub2e4\uace0 \ub9d0\ud588\ub2e4. \uad50\uc721 \uaca9\ucc28, \uc8fc\uac70 \ubd88\uc548\uc815, \ud658\uacbd \uc624\uc5fc, \uc815\ubcf4 \uaca9\ucc28, \uace0\ub839\ud654, \uccad\ub144 \uc2e4\uc5c5 \uac19\uc740 \uc8fc\uc81c\ub4e4\uc774 \ub2e4\ub904\uc84c\ub2e4. \uc5b4\ub290 \ud558\ub098\ub3c4 \ub2e8\uc21c\ud55c \uc6d0\uc778\uc73c\ub85c \uc124\uba85\ub418\uc9c0 \uc54a\uc558\ub2e4. \uc5ec\ub7ec \uc694\uc778\uc774 \ubcf5\uc7a1\ud558\uac8c \uc5bd\ud600 \uc788\uace0, \ud574\uacb0\ucc45 \uc5ed\uc2dc \uc5ec\ub7ec \ubc29\ud5a5\uc5d0\uc11c \ub3d9\uc2dc\uc5d0 \uc811\uadfc\ud574\uc57c \ud55c\ub2e4\ub294 \uc810\uc774 \uc778\uc0c1\uc801\uc774\uc5c8\ub2e4.\n\ud2b9\ud788 \uae30\uc5b5\uc5d0 \ub0a8\ub294 \uac83\uc740 \ucc45\uc784\uc758 \ubb38\uc81c\uc600\ub2e4. \uc5b4\ub5a4 \uc77c\uc774 \uc798\ubabb\ub418\uc5c8\uc744 \ub54c \ub204\uad6c\uc758 \uc798\ubabb\uc778\uc9c0\ub97c \ub530\uc9c0\ub294 \uac83\ub3c4 \ud544\uc694\ud558\uc9c0\ub9cc, \uadf8\ubcf4\ub2e4 \uba3c\uc800 \uc5b4\ub5a4 \uc870\uac74\uc774 \uadf8\ub7f0 \uacb0\uacfc\ub97c \ub9cc\ub4e4\uc5c8\ub294\uc9c0\ub97c \uc0b4\ud3b4\uc57c \ud55c\ub2e4\ub294 \uc8fc\uc7a5\uc774\uc5c8\ub2e4. \uac1c\uc778\uc744 \ud0d3\ud558\ub294 \ubc29\uc2dd\uc740 \uc27d\uace0 \ube60\ub974\uc9c0\ub9cc, \uac19\uc740 \ubb38\uc81c\uac00 \ubc18\ubcf5\ub418\ub294 \uac83\uc744 \ub9c9\uc9c0\ub294 \ubabb\ud55c\ub2e4.\n\ub514\uc9c0\ud138 \uae30\uc220\uc774 \uc6b0\ub9ac \uc0b6\uc744 \ubc14\uafb8\uace0 \uc788\ub2e4\ub294 \uc774\uc57c\uae30\ub294 \uc774\uc81c \uc0c8\ub86d\uc9c0 \uc54a\ub2e4. \ub2e4\ub9cc \uadf8 \ubcc0\ud654\uac00 \ubaa8\ub450\uc5d0\uac8c \uac19\uc740 \ubc29\uc2dd\uc73c\ub85c \ub2e4\uac00\uc624\uc9c0\ub294 \uc54a\ub294\ub2e4. \uc5b4\ub5a4 \uc0ac\ub78c\uc5d0\uac8c\ub294 \ud3b8\ub9ac\ud568\uc774\uc9c0\ub9cc, \ub2e4\ub978 \uc0ac\ub78c\uc5d0\uac8c\ub294 \uc0c8\ub85c\uc6b4 \uc7a5\ubcbd\uc774 \ub418\uae30\ub3c4 \ud55c\ub2e4. \uae30\uc220\uc744 \uc5b4\ub5bb\uac8c \uc124\uacc4\ud558\uace0 \ub204\uad6c\ub97c \uae30\uc900\uc73c\ub85c \ub9cc\ub4dc\ub294\uc9c0\uac00 \uc911\uc694\ud55c \uc774\uc720\ub2e4.\n\uc778\uacf5\uc9c0\ub2a5\uc5d0 \uad00\ud55c \ub17c\uc758\ub3c4 \ub9c8\ucc2c\uac00\uc9c0\ub2e4. \uae30\uc220 \uc790\uccb4\uc758 \uc131\ub2a5\ub9cc \uc774\uc57c\uae30\ud560 \uac83\uc774 \uc544\ub2c8\ub77c, \uadf8\uac83\uc774 \uc0ac\ud68c\uc5d0\uc11c \uc5b4\ub5a4 \uc5ed\ud560\uc744 \ud558\uac8c \ub418\ub294\uc9c0, \ub204\uac00 \uc774\uc775\uc744 \uc5bb\uace0 \ub204\uac00 \ubd88\uc774\uc775\uc744 \ubc1b\ub294\uc9c0\ub97c \ud568\uaed8 \uc0dd\uac01\ud574\uc57c \ud55c\ub2e4. \ud3b8\ub9ac\ud574\uc9c0\ub294 \ub9cc\ud07c \ub193\uce58\ub294 \uac83\ub3c4 \uc0dd\uae30\uae30 \ub54c\ubb38\uc774\ub2e4.\n\uc800\ub141\uc5d0\ub294 \uac00\uc871\ub4e4\uacfc \ud568\uaed8 \ubc25\uc744 \uba39\uc5c8\ub2e4. \uc624\ub79c\ub9cc\uc5d0 \ub2e4 \uac19\uc774 \ubaa8\uc5ec\uc11c \uc774\ub7f0\uc800\ub7f0 \uc774\uc57c\uae30\ub97c \ub098\ub204\uc5c8\ub2e4. \ubd80\ubaa8\ub2d8\uc740 \uc608\uc804 \uc774\uc57c\uae30\ub97c \ud558\uc168\uace0, \ub3d9\uc0dd\uc740 \ud559\uad50\uc5d0\uc11c \uc788\uc5c8\ub358 \uc77c\uc744 \uc2e0\ub098\uac8c \ub9d0\ud588\ub2e4. \ud2b9\ubcc4\ud55c \ub0b4\uc6a9\uc740 \uc544\ub2c8\uc5c8\uc9c0\ub9cc \uadf8\ub7f0 \uc2dc\uac04\uc774 \ud3b8\uc548\ud558\uac8c \ub290\uaef4\uc84c\ub2e4.\n\ubc24\uc5d0\ub294 \uc870\uc6a9\ud788 \uc74c\uc545\uc744 \ub4e4\uc73c\uba74\uc11c \ud558\ub8e8\ub97c \uc815\ub9ac\ud588\ub2e4. \uc798\ud55c \uc77c\ub3c4 \uc788\uace0 \uc544\uc26c\uc6b4 \uc77c\ub3c4 \uc788\uc5c8\ub2e4. \ub0b4\uc77c\uc740 \uc870\uae08 \ub354 \uc77c\ucc0d \uc77c\uc5b4\ub098\uc11c \uc5ec\uc720 \uc788\uac8c \uc900\ube44\ud574\uc57c\uaca0\ub2e4\uace0 \uc0dd\uac01\ud588\ub2e4. \uacc4\ud68d\uc744 \uc138\uc6b0\ub294 \uac83\uc740 \uc5b4\ub835\uc9c0 \uc54a\uc740\ub370 \uc9c0\ud0a4\ub294 \uac83\uc774 \ub298 \ubb38\uc81c\ub2e4. \uadf8\ub798\ub3c4 \uc870\uae08\uc529 \ub098\uc544\uc9c0\uace0 \uc788\ub2e4\uace0 \ubbff\ub294\ub2e4.\n\uc8fc\ub9d0\uc5d0\ub294 \uce5c\uad6c\uc640 \ub9cc\ub098\uae30\ub85c \ud588\ub2e4. \uc624\ub79c\ub9cc\uc5d0 \ubc16\uc5d0\uc11c \uac77\uace0 \uc774\uc57c\uae30\ub97c \ub098\ub20c \uc0dd\uac01\uc744 \ud558\ub2c8 \uae30\ub300\uac00 \ub41c\ub2e4. \ub0a0\uc528\uac00 \uc88b\uc73c\uba74 \uacf5\uc6d0\uc5d0 \uac00\uc11c \uc2dc\uac04\uc744 \ubcf4\ub0b4\ub3c4 \uc88b\uc744 \uac83 \uac19\ub2e4. \uc694\uc998\uc740 \ubc14\uc058\ub2e4\ub294 \uc774\uc720\ub85c \uc0ac\ub78c\ub4e4\uc744 \uc798 \ub9cc\ub098\uc9c0 \ubabb\ud588\ub294\ub370, \uc774\ub7f0 \uc2dc\uac04\uc774 \uacb0\uad6d \uac00\uc7a5 \uc624\ub798 \uae30\uc5b5\uc5d0 \ub0a8\ub294\ub2e4.\n\uc548\ub155\ud558\uc138\uc694. \ubb38\uc758\ub4dc\ub9b4 \ub0b4\uc6a9\uc774 \uc788\uc5b4 \uc5f0\ub77d\ub4dc\ub9bd\ub2c8\ub2e4. \ub9d0\uc500\ud574 \uc8fc\uc2e0 \uc790\ub8cc\ub97c \ud655\uc778\ud558\uc600\uc73c\uba70, \uba87 \uac00\uc9c0 \ucd94\uac00\ub85c \uc5ec\ucb59\uace0 \uc2f6\uc740 \uc810\uc774 \uc788\uc2b5\ub2c8\ub2e4. \uac00\ub2a5\ud558\uc2dc\ub2e4\uba74 \uc774\ubc88 \uc8fc \uc911\uc73c\ub85c \ub2f5\ubcc0 \uc8fc\uc2dc\uba74 \uac10\uc0ac\ud558\uaca0\uc2b5\ub2c8\ub2e4. \ubc14\uc058\uc2e0 \uc911\uc5d0 \uc2dc\uac04 \ub0b4\uc8fc\uc154\uc11c \uac10\uc0ac\ud569\ub2c8\ub2e4. \uc88b\uc740 \ud558\ub8e8 \ubcf4\ub0b4\uc2dc\uae30 \ubc14\ub78d\ub2c8\ub2e4.\n\ud68c\uc758\ub294 \ub2e4\uc74c \uc8fc \ud654\uc694\uc77c \uc624\ud6c4 \ub450 \uc2dc\uc5d0 \uc9c4\ud589\ub420 \uc608\uc815\uc785\ub2c8\ub2e4. \ucc38\uc11d\uc774 \uc5b4\ub824\uc6b0\uc2e0 \uacbd\uc6b0 \ubbf8\ub9ac \uc54c\ub824\uc8fc\uc2dc\uae30 \ubc14\ub78d\ub2c8\ub2e4. \uc790\ub8cc\ub294 \ud68c\uc758 \uc804\ub0a0\uae4c\uc9c0 \uacf5\uc720\ud574 \ub4dc\ub9ac\uaca0\uc2b5\ub2c8\ub2e4. \ub17c\uc758\ud560 \uc548\uac74\uc740 \ud06c\uac8c \uc138 \uac00\uc9c0\uc785\ub2c8\ub2e4. \uccab\uc9f8, \uc77c\uc815 \uc870\uc815\uc5d0 \uad00\ud55c \uc0ac\ud56d\uc785\ub2c8\ub2e4. \ub458\uc9f8, \uc608\uc0b0 \uc0ac\uc6a9 \uacc4\ud68d\uc785\ub2c8\ub2e4. \uc14b\uc9f8, \ud5a5\ud6c4 \uc9c4\ud589 \ubc29\ud5a5\uc5d0 \ub300\ud55c \uc758\uacac \uc218\ub834\uc785\ub2c8\ub2e4.\n\uc815\ubd80\ub294 \uc5b4\uc81c \uad00\ub828 \ub300\ucc45\uc744 \ubc1c\ud45c\ud588\ub2e4. \uc774\ubc88 \uc870\uce58\ub294 \ucd5c\uadfc \uc81c\uae30\ub41c \ubb38\uc81c\ub4e4\uc5d0 \ub300\uc751\ud558\uae30 \uc704\ud55c \uac83\uc73c\ub85c, \ub2e4\uc74c \ub2ec\ubd80\ud130 \uc21c\ucc28\uc801\uc73c\ub85c \uc2dc\ud589\ub41c\ub2e4. \uc804\ubb38\uac00\ub4e4\uc740 \uc2e4\ud6a8\uc131\uc5d0 \ub300\ud574 \uc5c7\uac08\ub9b0 \ud3c9\uac00\ub97c \ub0b4\ub193\uace0 \uc788\ub2e4. \uc77c\ubd80\ub294 \uae0d\uc815\uc801\uc778 \ubcc0\ud654\ub97c \uae30\ub300\ud560 \uc218 \uc788\ub2e4\uace0 \ubcf8 \ubc18\uba74, \ub2e4\ub978 \ucabd\uc5d0\uc11c\ub294 \uadfc\ubcf8\uc801\uc778 \ud574\uacb0\uc5d0\ub294 \ud55c\uacc4\uac00 \uc788\ub2e4\uace0 \uc9c0\uc801\ud588\ub2e4. \uc2dc\ubbfc\ub4e4\uc758 \ubc18\uc751\ub3c4 \ub2e4\uc591\ud558\uac8c \ub098\ud0c0\ub0ac\ub2e4.\n\uc9c0\ub09c\ud574 \uac19\uc740 \uae30\uac04\uacfc \ube44\uad50\ud558\uba74 \uc57d \uc2ed \ud37c\uc13c\ud2b8 \uc99d\uac00\ud55c \uc218\uce58\ub2e4. \uc870\uc0ac \uacb0\uacfc\uc5d0 \ub530\ub974\uba74 \uc751\ub2f5\uc790\uc758 \uc808\ubc18 \uc774\uc0c1\uc774 \ud544\uc694\uc131\uc5d0 \uacf5\uac10\ud55c\ub2e4\uace0 \ub2f5\ud588\ub2e4. \ub2e4\ub9cc \uad6c\uccb4\uc801\uc778 \ubc29\ubc95\uc5d0 \ub300\ud574\uc11c\ub294 \uc758\uacac\uc774 \ub098\ub258\uc5c8\ub2e4. \uc5f0\uad6c\uc9c4\uc740 \uc55e\uc73c\ub85c \ub354 \ub9ce\uc740 \uc790\ub8cc\ub97c \uc218\uc9d1\ud574 \ubd84\uc11d\ud560 \uacc4\ud68d\uc774\ub77c\uace0 \ubc1d\ud614\ub2e4.\n\uadf8\ub798 \uc54c\uc558\uc5b4 \uadf8\ub7fc \uc5b8\uc81c \ubcfc\uae4c \ub098\ub294 \uc544\ubb34 \ub54c\ub098 \uad1c\ucc2e\uc544 \ub108 \ud3b8\ud55c \uc2dc\uac04\uc73c\ub85c \ub9d0\ud574\uc918 \uc624\ub298\uc740 \uc880 \ud798\ub4e4 \uac83 \uac19\uace0 \ub0b4\uc77c\uc740 \uc5b4\ub54c \uc751 \uc88b\uc544 \uadf8\ub54c \ubcf4\uc790 \uace0\ub9c8\uc6cc \ubbf8\uc548\ud574 \uad1c\ucc2e\uc544 \uc815\ub9d0 \uc9c4\uc9dc \ub300\ubc15 \uc544 \ub9de\ub2e4 \uadf8\uac70 \uc5b4\ub5bb\uac8c \ub410\uc5b4 \uc798 \ub410\uc5b4 \ub2e4\ud589\uc774\ub2e4 \uc218\uace0\ud588\uc5b4 \uc870\uc2ec\ud788 \uac00 \uc798 \uc790 \ub0b4\uc77c \ubd10\n\ubb34\uc5c7\uc744 \uc5b4\ub5bb\uac8c \uc65c \uc5b8\uc81c \uc5b4\ub514\uc11c \ub204\uac00 \uc5bc\ub9c8\ub098 \uc5b4\ub5a4 \uadf8\ub7f0 \uc774\ub7f0 \uc800\ub7f0 \uc774\ub807\uac8c \uadf8\ub807\uac8c \uc800\ub807\uac8c \uc544\ub9c8\ub3c4 \ud639\uc2dc \uc5ed\uc2dc \ud2b9\ud788 \uc608\ub97c \ub4e4\uc5b4 \ub2e4\uc2dc \ub9d0\ud574 \ud55c\ud3b8 \ubc18\uba74\uc5d0 \uadf8\ub7fc\uc5d0\ub3c4 \ubd88\uad6c\ud558\uace0 \uc774\uc5d0 \ub530\ub77c \uadf8 \uacb0\uacfc \ubb34\uc5c7\ubcf4\ub2e4 \uc6b0\uc120 \ub9c8\uc9c0\ub9c9\uc73c\ub85c \uc815\ub9ac\ud558\uba74 \uc694\uc57d\ud558\uc790\uba74 \uacb0\ub860\uc801\uc73c\ub85c\n\uc0dd\uac01\ud55c\ub2e4 \ub290\uaf08\ub2e4 \uc54c\uc558\ub2e4 \ubab0\ub790\ub2e4 \ubc30\uc6e0\ub2e4 \uae68\ub2ec\uc558\ub2e4 \uae30\uc5b5\ud55c\ub2e4 \uc78a\uc5c8\ub2e4 \ubc14\ub780\ub2e4 \uc6d0\ud55c\ub2e4 \uc2eb\ub2e4 \uc88b\uc544\ud55c\ub2e4 \uad81\uae08\ud558\ub2e4 \uac71\uc815\ub41c\ub2e4 \uc548\uc2ec\ub41c\ub2e4 \uae30\ub300\ub41c\ub2e4 \uc544\uc27d\ub2e4 \ubfcc\ub4ef\ud558\ub2e4 \ub2f5\ub2f5\ud558\ub2e4 \ud3b8\uc548\ud558\ub2e4 \ubd88\uc548\ud558\ub2e4 \uc990\uac81\ub2e4 \uc9c0\ub8e8\ud558\ub2e4 \ub180\ub78d\ub2e4 \ub2f9\ud669\uc2a4\ub7fd\ub2e4 \uace0\ub9d9\ub2e4 \ubbf8\uc548\ud558\ub2e4\n\uc2dc\uc791\ud558\ub2e4 \ub05d\ub0b4\ub2e4 \uacc4\uc18d\ud558\ub2e4 \uba48\ucd94\ub2e4 \ubc14\uafb8\ub2e4 \uace0\uce58\ub2e4 \ub9cc\ub4e4\ub2e4 \ubd80\uc218\ub2e4 \ub298\ub9ac\ub2e4 \uc904\uc774\ub2e4 \ubaa8\uc73c\ub2e4 \ub098\ub204\ub2e4 \ucc3e\ub2e4 \uc783\ub2e4 \uc5bb\ub2e4 \uc8fc\ub2e4 \ubc1b\ub2e4 \ubcf4\ub0b4\ub2e4 \uac00\uc838\uc624\ub2e4 \uc62c\ub9ac\ub2e4 \ub0b4\ub9ac\ub2e4 \uc5f4\ub2e4 \ub2eb\ub2e4 \ub123\ub2e4 \ube7c\ub2e4 \uc313\ub2e4 \uc62e\uae30\ub2e4 \uc815\ub9ac\ud558\ub2e4 \uc900\ube44\ud558\ub2e4 \ud655\uc778\ud558\ub2e4 \uacb0\uc815\ud558\ub2e4 \uc120\ud0dd\ud558\ub2e4 \ud3ec\uae30\ud558\ub2e4 \ub3c4\uc804\ud558\ub2e4\n\ubb38\uc81c \ud574\uacb0 \ubc29\ubc95 \uacfc\uc815 \uacb0\uacfc \uc6d0\uc778 \uc774\uc720 \ubaa9\uc801 \ubaa9\ud45c \uacc4\ud68d \ubc29\ud5a5 \uae30\uc900 \uc870\uac74 \uc0c1\ud669 \ud658\uacbd \uad00\uacc4 \uc601\ud5a5 \ubcc0\ud654 \ubc1c\uc804 \uc131\uc7a5 \ucc28\uc774 \uacf5\ud1b5\uc810 \ud2b9\uc9d5 \uc7a5\uc810 \ub2e8\uc810 \ud55c\uacc4 \uac00\ub2a5\uc131 \ud544\uc694\uc131 \uc911\uc694\uc131 \uc758\ubbf8 \uac00\uce58 \uae30\uc900 \uc5ed\ud560 \ucc45\uc784 \uad8c\ub9ac \uc758\ubb34 \uaddc\uce59 \uc81c\ub3c4 \uc815\ucc45 \uc0ac\ud68c \ubb38\ud654 \uc5ed\uc0ac \uacbd\uc81c \uc815\uce58 \uad50\uc721 \uae30\uc220 \uacfc\ud559 \uc608\uc220 \uc5b8\uc5b4 \uc790\uc5f0 \uc778\uac04\n\uc9c0\uae08 \uc5b4\ub514\uc57c \uac70\uc758 \ub2e4 \uc654\uc5b4 \uc624\ubd84\uc774\uba74 \ub3c4\ucc29\ud574 \uba3c\uc800 \ub4e4\uc5b4\uac00 \uc788\uc5b4 \uc790\ub9ac \uc7a1\uc544\ub1a8\uc5b4 \uc785\uad6c\uc5d0\uc11c \uae30\ub2e4\ub9b4\uac8c \ub2a6\uc5b4\uc11c \ubbf8\uc548 \ucc28\uac00 \ub108\ubb34 \ub9c9\ud614\uc5b4 \ub2e4\uc74c\uc5d0\ub294 \uc9c0\ud558\ucca0 \ud0c0\uc57c\uaca0\ub2e4 \uc624\ub298 \uace0\ub9c8\uc6e0\uc5b4 \uc870\uc2ec\ud788 \ub4e4\uc5b4\uac00 \ub3c4\ucc29\ud558\uba74 \uc5f0\ub77d \uc918 \uc798 \ub4e4\uc5b4\uac14\uc5b4 \uc751 \ubc29\uae08 \ub3c4\ucc29 \ud479 \uc26c\uc5b4 \ub0b4\uc77c \ubd10\n\uc774\ubc88 \uc8fc\ub9d0\uc5d0 \uc2dc\uac04 \uad1c\ucc2e\uc544? \ud1a0\uc694\uc77c \uc624\ud6c4\uba74 \uc88b\uc744 \uac83 \uac19\uc740\ub370 \uc77c\uc694\uc77c\ub3c4 \uc0c1\uad00\uc5c6\uc5b4 \ud3b8\ud55c \uc2dc\uac04 \ub9d0\ud574\uc918 \ub098\ub294 \uc5b8\uc81c\ub4e0 \uad1c\ucc2e\uc73c\ub2c8\uae4c \uc815\ud574\uc9c0\uba74 \uc54c\ub824\uc918 \uc7a5\uc18c\ub294 \uadf8\ub54c \uc815\ud558\uc790 \uc911\uac04\ucbe4\uc5d0\uc11c \ubcf4\ub294 \uac8c \ub0ab\uaca0\ub2e4 \uac70\uae30 \uc8fc\ucc28 \ub418\ub098 \ubaa8\ub974\uaca0\ub124 \ub300\uc911\uad50\ud1b5\uc774 \ud3b8\ud560 \uac83 \uac19\uc544\n\ubc25\uc740 \uba39\uc5c8\uc5b4? \uc544\uc9c1 \uc548 \uba39\uc5c8\uc73c\uba74 \uac19\uc774 \uba39\uc790 \ubb50 \uba39\uace0 \uc2f6\uc5b4 \uc544\ubb34\uac70\ub098 \uc0c1\uad00\uc5c6\uc5b4 \ub124\uac00 \uc815\ud574 \uc800\ubc88\uc5d0 \uac14\ub358 \ub370 \uc5b4\ub54c \uac70\uae30 \uad1c\ucc2e\uc558\uc796\uc544 \uadf8\ub7fc \uac70\uae30\ub85c \ud558\uc790 \uba87 \uc2dc\uc5d0 \ubcfc\uae4c \uc77c\uacf1 \uc2dc\ucbe4 \uc5b4\ub54c \uc88b\uc544 \uadf8\ub54c \ubcf4\uc790\n\uc5b4\uba38\ub2c8 \uc0dd\uc2e0 \uc120\ubb3c \ubb50\uac00 \uc88b\uc744\uae4c \uace0\ubbfc\uc774\uc57c \uc791\ub144\uc5d0\ub294 \uc2a4\uce74\ud504 \ub4dc\ub838\ub294\ub370 \uc62c\ud574\ub294 \ub2e4\ub978 \uac78\ub85c \ud558\uace0 \uc2f6\uc5b4 \uac19\uc774 \uc2dd\uc0ac\ud558\ub294 \uac8c \uc81c\uc77c \uc88b\uc544\ud558\uc2e4 \uac83 \uac19\uae30\ub3c4 \ud558\uace0 \ud615\uc774\ub791 \uc0c1\uc758\ud574\ubd10\uc57c\uaca0\ub2e4 \ub2e4\ub4e4 \uc2dc\uac04 \ub418\ub294 \ub0a0\ub85c \uc7a1\uc544\uc11c \ubaa8\uc774\uc790\uace0 \ud574\uc57c\uc9c0\n\uc544\ubc84\uc9c0 \ubcd1\uc6d0 \uc608\uc57d \ub2e4\uc74c \uc8fc \ud654\uc694\uc77c \uc624\uc804 \uc5f4 \uc2dc\uc57c \ub0b4\uac00 \ubaa8\uc2dc\uace0 \uac08\uac8c \uac80\uc0ac \uacb0\uacfc\ub294 \uadf8\ub0a0 \ubc14\ub85c \ub098\uc628\ub2e4\uace0 \ud588\uc5b4 \uac71\uc815\ud558\uc9c0 \ub9c8\uc2dc\ub77c\uace0 \ub9d0\uc500\ub4dc\ub838\ub294\ub370 \ud45c\uc815\uc774 \uc548 \uc88b\uc73c\uc2dc\ub354\ub77c \uacb0\uacfc \ub098\uc624\uba74 \ubc14\ub85c \uc5f0\ub77d\ud560\uac8c\n\ub3d9\uc0dd\uc774 \uc2dc\ud5d8 \ub54c\ubb38\uc5d0 \uc694\uc998 \uc608\ubbfc\ud574 \uad1c\ud788 \uac74\ub4dc\ub9ac\uc9c0 \ub9d0\uace0 \uadf8\ub0e5 \ub450\uc790 \ub05d\ub098\uba74 \uc880 \ub098\uc544\uc9c0\uaca0\uc9c0 \uace0\uc0dd \ub9ce\uc774 \ud588\uc73c\ub2c8\uae4c \ub05d\ub098\uace0 \ub9db\uc788\ub294 \uac70 \uc0ac\uc8fc\ub824\uace0 \ud574 \ubb58 \uc88b\uc544\ud558\ub294\uc9c0 \ubb3c\uc5b4\ubd10\uc57c\uaca0\ub2e4\n\ud560\uba38\ub2c8 \ub301\uc5d0 \ub2e4\ub140\uc654\ub2e4. \ub9c8\ub2f9\uc5d0 \uac10\uc774 \ub9ce\uc774 \uc5f4\ub838\ub294\ub370 \ub530\uc11c \uae4e\uc544 \ub9d0\ub824 \ub450\uc168\ub2e4\uace0 \ud558\uc168\ub2e4. \uac00\uc838\uac00\ub77c\uace0 \ud55c \ubd09\uc9c0 \ucc59\uaca8 \uc8fc\uc168\ub2e4. \uc694\uc998 \ubb34\ub98e\uc774 \uc544\ud504\uc154\uc11c \uba40\ub9ac\ub294 \ubabb \ub2e4\ub2c8\uc2e0\ub2e4\uace0 \ud588\ub2e4. \uc790\uc8fc \ucc3e\uc544\ubd48\uc5b4\uc57c\uaca0\ub2e4\ub294 \uc0dd\uac01\uc744 \ud558\uba74\uc11c\ub3c4 \ub9c9\uc0c1 \uc2dc\uac04\uc744 \ub0b4\uae30\uac00 \uc27d\uc9c0 \uc54a\ub2e4.\n\uc624\ub298 \uc880 \ud798\ub4e4\uc5c8\uc5b4 \ubcc4\uc77c\uc740 \uc544\ub2cc\ub370 \uadf8\ub0e5 \uc9c0\uce58\ub124 \uc774\uc57c\uae30 \ub4e4\uc5b4\uc918\uc11c \uace0\ub9c8\uc6cc \ub9d0\ud558\uace0 \ub098\ub2c8\uae4c \uc880 \ub098\uc544\uc84c\uc5b4 \ub0b4\uc77c\uc740 \uad1c\ucc2e\uc544\uc9c8 \uac70\uc57c \ub108\ubb34 \uac71\uc815\ud558\uc9c0 \ub9c8 \ud63c\uc790 \ub059\ub059\ub300\uc9c0 \ub9d0\uace0 \ud798\ub4e4\uba74 \ub9d0\ud574 \uc5b8\uc81c\ub4e0 \ub4e4\uc5b4\uc904\uac8c\n\ucd95\ud558\ud574 \uc9c4\uc9dc \uc798\ub410\ub2e4 \uadf8\ub3d9\uc548 \uace0\uc0dd\ud55c \uac70 \uc544\ub2c8\uae4c \ub354 \uae30\uc058\ub2e4 \ud55c\ud131 \uc3f4\uc57c\uaca0\ub294\ub370 \uc5b8\uc81c \uc2dc\uac04 \ub3fc \ub0a0 \uc7a1\uc790 \ub2e4\ub4e4 \ubd80\ub974\uc790 \uc624\ub79c\ub9cc\uc5d0 \ubaa8\uc774\uba74 \uc88b\uaca0\ub2e4\n\uc548\ub155\ud558\uc138\uc694. \uc9c0\ub09c\ubc88\uc5d0 \ub9d0\uc500\ub4dc\ub9b0 \uc790\ub8cc \uc815\ub9ac\ud574\uc11c \ucca8\ubd80\ud569\ub2c8\ub2e4. \uac80\ud1a0\ud558\uc2dc\uace0 \uc218\uc815\ud560 \ubd80\ubd84 \uc788\uc73c\uba74 \uc54c\ub824 \uc8fc\uc2dc\uae30 \ubc14\ub78d\ub2c8\ub2e4. \ucd08\uc548\uc774\ub77c \ubd80\uc871\ud55c \uc810\uc774 \ub9ce\uc744 \uac83 \uac19\uc2b5\ub2c8\ub2e4. \uc758\uacac \uc8fc\uc2dc\uba74 \ubc18\uc601\ud574\uc11c \ub2e4\uc2dc \ubcf4\ub0b4 \ub4dc\ub9ac\uaca0\uc2b5\ub2c8\ub2e4. \uac10\uc0ac\ud569\ub2c8\ub2e4.\n\ub9d0\uc500\ud558\uc2e0 \uc77c\uc815\uc740 \ud655\uc778\ud588\uc2b5\ub2c8\ub2e4. \ub2e4\ub9cc \uadf8 \uc8fc\uc5d0\ub294 \ub2e4\ub978 \uc77c\uc815\uc774 \uc788\uc5b4 \ucc38\uc11d\uc774 \uc5b4\ub824\uc6b8 \uac83 \uac19\uc2b5\ub2c8\ub2e4. \uac00\ub2a5\ud558\uc2dc\ub2e4\uba74 \ub2e4\uc74c \uc8fc\ub85c \uc62e\uae38 \uc218 \uc788\uc744\uc9c0 \uc5ec\ucb59\uace0 \uc2f6\uc2b5\ub2c8\ub2e4. \ubc88\uac70\ub86d\uac8c \ud574 \ub4dc\ub824 \uc8c4\uc1a1\ud569\ub2c8\ub2e4. \uc870\uc728\uc774 \uc5b4\ub824\uc6b0\uc2dc\uba74 \ud68c\uc758\ub85d\uc73c\ub85c \ub300\uc2e0 \ud655\uc778\ud558\uaca0\uc2b5\ub2c8\ub2e4.\n\ud68c\uc758 \uacb0\uacfc\ub97c \uc815\ub9ac\ud574 \uacf5\uc720\ub4dc\ub9bd\ub2c8\ub2e4. \uccab\uc9f8, \uc77c\uc815\uc740 \uae30\uc874 \uacc4\ud68d\ub300\ub85c \uc9c4\ud589\ud558\uae30\ub85c \ud588\uc2b5\ub2c8\ub2e4. \ub458\uc9f8, \uc608\uc0b0\uc740 \ud56d\ubaa9\ubcc4\ub85c \uc7ac\uac80\ud1a0\ud55c \ub4a4 \ub2e4\uc74c \ud68c\uc758\uc5d0\uc11c \ud655\uc815\ud558\uae30\ub85c \ud588\uc2b5\ub2c8\ub2e4. \uc14b\uc9f8, \ub2f4\ub2f9\uc790\ub294 \uac01 \ud300\uc5d0\uc11c \ud55c \uba85\uc529 \uc9c0\uc815\ud574 \uc774\ubc88 \uc8fc \ub0b4\ub85c \uc54c\ub824 \uc8fc\uc2dc\uae30 \ubc14\ub78d\ub2c8\ub2e4.\n\ubcf4\uace0\ub4dc\ub9bd\ub2c8\ub2e4. \ud604\uc7ac\uae4c\uc9c0 \uc9c4\ud589\ub960\uc740 \uc57d \uce60\uc2ed \ud37c\uc13c\ud2b8\uc774\uba70, \uc608\uc815\ub41c \uc77c\uc815\ubcf4\ub2e4 \uc774\ud2c0 \uc815\ub3c4 \uc55e\uc11c \uc788\uc2b5\ub2c8\ub2e4. \ub2e4\ub9cc \uc678\ubd80 \uc5c5\uccb4 \ud68c\uc2e0\uc774 \ub2a6\uc5b4\uc9c0\ub294 \ubd80\ubd84\uc774 \uc788\uc5b4 \ub2e4\uc74c \ub2e8\uacc4\uc5d0\uc11c \uc9c0\uc5f0\ub420 \uac00\ub2a5\uc131\uc774 \uc788\uc2b5\ub2c8\ub2e4. \ub300\ube44\ucc45\uc744 \ud568\uaed8 \uc900\ube44\ud558\uace0 \uc788\uc2b5\ub2c8\ub2e4.\n\ud734\uac00 \uc2e0\uccad \uad00\ub828 \uc548\ub0b4\ub4dc\ub9bd\ub2c8\ub2e4. \ub2e4\uc74c \ub2ec \ud734\uac00 \uacc4\ud68d\uc740 \uc774\ubc88 \uc8fc \uae08\uc694\uc77c\uae4c\uc9c0 \uc81c\ucd9c\ud574 \uc8fc\uc2dc\uae30 \ubc14\ub78d\ub2c8\ub2e4. \uac19\uc740 \ud300\uc5d0\uc11c \uc911\ubcf5\ub418\ub294 \ub0a0\uc9dc\uac00 \uc788\uc744 \uacbd\uc6b0 \uc870\uc815\uc774 \ud544\uc694\ud558\ub2c8 \ubbf8\ub9ac \uc0c1\uc758\ud574 \uc8fc\uc2ed\uc2dc\uc624. \uc2b9\uc778 \uacb0\uacfc\ub294 \ub2e4\uc74c \uc8fc \ucd08\uc5d0 \uac1c\ubcc4 \uc548\ub0b4\ub4dc\ub9ac\uaca0\uc2b5\ub2c8\ub2e4.\n\uacc4\uc57d\uc11c \uac80\ud1a0 \uc694\uccad\ub4dc\ub9bd\ub2c8\ub2e4. \ud2b9\ud788 \uc0bc \uc870 \uc774 \ud56d\uc758 \uc704\uc57d\uae08 \uc870\ud56d\uacfc \uc624 \uc870\uc758 \uacc4\uc57d \ud574\uc9c0 \uc870\uac74\uc744 \uc911\uc810\uc801\uc73c\ub85c \ubd10 \uc8fc\uc2dc\uba74 \uac10\uc0ac\ud558\uaca0\uc2b5\ub2c8\ub2e4. \uc11c\uba85 \uc804\uc5d0 \ubc18\ub4dc\uc2dc \ud655\uc778\uc774 \ud544\uc694\ud55c \uc0ac\ud56d\uc785\ub2c8\ub2e4. \uc758\uacac\uc740 \uc774\ubc88 \uc8fc \ubaa9\uc694\uc77c\uae4c\uc9c0 \ubd80\ud0c1\ub4dc\ub9bd\ub2c8\ub2e4.\n\uacc4\uc88c\ubc88\ud638\ub294 \ub9cc\ub098\uc11c \uc54c\ub824\uc904\uac8c \ubb38\uc790\ub85c \ubcf4\ub0b4\ub294 \uac74 \uc880 \uadf8\ub798 \uc740\ud589 \uc571\uc5d0\uc11c \ud655\uc778\ud558\ub294 \uac8c \ub098\uc744 \uac83 \uac19\uc544 \uc785\uae08\ud558\uba74 \ud655\uc778\ud558\uace0 \uc5f0\ub77d\ud560\uac8c \uacc4\uc88c \ube44\ubc00\ubc88\ud638\ub098 \uc778\uc99d\ubc88\ud638\ub294 \ub204\uad6c\uc5d0\uac8c\ub3c4 \uc54c\ub824\uc8fc\uba74 \uc548 \ub3fc \uc740\ud589\uc5d0\uc11c\ub294 \uc808\ub300 \uadf8\ub7f0 \uac78 \ubb3b\uc9c0 \uc54a\uc544\n\uce74\ub4dc\uac12\uc774 \uc774\ubc88 \ub2ec\uc5d0 \uc0dd\uac01\ubcf4\ub2e4 \ub9ce\uc774 \ub098\uc654\ub2e4. \uba85\uc138\uc11c\ub97c \ubcf4\ub2c8 \uad6c\ub3c5 \uc11c\ube44\uc2a4\uac00 \uc5ec\ub7ec \uac1c \uc790\ub3d9 \uacb0\uc81c\ub418\uace0 \uc788\uc5c8\ub2e4. \uc548 \uc4f0\ub294 \uac74 \uc815\ub9ac\ud574\uc57c\uaca0\ub2e4. \ub9e4\ub2ec \uc870\uae08\uc529\uc774\ub77c\ub3c4 \ub098\uac00\ub294 \ub3c8\uc740 \uc77c \ub144\uc774\uba74 \uaf64 \ud070 \uae08\uc561\uc774 \ub41c\ub2e4.\n\uc801\uae08 \ub9cc\uae30\uac00 \ub2e4\uc74c \ub2ec\uc778\ub370 \uc5b4\ub5bb\uac8c \ud560\uc9c0 \uace0\ubbfc\uc774\ub2e4. \uae08\ub9ac\uac00 \uc608\uc804\ub9cc \ubabb\ud574\uc11c \ub2e4\uc2dc \ub123\uae30\uac00 \ub9dd\uc124\uc5ec\uc9c4\ub2e4. \uc77c\ubd80\ub294 \ube44\uc0c1\uae08\uc73c\ub85c \ub450\uace0 \ub098\uba38\uc9c0\ub9cc \ub2e4\uc2dc \ubb36\uc5b4 \ub458 \uc0dd\uac01\uc774\ub2e4. \ubb34\ub9ac\ud558\uac8c \uad74\ub9ac\uae30\ubcf4\ub2e4\ub294 \uc548\uc804\ud558\uac8c \uac00\ub294 \ud3b8\uc774 \ub0ab\uaca0\ub2e4.\n\ube44\ubc00\ubc88\ud638\ub97c \uc5ec\uae30\uc800\uae30 \uac19\uc740 \uac78 \uc4f0\uace0 \uc788\uc5c8\ub294\ub370 \ubc14\uafb8\uae30\ub85c \ud588\ub2e4. \ud55c \uacf3\uc774 \ub6ab\ub9ac\uba74 \uc804\ubd80 \uc704\ud5d8\ud574\uc9c4\ub2e4\ub294 \ub9d0\uc744 \ub4e3\uace0 \ub098\ub2c8 \ubd88\uc548\ud574\uc84c\ub2e4. \uc911\uc694\ud55c \uacf3\ubd80\ud130 \ud558\ub098\uc529 \ub2e4\ub974\uac8c \ubc14\uafb8\uace0 \uc788\ub2e4. \uc678\uc6b0\uae30 \uc5b4\ub824\uc6b4 \uac74 \ub530\ub85c \uc801\uc5b4\uc11c \uc548\uc804\ud55c \uacf3\uc5d0 \ub450\uc5c8\ub2e4.\n\uc0c8 \uc9d1 \ube44\ubc00\ubc88\ud638\ub294 \ub9cc\ub098\uc11c \ub9d0\ud574\uc904\uac8c \ubb38 \uc55e\uc5d0 \ud0dd\ubc30 \uc624\uba74 \uacbd\ube44\uc2e4\uc5d0 \ub9e1\uaca8 \ub2ec\ub77c\uace0 \ud588\uc5b4 \uc5f4\uc1e0\ub294 \ud558\ub098 \ub354 \ub9cc\ub4e4\uc5b4\uc11c \uc5b4\uba38\ub2c8\uaed8 \ub4dc\ub838\uc5b4 \ud639\uc2dc \ubaa8\ub974\ub2c8\uae4c\n\uc624\ub298 \uc544\uce68\uc5d0\ub294 \uc720\ub09c\ud788 \uc77c\uc5b4\ub098\uae30\uac00 \ud798\ub4e4\uc5c8\ub2e4. \uc54c\ub78c\uc744 \uc138 \ubc88\uc774\ub098 \ubbf8\ub8e8\ub2e4\uac00 \uaca8\uc6b0 \uc77c\uc5b4\ub0ac\ub2e4. \ucc3d\ubc16\uc740 \uc544\uc9c1 \uc5b4\ub451\ud588\uace0 \uacf5\uae30\uac00 \ucc3c\ub2e4. \ub530\ub73b\ud55c \ubb3c\uc744 \ud55c \uc794 \ub9c8\uc2dc\uace0 \ub098\ub2c8 \uc870\uae08 \uc815\uc2e0\uc774 \ub4e4\uc5c8\ub2e4. \uc694\uc998 \uc7a0\ub4dc\ub294 \uc2dc\uac04\uc774 \uc790\uafb8 \ub2a6\uc5b4\uc838\uc11c \uadf8\ub7f0 \uac83 \uac19\ub2e4.\n\uc800\ub141\uc5d0 \ud63c\uc790 \uac78\uc5c8\ub2e4. \ud2b9\ubcc4\ud788 \ubaa9\uc801\uc9c0\ub97c \uc815\ud558\uc9c0 \uc54a\uace0 \uadf8\ub0e5 \uac77\ub2e4 \ubcf4\ub2c8 \ud3c9\uc18c\uc5d0 \uc9c0\ub098\uce58\ub358 \uace8\ubaa9\uae4c\uc9c0 \ub4e4\uc5b4\uac00\uac8c \ub410\ub2e4. \uc624\ub798\ub41c \uac04\ud310\uacfc \ub0a1\uc740 \uacc4\ub2e8\uc774 \uadf8\ub300\ub85c \ub0a8\uc544 \uc788\uc5c8\ub2e4. \uc0ac\ub78c\ub4e4\uc774 \uc0ac\ub294 \ubaa8\uc2b5\uc740 \ud06c\uac8c \ub2ec\ub77c\uc9c0\uc9c0 \uc54a\uc558\uad6c\ub098 \uc2f6\uc5c8\ub2e4.\n\ud55c\ub3d9\uc548 \ubbf8\ub904 \ub450\uc5c8\ub358 \ucc45\uc744 \ub2e4\uc2dc \ud3bc\ucce4\ub2e4. \uc808\ubc18\ucbe4 \uc77d\ub2e4 \ub9cc \ucc44\ub85c \uba87 \ub2ec\uc774 \uc9c0\ub0ac\ub294\ub370, \uc55e\ubd80\ubd84\uc744 \ub2e4\uc2dc \ud6d1\uc73c\ub2c8 \uae30\uc5b5\ub098\ub294 \ubb38\uc7a5\uc774 \uaf64 \uc788\uc5c8\ub2e4. \uadf8\ub54c\ub294 \uadf8\ub0e5 \ub118\uacbc\ub358 \ub300\ubaa9\uc774 \uc9c0\uae08\uc740 \ub2e4\ub974\uac8c \uc77d\ud614\ub2e4. \uac19\uc740 \uae00\ub3c4 \uc77d\ub294 \uc2dc\uae30\uc5d0 \ub530\ub77c \ub2e4\ub974\uac8c \ub2e4\uac00\uc628\ub2e4.\n\uc77c\uc774 \ub73b\ub300\ub85c \ub418\uc9c0 \uc54a\uc740 \ub0a0\uc774\uc5c8\ub2e4. \uc900\ube44\ud55c \ub9cc\ud07c \uacb0\uacfc\uac00 \ub098\uc624\uc9c0 \uc54a\uc73c\uba74 \ud5c8\ud0c8\ud574\uc9c4\ub2e4. \uadf8\ub798\ub3c4 \uacfc\uc815\uc5d0\uc11c \ubc30\uc6b4 \uac8c \uc5c6\uc9c0\ub294 \uc54a\uc558\ub2e4. \ub2e4\uc74c\uc5d0\ub294 \uac19\uc740 \uc2e4\uc218\ub97c \ubc18\ubcf5\ud558\uc9c0 \uc54a\uc73c\uba74 \uadf8\uac78\ub85c \ucda9\ubd84\ud558\ub2e4\uace0 \uc0dd\uac01\ud558\uae30\ub85c \ud588\ub2e4.\n\uc62c\ud574\uac00 \ubc8c\uc368 \uc808\ubc18\uc774\ub098 \uc9c0\ub0ac\ub2e4. \uc5f0\ucd08\uc5d0 \uc138\uc6b4 \uacc4\ud68d\uc744 \ub2e4\uc2dc \ubcf4\ub2c8 \uc9c0\ud0a8 \uac83\ubcf4\ub2e4 \ubabb \uc9c0\ud0a8 \uac83\uc774 \ub9ce\ub2e4. \uadf8\ub798\ub3c4 \uc544\uc608 \uc190\ub3c4 \ubabb \ub304 \uac74 \uc544\ub2c8\uc5b4\uc11c \uc870\uae08\uc740 \uc704\uc548\uc774 \ub41c\ub2e4. \ub0a8\uc740 \uae30\uac04\uc5d0\ub294 \uac1c\uc218\ub97c \uc904\uc774\uace0 \ud558\ub098\ub77c\ub3c4 \uc81c\ub300\ub85c \ud574 \ubcf4\ub824 \ud55c\ub2e4.\n\uc815\ubd80\ub294 \uc5b4\uc81c \uad00\ub828 \ubc95\uc548\uc758 \uc2dc\ud589 \uc2dc\uae30\ub97c \ub0b4\ub144 \uc0c1\ubc18\uae30\ub85c \ubbf8\ub8e8\uae30\ub85c \ud588\ub2e4\uace0 \ubc1d\ud614\ub2e4. \uc900\ube44 \uae30\uac04\uc774 \ubd80\uc871\ud558\ub2e4\ub294 \ud604\uc7a5\uc758 \uc758\uacac\uc744 \ubc18\uc601\ud55c \uacb0\uc815\uc774\ub2e4. \ub2e4\ub9cc \uc2dc\ud589\uc774 \ub2a6\uc5b4\uc9c0\uba74\uc11c \uc81c\ub3c4\uc758 \uc2e4\ud6a8\uc131\uc774 \ub5a8\uc5b4\uc9c8 \uc218 \uc788\ub2e4\ub294 \uc9c0\uc801\ub3c4 \ub098\uc628\ub2e4.\n\uc870\uc0ac\uc5d0 \ub530\ub974\uba74 \uc751\ub2f5\uc790\uc758 \uc808\ubc18 \uc774\uc0c1\uc774 \ud544\uc694\uc131\uc5d0\ub294 \uacf5\uac10\ud558\uc9c0\ub9cc \uad6c\uccb4\uc801\uc778 \ubc29\uc2dd\uc5d0\ub294 \uc774\uacac\uc744 \ubcf4\uc600\ub2e4. \ud2b9\ud788 \ube44\uc6a9 \ubd80\ub2f4 \uc8fc\uccb4\ub97c \ub450\uace0 \uc758\uacac\uc774 \ud06c\uac8c \uac08\ub838\ub2e4. \uc5f0\uad6c\uc9c4\uc740 \ucd94\uac00 \uc870\uc0ac\ub97c \ud1b5\ud574 \uc138\ubd80 \ubc29\uc548\uc744 \ub9c8\ub828\ud560 \uacc4\ud68d\uc774\ub77c\uace0 \ubc1d\ud614\ub2e4.\n\uc9c0\ub09c\ub2ec \uc18c\ube44\uc790\ubb3c\uac00\ub294 \uc804\ub144 \uac19\uc740 \ub2ec\ubcf4\ub2e4 \uc774 \uc810 \uc0bc \ud37c\uc13c\ud2b8 \uc62c\ub790\ub2e4. \ub18d\uc0b0\ubb3c \uac00\uaca9\uc774 \uc548\uc815\ub418\uba74\uc11c \uc0c1\uc2b9 \ud3ed\uc740 \uc804\ub2ec\ubcf4\ub2e4 \uc904\uc5c8\ub2e4. \ub2e4\ub9cc \uc678\uc2dd\ube44\uc640 \uacf5\uacf5\uc694\uae08\uc740 \uc5ec\uc804\ud788 \uc624\ub984\uc138\ub97c \uc774\uc5b4\uac14\ub2e4.\n\uc804\ubb38\uac00\ub4e4\uc740 \ub2e8\uae30\uc801\uc778 \ub300\ucc45\ubcf4\ub2e4 \uad6c\uc870\uc801\uc778 \uc811\uadfc\uc774 \ud544\uc694\ud558\ub2e4\uace0 \uc785\uc744 \ubaa8\uc558\ub2e4. \uc6d0\uc778\uc774 \ud558\ub098\uac00 \uc544\ub2c8\uae30 \ub54c\ubb38\uc5d0 \ud574\uacb0\ucc45\ub3c4 \uc5ec\ub7ec \ubc29\ud5a5\uc5d0\uc11c \ub3d9\uc2dc\uc5d0 \ub098\uc640\uc57c \ud55c\ub2e4\ub294 \uac83\uc774\ub2e4. \ubb34\uc5c7\ubcf4\ub2e4 \uc9c0\uc18d\uc801\uc778 \uad00\ucc30\uacfc \uc790\ub8cc \ucd95\uc801\uc774 \uc911\uc694\ud558\ub2e4\uace0 \uac15\uc870\ud588\ub2e4.\n\ubb3c\uc740 \uc12d\uc528 \ubc31 \ub3c4\uc5d0\uc11c \ub053\uace0 \uc601 \ub3c4\uc5d0\uc11c \uc5b8\ub2e4. \ub2e4\ub9cc \uc555\ub825\uc774 \ub0ae\uc544\uc9c0\uba74 \ub053\ub294\uc810\ub3c4 \ud568\uaed8 \ub0b4\ub824\uac04\ub2e4. \ub192\uc740 \uc0b0\uc5d0\uc11c \ubc25\uc774 \uc124\uc775\ub294 \uc774\uc720\uac00 \uc5ec\uae30\uc5d0 \uc788\ub2e4. \uc555\ub825\uc1a5\uc740 \ubc18\ub300\ub85c \ub0b4\ubd80 \uc555\ub825\uc744 \ub192\uc5ec \ub053\ub294\uc810\uc744 \uc62c\ub9ac\ub294 \ub3c4\uad6c\ub2e4.\n\uc2dd\ubb3c\uc740 \ube5b\uc744 \ubc1b\uc544 \uc774\uc0b0\ud654\ud0c4\uc18c\uc640 \ubb3c\ub85c \uc591\ubd84\uc744 \ub9cc\ub4e0\ub2e4. \uc774 \uacfc\uc815\uc5d0\uc11c \uc0b0\uc18c\uac00 \ub098\uc628\ub2e4. \ubc24\uc5d0\ub294 \ubc18\ub300\ub85c \ud638\ud761\ub9cc \ud558\uae30 \ub54c\ubb38\uc5d0 \uc0b0\uc18c\ub97c \uc4f0\uace0 \uc774\uc0b0\ud654\ud0c4\uc18c\ub97c \ub0b4\ub193\ub294\ub2e4. \uc78e\uc758 \ub4b7\uba74\uc5d0 \uc788\ub294 \uc791\uc740 \uad6c\uba4d\uc73c\ub85c \uae30\uccb4\uac00 \ub4dc\ub098\ub4e0\ub2e4.\n\u314b\u314b\u314b\u314b \uc9c4\uc9dc \uc6c3\uaca8 \ub098 \uc9c0\uae08 \ud63c\uc790 \uc6c3\uace0 \uc788\uc5b4 \u3160\u3160 \uc544 \ubc30\uc544\ud30c \uadf8\uac70 \uc5b4\ub514\uc11c \ubd24\uc5b4 \ub9c1\ud06c \uc880 \ubcf4\ub0b4\uc918 \ub098\ub3c4 \ubcf4\uace0 \uc2f6\uc5b4 \u3147\u3147 \uc9c0\uae08 \ubcf4\ub0bc\uac8c \u3131\u3131 \ubd24\uc5b4? \ub300\ubc15\uc774\uc9c0 \u3147\u3148 \uc778\uc815 \uc644\uc804 \ub0b4 \uc598\uae30\uc796\uc544\n\ud5d0 \uc9c4\uc9dc? \uc5b8\uc81c \uadf8\ub7ac\ub300 \ub098\ub9cc \ubab0\ub790\ub124 \uc544\ub2c8 \uc65c \ub9d0 \uc548 \ud588\uc5b4 \uc11c\uc6b4\ud558\ub2e4 \u314b\u314b \ubbf8\uc548\ubbf8\uc548 \uae4c\uba39\uc5c8\uc5b4 \ub2f4\uc5d4 \uaf2d \ub9d0\ud560\uac8c \uc54c\uaca0\uc5b4 \ub118\uc5b4\uac00\uc90c \u314e\u314e\n\uc544 \ub9de\ub2e4 \uadf8\uac70 \uc5b4\ub5bb\uac8c \ub410\uc5b4 \uc798 \ud574\uacb0\ub410\uc5b4? \uc751 \ub2e4\ud589\ud788 \uc798 \ub05d\ub0ac\uc5b4 \ub2e4\ud589\uc774\ub2e4 \uc9c4\uc9dc \uac71\uc815\ud588\uc796\uc544 \uace0\ub9c8\uc6cc \uc2e0\uacbd \uc368\uc918\uc11c \ubcc4\ub9d0\uc500\uc744 \ub2f9\uc5f0\ud55c \uac70\uc9c0\n\uc624\ub298 \uc9c4\uc9dc \ud53c\uace4\ud558\ub2e4 \uadf8\ub0e5 \uc9d1 \uac00\uc11c \ub215\uace0 \uc2f6\uc5b4 \ub098\ub3c4 \u3160\u3160 \uc6b0\ub9ac \ub458 \ub2e4 \uc26c\uc5b4\uc57c \ud574 \uc8fc\ub9d0\uc5d0 \ud479 \uc790\uc790 \uadf8\ub798 \uadf8\ub7ec\uc790\n\uc11c\ubc84\uac00 \uc0c8\ubcbd\uc5d0 \ub450 \ubc88 \uc7ac\uc2dc\uc791\ub410\ub2e4. \ub85c\uadf8\ub97c \ubcf4\ub2c8 \uba54\ubaa8\ub9ac \uc0ac\uc6a9\ub7c9\uc774 \uacc4\uc18d \uc62c\ub77c\uac00\ub2e4\uac00 \ud55c\uacc4\uc5d0 \ubd80\ub52a\ud600 \uc885\ub8cc\ub41c \ud754\uc801\uc774\uc5c8\ub2e4. \uc5b4\uc81c \ubc30\ud3ec\ud55c \ubcc0\uacbd \uc911\uc5d0 \uce90\uc2dc\ub97c \ube44\uc6b0\uc9c0 \uc54a\ub294 \ubd80\ubd84\uc774 \uc788\uc5c8\ub358 \uac83 \uac19\ub2e4. \uc77c\ub2e8 \ub418\ub3cc\ub9ac\uace0 \uc6d0\uc778\uc744 \ub354 \ud655\uc778\ud558\uae30\ub85c \ud588\ub2e4.\n\ube4c\ub4dc\uac00 \uc2e4\ud328\ud574\uc11c \ud655\uc778\ud574 \ubcf4\ub2c8 \uc758\uc874\uc131 \ubc84\uc804\uc774 \uc11c\ub85c \ucda9\ub3cc\ud558\uace0 \uc788\uc5c8\ub2e4. \uc7a0\uae08 \ud30c\uc77c\uc744 \uc9c0\uc6b0\uace0 \ub2e4\uc2dc \uc124\uce58\ud558\ub2c8 \ud574\uacb0\ub410\ub2e4. \ub2e4\ub9cc \uc65c \uac11\uc790\uae30 \ucda9\ub3cc\uc774 \uc0dd\uacbc\ub294\uc9c0\ub294 \ub354 \ubd10\uc57c \ud560 \uac83 \uac19\ub2e4. \uc0c1\uc704 \ud328\ud0a4\uc9c0\uac00 \uc870\uc6a9\ud788 \ubc94\uc704\ub97c \ubc14\uafbc \ub4ef\ud558\ub2e4.\n\ub370\uc774\ud130\ubca0\uc774\uc2a4 \uc870\ud68c\uac00 \ub290\ub824\uc11c \uc2e4\ud589 \uacc4\ud68d\uc744 \ud655\uc778\ud588\ub2e4. \uc778\ub371\uc2a4\ub97c \ud0c0\uc9c0 \uc54a\uace0 \uc804\uccb4\ub97c \ud6d1\uace0 \uc788\uc5c8\ub2e4. \uc870\uac74\uc808\uc5d0 \ud568\uc218\ub97c \uc50c\uc6b4 \ud0d3\uc774\uc5c8\ub2e4. \ud568\uc218\ub97c \uac77\uc5b4\ub0b4\uace0 \uc778\ub371\uc2a4\ub97c \ub2e4\uc2dc \uc7a1\uc73c\ub2c8 \uc751\ub2f5 \uc2dc\uac04\uc774 \ud06c\uac8c \uc904\uc5c8\ub2e4.\n\ucf54\ub4dc\ub97c \uace0\uce58\uae30 \uc804\uc5d0 \uc65c \uadf8\ub807\uac8c \ub418\uc5b4 \uc788\ub294\uc9c0\ubd80\ud130 \uc774\ud574\ud558\ub294 \ud3b8\uc774 \ub0ab\ub2e4. \uc774\uc0c1\ud574 \ubcf4\uc774\ub294 \ubd80\ubd84\uc5d0\ub3c4 \ub300\uac1c \uc774\uc720\uac00 \uc788\ub2e4. \uc774\uc720\ub97c \ubaa8\ub978 \ucc44 \uace0\uce58\uba74 \uac19\uc740 \ubb38\uc81c\uac00 \ub2e4\ub978 \ubaa8\uc591\uc73c\ub85c \ub2e4\uc2dc \ub098\ud0c0\ub09c\ub2e4.\n\ud14c\uc2a4\ud2b8\ub97c \uba3c\uc800 \uc368 \ub450\uba74 \ub098\uc911\uc5d0 \uc190\ubcfc \ub54c \ub9c8\uc74c\uc774 \ud3b8\ud558\ub2e4. \ubb34\uc5c7\uc774 \uae68\uc84c\ub294\uc9c0 \ubc14\ub85c \uc54c \uc218 \uc788\uae30 \ub54c\ubb38\uc774\ub2e4. \ucc98\uc74c\uc5d0\ub294 \ubc88\uac70\ub86d\uac8c \ub290\uaef4\uc9c0\uc9c0\ub9cc, \uace0\uce60 \uc77c\uc774 \ubc18\ubcf5\ub420\uc218\ub85d \uc774\ub4dd\uc774 \ucee4\uc9c4\ub2e4.\n\ubb38\uc81c\ub97c \ud480 \ub54c\ub294 \uc870\uac74\uc744 \uba3c\uc800 \uc815\ub9ac\ud558\ub294 \uac8c \uc911\uc694\ud558\ub2e4. \uc8fc\uc5b4\uc9c4 \uac83\uacfc \uad6c\ud558\ub294 \uac83\uc744 \ub098\ub220 \uc801\uae30\ub9cc \ud574\ub3c4 \uae38\uc774 \ubcf4\uc774\ub294 \uacbd\uc6b0\uac00 \ub9ce\ub2e4. \ub9c9\ud788\uba74 \ube44\uc2b7\ud55c \uc720\ud615\uc744 \ub5a0\uc62c\ub824 \ubcf4\uace0, \uadf8\ub798\ub3c4 \uc548 \ub418\uba74 \uc870\uac74\uc744 \ud558\ub098\uc529 \ubc14\uafd4 \uac00\uba70 \uc5b4\ub514\uc11c \uac78\ub9ac\ub294\uc9c0 \ud655\uc778\ud55c\ub2e4.\n\uc678\uc6b0\ub294 \uac83\uacfc \uc774\ud574\ud558\ub294 \uac83\uc740 \ub2e4\ub974\ub2e4. \uc678\uc6b4 \uac83\uc740 \uc870\uae08\ub9cc \ud615\ud0dc\uac00 \ubc14\ub00c\uc5b4\ub3c4 \uc4f8 \uc218 \uc5c6\uc9c0\ub9cc, \uc774\ud574\ud55c \uac83\uc740 \ucc98\uc74c \ubcf4\ub294 \ubb38\uc81c\uc5d0\ub3c4 \uc801\uc6a9\ud560 \uc218 \uc788\ub2e4. \uc2dc\uac04\uc774 \uac78\ub9ac\ub354\ub77c\ub3c4 \uc65c \uadf8\ub7f0\uc9c0\ub97c \ub530\uc838 \ubcf4\ub294 \ud3b8\uc774 \uacb0\uad6d \ube60\ub974\ub2e4.\n\ubcf5\uc2b5\uc740 \ubbf8\ub8e8\uc9c0 \uc54a\ub294 \uac8c \uc88b\ub2e4. \ubc30\uc6b4 \ub0a0 \ub2e4\uc2dc \ubcf4\uba74 \uc2ed \ubd84\uc774\uba74 \ub420 \uac83\uc744, \uc77c\uc8fc\uc77c \ub4a4\uc5d0 \ubcf4\uba74 \ucc98\uc74c\ubd80\ud130 \ub2e4\uc2dc \ud574\uc57c \ud55c\ub2e4. \uc9e7\uac8c\ub77c\ub3c4 \uc790\uc8fc \ubcf4\ub294 \ucabd\uc774 \uc624\ub798 \ub0a8\ub294\ub2e4.\n\uacc4\ud68d\uc740 \ud06c\uac8c \uc138\uc6b0\uace0 \uc2e4\ud589\uc740 \uc791\uac8c \ucabc\uac1c\ub294 \ud3b8\uc774 \ub0ab\ub2e4. \uc624\ub298 \ud560 \uc77c\uc744 \ud55c \uc904\ub85c \uc801\uc5b4 \ub450\uba74 \uc2dc\uc791\ud558\uae30\uac00 \ud6e8\uc52c \uc218\uc6d4\ud558\ub2e4. \uc644\ubcbd\ud558\uac8c \ud558\ub824\ub2e4 \uc544\uc608 \uc2dc\uc791\ud558\uc9c0 \ubabb\ud558\ub294 \uacbd\uc6b0\uac00 \uc81c\uc77c \uc544\uae5d\ub2e4.\n\uc5ec\ud589 \uc77c\uc815 \uc815\ub9ac\ud588\uc5b4 \uccab\ub0a0\uc740 \ub3c4\ucc29\ud574\uc11c \uc219\uc18c\ub9cc \uac00\uace0 \ub458\uc9f8 \ub0a0\ubd80\ud130 \uc6c0\uc9c1\uc774\uc790 \uc14b\uc9f8 \ub0a0\uc740 \uc880 \uc5ec\uc720 \uc788\uac8c \uc7a1\uc558\uc5b4 \ub108\ubb34 \ube61\ube61\ud558\uba74 \ud798\ub4e4\ub354\ub77c \ub9c8\uc9c0\ub9c9 \ub0a0\uc740 \uacf5\ud56d \uac00\uae30 \uc804\uc5d0 \uadfc\ucc98\ub9cc \ub458\ub7ec\ubcf4\uba74 \ub420 \uac83 \uac19\uc544\n\uc219\uc18c\ub294 \uc5ed\uc5d0\uc11c \uac78\uc5b4\uc11c \uc2ed \ubd84 \uac70\ub9ac\uc57c \uac00\uaca9\ub3c4 \uad1c\ucc2e\uace0 \ud6c4\uae30\ub3c4 \ub098\uc058\uc9c0 \uc54a\uc544 \uc870\uc2dd\uc740 \ud3ec\ud568 \uc548 \ub3fc \uc788\ub294\ub370 \uadfc\ucc98\uc5d0 \uba39\uc744 \ub370\uac00 \ub9ce\uc544\uc11c \uc0c1\uad00\uc5c6\uc744 \uac83 \uac19\uc544 \uc608\uc57d\uc740 \ub0b4\uac00 \ud560\uac8c \ub098\uc911\uc5d0 \uc815\uc0b0\ud558\uc790\n\ube44\ud589\uae30 \uc2dc\uac04\uc774 \uc774\ub978 \ud3b8\uc774\ub77c \uc804\ub0a0 \uc77c\ucc0d \uc790\uc57c \ud560 \uac83 \uac19\uc544 \uc9d0\uc740 \ubbf8\ub9ac \uc2f8 \ub450\ub294 \uac8c \uc88b\uaca0\uc5b4 \ucda9\uc804\uae30\ub791 \uc5ec\uad8c\uc740 \uaf2d \ucc59\uae30\uace0 \uc6b0\uc0b0\ub3c4 \ud558\ub098 \ub123\uc5b4 \uac00\uc790 \ub0a0\uc528\uac00 \uc624\ub77d\uac00\ub77d\ud55c\ub2e4\ub354\ub77c\n\ub0a0\uc528\uac00 \uac11\uc790\uae30 \ucd94\uc6cc\uc84c\ub2e4. \uc5b4\uc81c\uae4c\uc9c0\ub9cc \ud574\ub3c4 \uc587\uc740 \uc637\uc73c\ub85c \ubc84\ud17c\ub294\ub370 \uc624\ub298\uc740 \ub3c4\uc800\ud788 \uc548 \ub418\uaca0\uc5b4\uc11c \ub450\uaebc\uc6b4 \uac78 \uaebc\ub0c8\ub2e4. \ud658\uc808\uae30\ub77c \uac10\uae30 \uac78\ub9ac\uae30 \uc26c\uc6b0\ub2c8 \uc870\uc2ec\ud574\uc57c\uaca0\ub2e4.\n\uc7a5\uc744 \ubcf4\uace0 \uc654\ub2e4. \uc774\ubc88 \uc8fc\uc5d0 \ud574 \uba39\uc744 \uac83\ub4e4\uc744 \ub300\ucda9 \uc815\ud574 \ub193\uace0 \uc0ac\ub2c8 \uc4f8\ub370\uc5c6\ub294 \uac78 \ub35c \uc0ac\uac8c \ub41c\ub2e4. \ub0c9\uc7a5\uace0\ub97c \ud55c \ubc88 \uc815\ub9ac\ud558\uace0 \ub123\uc5c8\ub354\ub2c8 \ud6e8\uc52c \ubcf4\uae30 \uc88b\uc544\uc84c\ub2e4. \uc720\ud1b5\uae30\ud55c \uc9c0\ub09c \uac83\ub4e4\ub3c4 \uba87 \uac1c \ubc84\ub838\ub2e4.\n\ud654\ubd84\uc5d0 \ubb3c\uc744 \uc8fc\ub294 \uac04\uaca9\uc744 \uc870\uae08 \ub298\ub838\ub2e4. \uaca8\uc6b8\uc5d0\ub294 \ud759\uc774 \ub9c8\ub974\ub294 \uc18d\ub3c4\uac00 \ub290\ub824\uc11c \uc790\uc8fc \uc8fc\uba74 \uc624\ud788\ub824 \ubfcc\ub9ac\uac00 \uc0c1\ud55c\ub2e4\uace0 \ud55c\ub2e4. \uc190\uac00\ub77d\uc744 \ub123\uc5b4 \ubcf4\uace0 \uc18d\uae4c\uc9c0 \ub9d0\ub790\uc744 \ub54c\ub9cc \uc8fc\uae30\ub85c \ud588\ub2e4.\n\uc9d1 \uc815\ub9ac\ub97c \ud588\ub2e4. \ubc84\ub9b4\uae4c \ub9d0\uae4c \ub9dd\uc124\uc774\ub358 \uac83\ub4e4\uc744 \uc774\ubc88\uc5d0\ub294 \uacfc\uac10\ud558\uac8c \uc815\ub9ac\ud588\ub2e4. \uc5b8\uc820\uac00 \uc4f8\uc9c0\ub3c4 \ubaa8\ub978\ub2e4\ub294 \uc0dd\uac01\uc73c\ub85c \ub450\uc5c8\ub358 \uac83\ub4e4\uc740 \uacb0\uad6d \uba87 \ub144\uc9f8 \uadf8\ub300\ub85c\uc600\ub2e4. \ube44\uc6b0\uace0 \ub098\ub2c8 \uacf5\uac04\uc774 \ub113\uc5b4 \ubcf4\uc778\ub2e4.\n0123456789 abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ .,!?:;()[]\"'-~/@#%&*+=<> http https www com net org co.kr\n";
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

  // 문맥 표 크기. 2^20 이 0.7%쯤 더 좋지만 모형마다 3MB씩 먹는다.
  // 2^19 면 9개 모형에 13.5MB — 휴대전화에서도 안전하고 예열도 빠르다.
  var MASK = (1 << 19) - 1;

  // 32비트 곱수 — Python 쪽과 결과를 맞추려고 하위 32비트만 쓴다
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

  // 차수는 짧은 쪽(0~6)이 유리하다. 긴 문맥은 코퍼스 안에서 너무 희소해
  // 학습이 되지 않아, 늘려도 0.5% 안쪽이면서 예열만 느려진다.
  function Cfg(orders, sparse, posMix) {
    this.orders = orders;
    this.sparse = sparse || [];
    this.posMix = posMix !== false;
    this.nm = orders.length + this.sparse.length + 1;   // + 단어 모델
    this.nmix = this.posMix ? 2048 : 512;
  }

  var CFG = new Cfg([0, 1, 2, 3, 4, 5, 6], [[1, 2]]);

  // 일치 모델 — 지금까지 본 글(코퍼스 포함)에서 방금 쓴 부분과 길게 겹치는 곳을 찾아
  // 그다음 바이트를 예측한다. 짧은 메시지에서는 1~2%지만, 같은 표현이 되풀이되는
  // 긴 글에서는 17% 가까이 줄어든다. 겹침이 8바이트(한글 2~3글자) 이상일 때만 따른다.
  var MATCH_MIN = 8;
  var MATCH_BITS = 16;
  var MATCH_SIZE = 1 << MATCH_BITS;
  var MATCH_VERIFY = 32;
  var ORDERS = CFG.orders;
  var NM = CFG.nm;

  function Model(cfg) {
    cfg = cfg || CFG;
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
      var wv = new Int32Array(nm + 1); wv.fill(1 << 14);   // +일치 모델
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
    this.histHi = 0;   // 직전 5~8바이트
    this.wh = 0;       // 단어 해시의 하위 32비트
    this.pos = 0;      // UTF-8 연속바이트 위치
    this.buf = new Uint8Array(1 << 15);        // 지금까지 본 모든 바이트
    this.blen = 0;
    this.mt = new Int32Array(MATCH_SIZE);      // 해시 → 그 뒤에 올 바이트의 위치
    this.ms = new Uint16Array(32); this.ms.fill(32768);   // 일치 길이별 "맞을" 확률
    this.mn = new Uint8Array(32);
    this.mlen = 0; this.mptr = 0; this.mexp = 0;
    this.mst = 0; this.mi = -1; this.mbit = 0;
    this.pr = 2048;
    this._ai = 0;
    this._aw = 0;
    this._setCtx();
  }

  Model.prototype._setCtx = function () {
    var cfg = this.cfg, orders = cfg.orders, i, o;
    var h = this.hist;
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
    this.mst = 0;
    this.mi = -1;
    if (this.mlen > 0) {
      var known = 31 - Math.clz32(c0);              // 이 바이트에서 이미 본 비트 수
      if (((this.mexp | 256) >> (8 - known)) === c0) {
        var eb = (this.mexp >> (7 - known)) & 1;
        var mi = this.mlen < 31 ? this.mlen : 31;
        var ms = STRETCH[this.ms[mi] >> 4];
        this.mbit = eb;
        this.mi = mi;
        this.mst = eb ? ms : -ms;
        dot += w[this.nm] * this.mst;
      }
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
    w[this.nm] += (this.mst * err) >> 13;
    if (this.mi >= 0) {
      var mc = this.mn[this.mi];
      this.ms[this.mi] += Math.floor(
        (((bit === this.mbit ? 1 : 0) << 16) - this.ms[this.mi]) * RATE[mc] / 131072);
      if (mc < LIMIT) this.mn[this.mi] = mc + 1;
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
      this._matchByte(b);
      this.c0 = 1;
      this._setCtx();
    }
  };

  Model.prototype._matchByte = function (b) {
    if (this.blen === this.buf.length) {
      var nb = new Uint8Array(this.buf.length * 2);
      nb.set(this.buf);
      this.buf = nb;
    }
    var buf = this.buf;
    buf[this.blen++] = b;
    var n = this.blen;
    if (this.mlen > 0) {
      if (buf[this.mptr] === b) { this.mlen++; this.mptr++; }
      else this.mlen = 0;
    }
    if (n >= MATCH_MIN) {
      var acc = 0x811C9DC5 | 0;                     // FNV-1a (32비트)
      for (var q = n - MATCH_MIN; q < n; q++) acc = Math.imul(acc ^ buf[q], 0x01000193);
      var h = fin(acc) & (MATCH_SIZE - 1);
      if (this.mlen === 0) {
        var cand = this.mt[h];
        if (cand > 0) {
          var ln = 0;
          while (ln < MATCH_VERIFY && cand - 1 - ln >= 0 &&
                 buf[cand - 1 - ln] === buf[n - 1 - ln]) ln++;
          if (ln >= MATCH_MIN) { this.mlen = ln; this.mptr = cand; }
        }
      }
      this.mt[h] = n;
    }
    this.mexp = this.mlen > 0 ? buf[this.mptr] : 0;
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
      pr: m.pr, _ai: m._ai, _aw: m._aw,
      buf: m.buf.slice(0, m.blen), blen: m.blen, mt: m.mt.slice(), ms: m.ms.slice(),
      mn: m.mn.slice(), mlen: m.mlen, mptr: m.mptr, mexp: m.mexp
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
    m.buf = new Uint8Array(Math.max(s.blen * 2, 1 << 15));
    m.buf.set(s.buf);
    m.blen = s.blen;
    m.mt = s.mt.slice(); m.ms = s.ms.slice(); m.mn = s.mn.slice();
    m.mlen = s.mlen; m.mptr = s.mptr; m.mexp = s.mexp;
    m.mst = 0; m.mi = -1; m.mbit = 0;
    return m;
  }

  // 캐시가 오염되지 않도록 항상 복사본을 준다
  function newPrimed(cfg) { return restore(primedModel(cfg || CFG)); }

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
  // 열쇠 유도 — scrypt (RFC 7914).
  //   실제 공격은 열쇠말을 하나씩 넣어 보는 쪽으로 온다. scrypt는 시도 한 번마다
  //   메모리를 64MB씩 쓰게 만들어 GPU·전용 칩으로 대량 병렬 공격하는 비용을 올린다.
  //   N=2^16, r=8, p=2 는 OWASP가 N=2^17·r=8·p=1 과 같은 강도로 꼽는 값이다.
  //   WebCrypto에는 scrypt가 없어서 직접 구현한다. 결과는 Python hashlib.scrypt와 같다.
  var SCRYPT_N = 1 << 16;
  var SCRYPT_R = 8;
  var SCRYPT_P = 2;

  // Salsa20/8 코어 — B[bi..bi+15] 를 제자리에서 바꾼다
  function salsa8(B, bi) {
    var j0 = B[bi], j1 = B[bi + 1], j2 = B[bi + 2], j3 = B[bi + 3],
        j4 = B[bi + 4], j5 = B[bi + 5], j6 = B[bi + 6], j7 = B[bi + 7],
        j8 = B[bi + 8], j9 = B[bi + 9], j10 = B[bi + 10], j11 = B[bi + 11],
        j12 = B[bi + 12], j13 = B[bi + 13], j14 = B[bi + 14], j15 = B[bi + 15];
    var x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7,
        x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15, u;
    for (var i = 0; i < 8; i += 2) {
      u = x0 + x12 | 0;  x4 ^= u << 7 | u >>> 25;
      u = x4 + x0 | 0;   x8 ^= u << 9 | u >>> 23;
      u = x8 + x4 | 0;   x12 ^= u << 13 | u >>> 19;
      u = x12 + x8 | 0;  x0 ^= u << 18 | u >>> 14;
      u = x5 + x1 | 0;   x9 ^= u << 7 | u >>> 25;
      u = x9 + x5 | 0;   x13 ^= u << 9 | u >>> 23;
      u = x13 + x9 | 0;  x1 ^= u << 13 | u >>> 19;
      u = x1 + x13 | 0;  x5 ^= u << 18 | u >>> 14;
      u = x10 + x6 | 0;  x14 ^= u << 7 | u >>> 25;
      u = x14 + x10 | 0; x2 ^= u << 9 | u >>> 23;
      u = x2 + x14 | 0;  x6 ^= u << 13 | u >>> 19;
      u = x6 + x2 | 0;   x10 ^= u << 18 | u >>> 14;
      u = x15 + x11 | 0; x3 ^= u << 7 | u >>> 25;
      u = x3 + x15 | 0;  x7 ^= u << 9 | u >>> 23;
      u = x7 + x3 | 0;   x11 ^= u << 13 | u >>> 19;
      u = x11 + x7 | 0;  x15 ^= u << 18 | u >>> 14;
      u = x0 + x3 | 0;   x1 ^= u << 7 | u >>> 25;
      u = x1 + x0 | 0;   x2 ^= u << 9 | u >>> 23;
      u = x2 + x1 | 0;   x3 ^= u << 13 | u >>> 19;
      u = x3 + x2 | 0;   x0 ^= u << 18 | u >>> 14;
      u = x5 + x4 | 0;   x6 ^= u << 7 | u >>> 25;
      u = x6 + x5 | 0;   x7 ^= u << 9 | u >>> 23;
      u = x7 + x6 | 0;   x4 ^= u << 13 | u >>> 19;
      u = x4 + x7 | 0;   x5 ^= u << 18 | u >>> 14;
      u = x10 + x9 | 0;  x11 ^= u << 7 | u >>> 25;
      u = x11 + x10 | 0; x8 ^= u << 9 | u >>> 23;
      u = x8 + x11 | 0;  x9 ^= u << 13 | u >>> 19;
      u = x9 + x8 | 0;   x10 ^= u << 18 | u >>> 14;
      u = x15 + x14 | 0; x12 ^= u << 7 | u >>> 25;
      u = x12 + x15 | 0; x13 ^= u << 9 | u >>> 23;
      u = x13 + x12 | 0; x14 ^= u << 13 | u >>> 19;
      u = x14 + x13 | 0; x15 ^= u << 18 | u >>> 14;
    }
    B[bi] = j0 + x0 | 0;     B[bi + 1] = j1 + x1 | 0;   B[bi + 2] = j2 + x2 | 0;
    B[bi + 3] = j3 + x3 | 0; B[bi + 4] = j4 + x4 | 0;   B[bi + 5] = j5 + x5 | 0;
    B[bi + 6] = j6 + x6 | 0; B[bi + 7] = j7 + x7 | 0;   B[bi + 8] = j8 + x8 | 0;
    B[bi + 9] = j9 + x9 | 0; B[bi + 10] = j10 + x10 | 0; B[bi + 11] = j11 + x11 | 0;
    B[bi + 12] = j12 + x12 | 0; B[bi + 13] = j13 + x13 | 0;
    B[bi + 14] = j14 + x14 | 0; B[bi + 15] = j15 + x15 | 0;
  }

  // BlockMix — 결과는 (Y0, Y2, …, Y1, Y3, …) 순서로 X에 되돌린다
  function blockMix(X, Y, r, T) {
    T.set(X.subarray((2 * r - 1) * 16, 2 * r * 16));
    for (var i = 0; i < 2 * r; i++) {
      var o = i * 16;
      for (var k = 0; k < 16; k++) T[k] ^= X[o + k];
      salsa8(T, 0);
      Y.set(T, ((i >> 1) + (i & 1) * r) * 16);
    }
    X.set(Y);
  }

  function roMix(W, r, N, V, X, Y, T) {
    var len = 32 * r, i, k;
    X.set(W);
    for (i = 0; i < N; i++) { V.set(X, i * len); blockMix(X, Y, r, T); }
    for (i = 0; i < N; i++) {
      var off = (X[(2 * r - 1) * 16] & (N - 1)) * len;
      for (k = 0; k < len; k++) X[k] ^= V[off + k];
      blockMix(X, Y, r, T);
    }
    W.set(X);
  }

  // PBKDF2-HMAC-SHA256 을 1회만 돈다 (scrypt의 바깥 두 단계).
  //   WebCrypto의 PBKDF2를 쓰지 않는 까닭: Firefox는 한 번에 2048비트(256바이트)까지만
  //   뽑아 주고 그 이상은 OperationError를 낸다. scrypt 첫 단계는 p·128·r = 2048바이트가
  //   필요하다. 반복이 1회면 PBKDF2는 32바이트 블록마다 HMAC 한 번이므로, HMAC으로 직접
  //   짜면 모든 브라우저에서 똑같이 돈다.
  async function pbkdf2Once(hkey, salt, dkLen) {
    var blocks = Math.ceil(dkLen / 32), jobs = [];
    for (var i = 1; i <= blocks; i++) {
      var msg = new Uint8Array(salt.length + 4);
      msg.set(salt);
      msg[salt.length] = (i >>> 24) & 255;
      msg[salt.length + 1] = (i >>> 16) & 255;
      msg[salt.length + 2] = (i >>> 8) & 255;
      msg[salt.length + 3] = i & 255;
      jobs.push(webcrypto.subtle.sign('HMAC', hkey, msg));
    }
    var parts = await Promise.all(jobs);
    var out = new Uint8Array(blocks * 32);
    for (var k = 0; k < parts.length; k++) out.set(new Uint8Array(parts[k]), k * 32);
    return out.slice(0, dkLen);
  }

  async function scrypt(pwBytes, salt, N, r, p, dkLen) {
    // HMAC은 64바이트보다 짧은 열쇠를 0으로 채워 쓰므로, 빈 열쇠말은 0 64바이트와 같다.
    // (WebCrypto는 길이 0인 HMAC 열쇠를 받지 않는다)
    var hkey = await webcrypto.subtle.importKey(
      'raw', pwBytes.length ? pwBytes : new Uint8Array(64),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    var B = await pbkdf2Once(hkey, salt, p * 128 * r);
    var len = 32 * r;
    var V = new Int32Array(len * N);
    var X = new Int32Array(len), Y = new Int32Array(len), W = new Int32Array(len);
    var T = new Int32Array(16);
    var dv = new DataView(B.buffer, B.byteOffset, B.byteLength);
    for (var i = 0; i < p; i++) {
      var off = i * 128 * r, k;
      for (k = 0; k < len; k++) W[k] = dv.getInt32(off + k * 4, true);   // 리틀엔디언
      roMix(W, r, N, V, X, Y, T);
      for (k = 0; k < len; k++) dv.setInt32(off + k * 4, W[k], true);
    }
    V.fill(0);   // 64MB 작업 공간을 비워 둔다
    return pbkdf2Once(hkey, B, dkLen);
  }

  var SEED_OPT = [0, 4, 6, 8];
  var TAG_OPT = [0, 4, 8, 16];
  var NOKEY_PASSWORD = 'hangul-crypt-no-key';

  // 길이 감추기 — 압축한 뒤 암호화하면 암호문 길이가 내용에 따라 달라진다.
  // 전체 길이를 Padmé 방식으로 맞춰 채우면 길이가 드러내는 정보가 O(log log n)
  // 비트로 줄고, 늘어나는 크기는 최대 12%다. 32바이트 이하는 모두 32바이트로.
  var PAD_MIN = 32;

  function padTarget(n) {
    if (n <= PAD_MIN) return PAD_MIN;
    var e = 31 - Math.clz32(n);        // floor(log2 n)
    var sb = 32 - Math.clz32(e);       // floor(log2 e) + 1
    var mask = (1 << (e - sb)) - 1;
    return (n + mask) & ~mask;
  }

  function concatBytes(parts) {
    var total = 0, i;
    for (i = 0; i < parts.length; i++) total += parts[i].length;
    var out = new Uint8Array(total), off = 0;
    for (i = 0; i < parts.length; i++) { out.set(parts[i], off); off += parts[i].length; }
    return out;
  }

  async function deriveKeys(password, seed) {
    var fp = await corpusFingerprint();
    var salt = concatBytes([new Uint8Array([0x48, 0x47, 0x43, 0x33, fp]), seed]); // 'HGC3'
    var dk = await scrypt(new TextEncoder().encode(password), salt,
                          SCRYPT_N, SCRYPT_R, SCRYPT_P, 64);
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
    var pad = !!opts.pad;
    if (password === undefined) password = null;

    var raw = new TextEncoder().encode(text);

    // 압축 방식 선택. Python과 달리 lzma 후보가 없다 (브라우저에 압축기 없음).
    // 헤더에 방식이 기록되므로 Python 쪽에서 읽는 데는 문제가 없다.
    var mid = 0, body = raw;
    var cands = [];
    if (method === 'auto' || method === 'raw') cands.push([0, raw]);
    if (method === 'auto' || method === 'cm') cands.push([1, cmCompress(raw)]);
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
    if (pad) {
      var inner = concatBytes([varint(payload.length), payload]);
      var unpadded = 1 + seedLen + inner.length + tagLen;
      payload = concatBytes([inner, new Uint8Array(padTarget(unpadded) - unpadded)]);
    }

    var keys = await deriveKeys(pw, seed);
    var ct = chacha20(keys[0], new Uint8Array(12), payload);

    var hdr = new Uint8Array([
      mid | (SEED_OPT.indexOf(seedLen) << 2) | (TAG_OPT.indexOf(tagLen) << 4) |
      (keyed ? 0x40 : 0) | (pad ? 0x80 : 0)
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
    var padded = !!(hdr & 0x80);
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
          '다른 판에서 만든 암호문입니다.');
      }
    }

    var payload = chacha20(keys[0], new Uint8Array(12), ct);
    if (padded) {
      var pv = readVarint(payload, 0);
      if (pv[1] + pv[0] > payload.length) throw new Error('데이터가 잘렸습니다.');
      payload = payload.slice(pv[1], pv[1] + pv[0]);
    }
    var raw;
    if (mid === 0) {
      raw = payload;
    } else {
      var r = readVarint(payload, 0);
      var n = r[0], j = r[1];
      raw = cmDecompress(payload.slice(j), n);
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
    CFG: CFG,
    SCRYPT: { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P },
    scrypt: scrypt,
    padTarget: padTarget,
    _prime: function (cfg) { return newPrimed(cfg); }
  };
});
