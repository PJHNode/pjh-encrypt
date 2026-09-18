import { chromium } from 'playwright';
const ctx = await chromium.launchPersistentContext(process.argv[2]);
const p = await ctx.newPage();
await p.goto('https://pjh-hub.pages.dev/encrypt/');
await p.evaluate(() => navigator.serviceWorker.ready);
const v = await p.evaluate(async () => (await caches.keys()).filter(k => k.startsWith('milseo-')));
let broken = false;
try { await p.reload({ timeout: 15000 }); } catch { broken = true; }
console.log('옛 워커 설치됨:', v.join(','), '| 지금 이 프로필은 망가진 상태인가:', broken);
await ctx.close();
