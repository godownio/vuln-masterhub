---
id: ctf-web-wasm-client-game-logic-tamper-proof-forgery
title: 客户端 Wasm 游戏逻辑篡改：改 Minimax 比较或伪造棋盘与 proof 绕过服务端校验
type: scenario
domain: ctf
path: ctf/web
technique: wasm-client-game-logic-tamper-proof-forgery
aliases:
- Wasm 篡改
- Minimax 篡改
- 本地替换 Wasm
- updateProof 伪造
- 客户端校验绕过
- 井字棋 AI 绕过
tags:
- ctf
- web
- wasm
- client-side
- minimax
- game
- proof
- devtools
- local-override
- memory-tampering
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V151
  verified_at: '2026-11-06T07:40:37+08:00'
  notes: 已对照原文与6张图核对：Go/Wasm 客户端井字棋、wasm2wat 定位 main.minimax、-10000→10000 与 i64.lt_s→i64.gt_s、wat2wasm+DevTools Overrides 替换（图02 SUCCESS/ACCESS GRANTED ttt:1q2w3e4r@Dashazi）、控制台重置 board/moves 并逐步 updateProof+handleWin（图04 输出获胜棋谱与凭据）、服务端只校验 proof 不校验落子来源均与原文一致；图03 SVG 的 POST /win 字段亦吻合。未验证点：未在本机复跑靶机；CTF 无组件版本，不设 affected_versions。
---

## 一句话结论

当井字棋/小游戏的 AI 与胜负判定在浏览器端的 Go/Wasm 中执行、服务端只校验客户端提交的走法与 proof 时，攻击者可以用 `wasm2wat` 改掉 Minimax 的初始分数与比较方向并本地替换 `main.wasm`，或直接在控制台篡改 Wasm/JS 共享状态、调用 `updateProof` 伪造合法凭证；服务端不重算棋局，最终返回用户凭据。

## 原理

- **信任边界错位**：页面把游戏逻辑编译成 `main.wasm` 在浏览器执行，服务端只在 `/init` 下发 `session_id` 和 `seed`，在 `/win` 接收 `{id, moves, proof}` 并校验 proof 合法性。服务端没有权威棋局状态，也不验证走法是否真的来自实际对局。
- **方法一：静态篡改 Wasm**
  - `wasm2wat main.wasm -o main.wat` 把二进制转为 WAT；Go 编译的 Wasm 业务函数以 `main.` 为前缀，可定位 `main.minimax`、`main.getAIMove`、`main.updateProof` 等。
  - Minimax 中 AI 是最大化者：初始最高分 `i64.const -10000`，比较用 `i64.lt_s`（新分数是否大于当前最高分）。把初始值改成 `i64.const 10000`、比较改成 `i64.gt_s`，AI 就从“找最高分”变成“找最低分”，主动走输棋。
  - `wat2wasm main.wat -o main_patched.wasm`；Chrome DevTools → Sources → Overrides（本地替换）把原 `main.wasm` 替换为补丁文件，刷新后 AI 策略失效，随意落子即可获胜，服务端接受 proof 并返回凭据。
- **方法二：动态篡改内存/调用导出函数**
  - Go 的 `wasm_exec.js` 把实例挂在 `go._inst`，Wasm 线性内存与 JS 共享；控制台可直接重置 `board`/`moves`/`gameOver` 等 JS 全局状态。
  - 构造一条交替落子、最终玩家 1 获胜的 `winningMoves`；对每一步调用 Wasm 导出的 `updateProof(pos, index)` 生成合法 proof，更新 UI 并调用 `handleWin()` 提交。
  - 因为 `updateProof` 只根据位置/序号计算证明，不校验“这一步是不是 AI/玩家真实下的”，伪造的棋谱同样能生成通过服务端校验的 proof。
- **根因**：proof 证明的是“这组走法在密码学/格式上有效”，而不是“这组走法来自真实对局”。客户端代码、内存和 proof 生成函数都在攻击者控制下，任何只依赖客户端计算的胜负/凭证都不构成安全边界。
- 原文还列出进阶路线：完整逆出 `updateProof` 算法直接构造棋谱与 proof；或反编译 Wasm 后模拟服务端 flag 校验逻辑；或劫持 AI 生成的 proof 复用（本题禁用，同类题可复用）。

## 触发条件

- Web 应用把游戏/AI 决策/胜负判定放在客户端 Wasm（或 JS）执行；
- 服务端只接收并校验 `moves` + `proof`，不重算棋局、不校验落子来源；
- 攻击者能使用浏览器 DevTools（本地替换、控制台）或直接构造 `/win` 请求；
- proof 生成函数可在客户端调用，或算法可逆向/复用。

## 利用步骤

1. 抓包/看前端代码，确认 `main.wasm` 负责 `initGame`、`getAIMove`、`minimax`、`updateProof`、`checkWinner`，服务端只做 proof 校验。
2. **改 Wasm**：`wasm2wat` 转 WAT，定位 `main.minimax` 中 `i64.const -10000` 与 `i64.lt_s`；改为 `10000` 与 `i64.gt_s`；`wat2wasm` 回二进制；DevTools Overrides 替换 `main.wasm`，刷新后正常落子获胜。
3. **或改内存**：控制台获取 `go._inst`，重置棋盘/走法/胜负标志，按预设获胜序列写入 `board`，逐步调用 `updateProof`，再调用 `handleWin()` 让页面走正常提交逻辑。
4. 读取页面返回的凭据（案例 `ttt:1q2w3e4r@Dashazi`），用于 SSH 登录。
5. 若需要，直接构造 `POST /win`，携带 `id`、`moves`、`proof`，跳过 UI。

## PoC

```bash
wasm2wat main.wasm -o main.wat
# 修改 main.minimax：
#   i64.const -10000  -> i64.const 10000
#   i64.lt_s          -> i64.gt_s
wat2wasm main.wat -o main_patched.wasm
# DevTools -> Sources -> Overrides -> 用 main_patched.wasm 替换 main.wasm -> 刷新
```

```javascript
// 控制台：伪造棋盘 + 合法 proof
(async () => {
  await new Promise(r => setTimeout(r, 1000));
  const wasmInstance = go._inst;
  const mem = new Uint8Array(wasmInstance.exports.mem.buffer);

  board = [0,0,0,0,0,0,0,0,0];
  moves = [];
  gameOver = false;
  isPlayerTurn = true;

  const winningMoves = [
    {pos:0, player:1}, {pos:1, player:2}, {pos:4, player:1},
    {pos:3, player:2}, {pos:6, player:1}, {pos:5, player:2},
    {pos:2, player:1}
  ];

  for (let i = 0; i < winningMoves.length; i++) {
    const m = winningMoves[i];
    board[m.pos] = m.player;
    moves.push(m.pos);
    updateProof(m.pos, i);          // 生成服务端可接受的 proof
  }
  updateUI();
  if (checkWin(1)) await handleWin();
})();
```

## 变体与关联

- 变体：改 JS 里的 AI 函数而不是 Wasm；Hook `fetch`/XHR 直接改 `/win` 请求体；重放 AI 生成的 proof；完整逆向 proof 算法离线生成。
- 关联 [[web-generic-wasm-exported-memory-secret-read]] 与 [[web-generic-wasm-unchecked-index-linear-memory-write]]：同样利用 Wasm 线性内存/导出函数缺少边界或信任，本卡是“客户端逻辑可篡改”的信任问题。
- 关联 [[ctf-web-service-worker-double-decode-scope-navigation-preload]]：都是浏览器端逻辑/状态被攻击者控制后绕过服务端预期。
- 关联 [[ctf-web-unsigned-role-cookie-md5-magic-hash-ssrf-loopback]]：都是客户端可控状态被服务端信任导致的越权。
- 边界：服务端若保存权威棋局、逐步校验走法合法性、对 Move/Proof 做服务端重算或 HMAC 绑定会话与序号，单纯改客户端会失效；Go/Wasm 混淆/加密会增加静态篡改成本，但不改变信任边界问题。

## 检测与防御

- 服务端必须保存权威状态：每步落子校验轮次、位置合法性、胜负；不接受客户端一次性提交的完整棋谱作为事实。
- Proof 只作为完整性校验，不等于来源证明：应把 proof 与会话、序号、服务端记录的棋盘状态绑定，或用服务端密钥对每步签名。
- 关键判定（胜负、发奖、凭证）全部服务端重算；客户端只负责展示。
- 检测：同一 session 的 moves 与 proof 生成速度/顺序异常、同一 proof 重复使用、客户端提交的走法不符合 AI 策略或落子轮次、DevTools Overrides/本地文件替换难以直接检测但可通过资源哈希校验发现。
- 防护：对 Wasm/JS 资源做 SRI/哈希校验只能提高篡改成本，不能替代服务端权威校验。
