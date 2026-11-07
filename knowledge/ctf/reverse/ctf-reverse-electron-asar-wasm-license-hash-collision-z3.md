---
id: ctf-reverse-electron-asar-wasm-license-hash-collision-z3
title: Electron asar + Rust WASM 许可证校验：32 位滚动哈希碰撞 + Z3 联立解锁输出约束
type: scenario
domain: ctf
path: ctf/reverse
technique: electron-asar-wasm-license-hash-collision-z3
aliases:
- PAY-FOR-2048
- app.asar 解包
- wasm_core.wasm
- verify_license
- unlock_flag
- 32 位滚动哈希碰撞
- Z3 联立约束
- Electron WASM 逆向
tags:
- reverse
- electron
- asar
- wasm
- rust
- hash-collision
- z3
- license
- ctf
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:12:59+08:00'
  notes: 已对照原文核对：app.asar/wasm_core.wasm、verify_license/unlock_flag、32 位滚动哈希碰撞、Z3 联立 unlock 输出格式约束均一致；卡内已注明原文脚本额外使用部分已知 UUID 段收敛，且 PoC 省略这些段时可能解出不同合法格式 key，confidence=medium 合理；原文无图片；未实际运行。
---

## 一句话结论

Electron 游戏把 License 校验和 Flag 解锁拆成 `verify_license` / `unlock_flag` 两个 WASM 导出函数：`verify` 只做 32 位滚动哈希，存在大量碰撞，能通过校验的 key 不一定是正确 key；必须把 `unlock_flag` 的异或流解密结果同时约束成 flag 格式（`NCTF{...}`、UUID 分段、十六进制字符），用 Z3 联立哈希约束与输出约束，才能从碰撞集合中解出真正能解出 flag 的 key。

## 原理

- Electron 应用的核心逻辑通常在 `resources/app.asar` 中；asar 头部是 JSON 索引，不是加密格式，用 `npx asar extract` 或解析头部即可取出 `src/game-controller.js`、`src/license-service.js`、`src/wasm-bridge.js` 与 `wasm-build/.../wasm_core.wasm`。
- `wasm-bridge.js` 暴露两个导出：`verify_license` 与 `unlock_flag`。`game-controller.js` 在分数达到 256 时要求输入 key 并调用 verify；达到 2048 后调用 unlock。上下文包含 key、score、steps、maxTile、board、sessionToken。
- WASM 内部函数（wat 中可见）：`normalize_key`、`verify_license_impl`、`build_session_token`、`unlock_flag_impl`。
  - verify：检查 `maxTile >= 256`；key 格式 `NCTF-XXXX-XXXX-XXXX`；normalize 去掉前缀和短横线得到 12 字符；对 12 字符做 32 位滚动哈希，等于固定常量才通过；通过后返回 `sessionToken`。
  - unlock：检查 `maxTile >= 2048`；重新计算并比对 `sessionToken`；再次 normalize key；以 `normalized_key + "|" + "arcade::unlock-seed"` 为输入做异或流解密，输出 flag。
- **碰撞点**：verify 的哈希只有 32 位，12 个字符（0-9A-Z）空间远大于 2^32，必然存在大量碰撞。文章先用哈希方程求出一个能过 verify 的 key（如 `NCTF-NYOY-6GD8-6MLP`），但 unlock 返回乱码，说明 verify 通过不等于 key 正确。
- **联立求解**：把 verify 的哈希常量约束，与 unlock 输出必须满足的 flag 格式约束（`NCTF{` 开头、UUID 分段、十六进制字符、`}` 结尾）同时交给 Z3；解出的 normalized key 才能让异或流输出合法 flag。文章脚本还把部分 UUID 段（`c4f2`、`4dbb`、`b270`、`f5d`）作为已知约束，进一步收敛解空间。
- 根因是“用短哈希做许可证校验 + 解锁逻辑只依赖同一个 key”；只验哈希不验解锁输出，就会接受碰撞 key。

## 触发条件

- 目标是 Electron 应用，核心校验在 asar 内的 JS + WASM。
- WASM 导出 verify/unlock 两个阶段，verify 使用短哈希（32 位或更短）且无签名/服务端校验。
- unlock 的输出由 key 派生的流密码/异或流决定，输出格式可被约束（flag 前缀、UUID、hex 字符）。
- 允许解包 asar、反编译 WASM、用 Z3/符号执行求解（CTF/授权逆向场景）。

## 利用步骤

1. 解包 `resources/app.asar`：`npx asar extract app.asar app_unpacked`，查看 `package.json`、`src/*.js`、`wasm-build/.../wasm_core.wasm`。
2. 阅读 `wasm-bridge.js`/`game-controller.js`，确认 verify/unlock 的调用条件、上下文字段与 key 格式。
3. 用 `wasm2wat` 或 Ghidra/WASM 插件反编译 `wasm_core.wasm`，恢复 `normalize_key`、`verify_license_impl`、`build_session_token`、`unlock_flag_impl`。
4. 提炼 verify 的 32 位滚动哈希更新式与最终常量；提炼 unlock 的异或流公式（输入为 normalized key + `|` + seed，逐字节 XOR 掩码与常量数组）。
5. 先用哈希约束求一个碰撞 key，调用 unlock 验证是否返回合法 flag；若为乱码，说明需要输出约束。
6. 用 Z3 建立 12 个 8 位变量，加入字符集约束、哈希约束、unlock 输出格式约束；求解 normalized key，再拼成 `NCTF-XXXX-XXXX-XXXX`。
7. 调用 verify 拿 sessionToken，再调用 unlock（maxTile=2048）验证返回 flag。

## PoC

```python
from z3 import *

norm = [BitVec(f"n{i}", 8) for i in range(12)]
s = Solver()
for c in norm:
    s.add(Or(And(c >= ord("0"), c <= ord("9")), And(c >= ord("A"), c <= ord("Z"))))

# verify：32 位滚动哈希（常量与更新式按目标 WASM 填入）
K = BitVecVal((-1515890086) & 0xffffffff, 32)
p = BitVecVal(4951, 32)
for i in range(12):
    c = ZeroExt(24, norm[i])
    t = BitVecVal(40503 if (i & 1) else 17881, 32)
    v = (t + c) * BitVecVal(i + 11, 32)
    v = v ^ RotateLeft(p, 3)
    v = v + ((c << (i % 5)) ^ K)
    p = Extract(31, 0, v)
s.add(p == BitVecVal((-57161169) & 0xffffffff, 32))

# unlock：inp = norm + b"|" + b"arcade::unlock-seed"
seed = b"arcade::unlock-seed"
const = [13, 56, 42, 25, 169, 244, 236, 247, 250, 16, 53, 94, 39, 198, 182, 147,
         230, 168, 83, 54, 11, 101, 131, 237, 196, 183, 95, 61, 99, 89, 39, 148,
         134, 255, 231, 15, 66, 20, 95, 5, 200, 251]
inp = list(norm) + [BitVecVal(ord("|"), 8)] + [BitVecVal(b, 8) for b in seed]

for i in range(42):
    out = inp[i % 32] ^ BitVecVal((i * 29 + 17) & 0xff, 8) ^ BitVecVal(const[i], 8)
    if i < 5:
        s.add(out == b"NCTF{"[i])
    elif i == 13 or i == 18 or i == 23 or i == 28:
        s.add(out == ord("-"))
    elif i == 41:
        s.add(out == ord("}"))
    else:
        s.add(Or(And(out >= ord("0"), out <= ord("9")),
                 And(out >= ord("a"), out <= ord("f"))))

assert s.check() == sat
m = s.model()
norm_s = "".join(chr(m[c].as_long()) for c in norm)
print("KEY =", f"NCTF-{norm_s[:4]}-{norm_s[4:8]}-{norm_s[8:]}")
```

说明：文章脚本还把若干 UUID 段作为已知常量加入约束；若没有这些已知段，可以只保留 hex/分段约束，或枚举 32 位碰撞集合逐个调用 unlock。

## 变体与关联

- **WASM 变体**：Rust/C++ 编译的 WASM、wasm-bindgen、Emscripten；导出名可能被混淆，但字符串/调用关系仍可恢复。
- **哈希变体**：32 位滚动哈希、CRC32、FNV、自定义 hash；短哈希都可能碰撞，关键是找到“第二阶段的输出约束”。
- **求解变体**：Z3、angr、Unicorn 仿真、逐字节枚举；若解锁输出没有可利用格式，可能需要动态跟踪 WASM 内存。
- **关联**：[[ctf-reverse-z3-constraint-equation-solve]]（Z3 约束求解基础）；[[ctf-reverse-android-ue-pak-encrypted-wasm-native-vm-co-simulation]]（WASM/原生协同逆向的另一场景）；[[ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery]]（自定义 VM 的逆执行思路）。
- **边界**：若 verify 使用服务端签名/非对称校验，或 unlock 需要服务端 sessionToken，纯客户端 Z3 求解不成立。

## 检测与防御

- **检测**：Electron 应用中出现 `app.asar`、`wasm_core.wasm`、`verify_license`/`unlock_flag` 导出；WASM 中存在短哈希常量与异或流；客户端可离线通过 license 校验。
- **防御**：许可证校验放服务端，使用非对称签名/短期令牌；不要仅用 32 位哈希做授权；unlock 逻辑依赖服务端下发的密钥/令牌。
- **加固**：WASM 混淆、字符串加密只能提高成本；关键授权必须由服务端裁决。
