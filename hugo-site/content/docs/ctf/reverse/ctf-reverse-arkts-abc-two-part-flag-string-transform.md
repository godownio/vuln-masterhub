---
id: ctf-reverse-arkts-abc-two-part-flag-string-transform
title: ArkTS ABC 双段 flag 逆向：长度偏移+索引递减变换与 Base64 反转，绕过百万次点击门控
type: scenario
domain: ctf
path: ctf/reverse
technique: arkts-abc-two-part-flag-length-offset-index-decrement
tags:
- ctf
- reverse
- harmonyos
- arkts
- abc
- hap
- base64
- string-transform
- ui-gate
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-19
  verified_at: '2026-11-08T12:12:35+08:00'
  notes: 已对照原文核对：img11 确认 hint1='tlfr`llakodZbjW_aR'，img08 确认 magic='NGQ0Yjg0YzIyZjQzNGNjOGNkYTZkZDQ3MDNhZjg5ZGFiODM='，img10 确认 base64 解码+反转得 part2=38bad98fa3074dd6adc8cc434f22c48b4d4，img12 确认 +len/反转/逐字符减下标/再反转变换逻辑，img13 确认 part1=universityofoxford，门控 1000000 次点击见 img03/05/06。脚本与输出完整，PoC 完整。未验证点：脚本未在本机执行。
url: /docs/ctf/reverse/ctf-reverse-arkts-abc-two-part-flag-string-transform/
draft: false
kb_aliases:
- OHCTF easyre
- 点击 1000000 次拿到 flag
- ArkTS 字符串自解码
- reverseStr 双重反转
- HAP 双段 flag
---

## 一句话结论

HarmonyOS 题把 flag 拆成两段分别由客户端常量派生：一段经「逐字符加自身长度 → 整体反转 → 逐字符减下标 → 再整体反转」的可逆变换得到，另一段是「Base64 解码后整体反转」；界面上的「点满 100 万次」只是拼接两段并弹窗的展示条件，只要复刻两条变换即可直接算出完整 flag，无需真去点击。

## 原理

- **结构定位**：HAP 本质是 ZIP，`ets/modules.abc` 是方舟字节码。用带 ABC 插件的反编译器打开后可看到 `pages/Index` 与 `pages/Flag` 两个页面类，flag 的拼装语句只出现在 `Index` 的按钮 `onClick` 回调里，形如 `'The flag is flag{' + router_.getParams().hint1 + x_2_2.getH2(x_2_2.magic) + '}'`，两段的来源分别是页面参数 `hint1` 与页面常量 `magic`。
- **门控的误导性**：回调里先判断 `if (x_2_2.count != 1000000) { 只弹 toast 显示计数 }`，只有等于 100 万才走拼 flag 分支。计数每次点击 `+1`，正常操作不可达。但门控只决定「是否执行拼接并显示」，不改变拼接所用的数据——两段值在页面构造时就已固定，因此门控对逆向不构成障碍。
- **第一段的变换**：外层循环取 `hint1` 每个字符 `charCodeAt(i) + hint1.length`，拼成中间串 `r10`；内层循环对 `reverse(r10)` 逐字符减下标 `i` 得到 `r43`；最后 `pushUrl` 时再传 `reverse(r43)`。整条链是「加常量 → 反转 → 减下标 → 反转」，四步都是逐字符或整体位置的可逆操作，反着做即可：
  `plain = reverse( reverse(plain[i] + len)[i] - i )`。
- **第二段的变换**：`getH2(magic)` → `decodeToString` → `x_1_7(x_1_8(magic))`。`x_1_8` 是标准 Base64 解码，`x_1_7` 把结果从尾到头逐字符拼接，即整体反转。因此第二段就是 `reverse(base64decode(magic))`。
- **为什么成立**：两段的输入（`hint1` 字符串常量、`magic` 常量）都硬编码在 ABC 的字符串常量池中，算法是无密钥的确定性变换；不依赖运行时状态、设备信息或服务端，任何人拿到包都能离线重算。

## 触发条件

- 目标是 HarmonyOS HAP，`ets/modules.abc` 可反编译（未加壳、未做字符串加密）。
- flag 由客户端常量经可逆变换派生，且只用于本地显示/比对。
- 存在「必须满足某 UI 计数/状态才显示」的门控分支，但拼接逻辑静态可读。

## 利用步骤

1. `.hap` 改名为 `.zip` 解压，取出 `ets/modules.abc` 与 `ets/sourceMaps.map`（若有）。
2. 用带 ABC 插件的反编译器（或在线 ABC 反编译服务）得到 ArkTS 伪代码，按 `main_pages.json` 找到入口页 `pages/Index`。
3. 在 `Index` 的按钮回调里定位 flag 拼接串，记下两个数据来源：页面参数 `hint1` 与类常量 `magic`。
4. 回溯 `hint1` 的来源：`pushUrl({url:'pages/Flag', params:{hint1: reverseStr(r43)}})`，再从 `r43` 反推内层循环与 `r10` 的生成规则。
5. 在 `Flag` 页面类里抄出 `hint1` 的初始常量；在 `Index` 里抄出 `magic` 常量。
6. 手写逆变换脚本（先第二段后第一段均可），拼成 `flag{...}`。
7. 若结果出现不可打印字符，重点核对内层循环的下标起点（反编译里常见 `r42 = r42 + 1` 提前自增导致的 off-by-one）与 `reverseStr` 是否被调用两次。

## PoC

```python
import base64

# 第一段：hint1 常量（Flag 页面）
hint1 = "tlfr`llakodZbjW_aR"
r10 = "".join(chr(ord(c) + len(hint1)) for c in hint1)      # 逐字符 + 长度
r43 = "".join(chr(ord(c) - i) for i, c in enumerate(r10[::-1]))  # 反转后逐字符 - 下标
part1 = r43[::-1]

# 第二段：magic 常量经 base64 解码后整体反转
magic = "<MAGIC_CONSTANT_FROM_Index>"
part2 = base64.b64decode(magic)[::-1].decode()

print("flag{" + part1 + part2 + "}")
```

```text
# 本题实际结果
part1 = universityofoxford
part2 = 38bad98fa3074dd6adc8cc434f22c48b4d4
```

## 变体与关联

- 变体：中间串可改成「异或固定字节」「加减下标与长度互换」；反转可换成逆序表置换；Base64 可换成换表或 URL-safe 变体，识别方法是看字母表常量与填充符处理。
- 变体：门控可换成「授权码正确」「倒计时结束」「输入等于某哈希」等，判据不同但 flag 派生逻辑仍然静态，优先读拼接点而不是硬闯门控。
- 关联：[[mobile-harmony-hap-abc-reverse-sourcemaps-workflow]]（HAP/ABC 解包与反编译流程）、[[ctf-reverse-arkts-abc-modified-rc4-addition-rsa-custom-base64]]（同赛事另一题，加密层更复杂）、[[mobile-harmony-hap-abc-xor-hardcoded-secrets]]（ABC 字符串常量提取）。

## 检测与防御

- 本题无服务端攻击面；对真实产品而言，把敏感数据交给客户端变换并不可靠。
- 检测：ABC 中出现 `charCodeAt` 循环、`reverseStr`、`String.fromCharCode` 与硬编码长字符串常量并存，通常是自解码的敏感串；HAP 内 `sourceMaps.map` 未剥离会进一步降低门槛。
- 防御：flag/凭据不下发到客户端；必须下发时由服务端做校验，客户端只做展示；发布构建开启 ABC 混淆与字符串加密，并剥离 sourceMaps。
