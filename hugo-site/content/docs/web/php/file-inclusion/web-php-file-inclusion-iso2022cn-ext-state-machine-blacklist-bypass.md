---
id: web-php-file-inclusion-iso2022cn-ext-state-machine-blacklist-bypass
title: ISO-2022-CN-EXT 状态机吞字节绕过路径黑名单：iconv //IGNORE 归一化还原 ../ 路径
type: scenario
domain: web
path: web/php/file-inclusion
technique: iso2022cn-ext-state-machine-iconv-blacklist-bypass
tags:
- php
- file-read
- file-inclusion
- iconv
- iso-2022-cn-ext
- state-machine
- blacklist-bypass
- normalization
- path-traversal
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V158
  verified_at: '2026-11-06T07:33:04+08:00'
  notes: 已对照原文核对：黑名单在 iconv 前检查 rawPath，源编码可控为 ISO-2022-CN-EXT；ESC $)A 装载 GB2312 到 G1、SO 进入双字节、0xXX 0x2e 吞掉一个点、SI 回 ASCII，//IGNORE 丢弃非法双字节后路径还原，属检查/使用字节流不一致。卡已如实限定该构造直接绕过的是连续 .. 检测，原文示例末尾仍含 flag 字面量，若黑名单含 flag 需另行吞字节布局。未验证点：字节布局未本机实测，原文仅给构造示意、未给可执行 PoC；无产品版本信息，未设 versions；frontmatter 无 sources/source_url。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-iso2022cn-ext-state-machine-blacklist-bypass/
draft: false
kb_aliases:
- ISO-2022-CN-EXT 绕过
- iconv 状态机绕过
- GB2312 双字节吞点
- //IGNORE 路径归一化
- iconv TOCTOU 黑名单
- 编码状态机 WAF 绕过
---

## 一句话结论

当 PHP 应用先用正则黑名单检查路径、再用 `iconv($sourceEncoding, "UTF-8//IGNORE", $path)` 归一化并读取文件时，若源编码可控为 `ISO-2022-CN-EXT`，攻击者可在路径中插入转义序列把 `..` 里的一个点吞进双字节字符，使黑名单看不到连续的 `..`；`//IGNORE` 丢弃这个非法双字节字符后，路径又恢复成包含 `../` 的穿越形式，从而实现任意文件读取。

## 原理

- **ISO-2022 是状态机编码**：`ISO-2022-CN-EXT` 用转义序列把不同字符集装载到 G0-G3 槽位，再用 `SO`（`\x0e`）切换到 G1 双字节模式、`SI`（`\x0f`）切回 ASCII。处于双字节模式时，连续两个字节被当作一个字符，ASCII 字节可以被“吞”进双字节字符的低字节位置。
- **黑名单看到的是原始字节**：`preg_match('/\.\./', $rawPath)` 之类的检查在 iconv 之前执行，只认连续的 `0x2e 0x2e`。
- **构造**：`\x1b$)A` 把 GB2312 装载到 G1，`\x0e` 进入双字节模式，随后 `\xXX\x2e` 组成一个双字节字符（其中一个点是 `..` 的第一个点），`\x0f` 切回 ASCII，再跟 `./flag` 或 `../` 的剩余部分。原始字节流里不再出现连续的 `..`，黑名单放行。
- **归一化还原**：如果 `\xXX` 选在 GB2312 首字节范围之外（例如 `0x80-0xA0`），`\xXX\x2e` 不是合法 GB2312 字符；`iconv(..., "UTF-8//IGNORE", ...)` 遇到非法序列时按 `IGNORE` 策略丢弃整个双字节字符，剩下的字节重新拼合，路径恢复为 `../` 或 `/./` 形式，`file_get_contents` 按文件系统语义解析并读到目标文件。
- **为什么成立**：这是典型的“检查者与使用者看到不同字符串”问题——黑名单检查的是转义序列混杂的原始字节流，文件系统看到的是 iconv 状态机解析并清理后的路径。两步之间隔了一层有状态编码转换，且 `//IGNORE` 把“非法输入”变成了“静默删除”。
- **关键词限制**：这个技巧直接解决的是 `..` 的连续点检测；如果黑名单还包含 `flag` 等完整关键词，仅吞一个点不会让 `flag` 消失，仍需对关键词中的字节做单独的吞并/丢弃布局，或改用其他编码/路径。原文示例中的路径末尾仍含 `flag` 字面量，因此只在黑名单仅拦截 `..`（或关键词可另行处理）时成立。

## 触发条件

- PHP 应用把用户可控路径先交给正则/黑名单检查，再交给 `iconv($attackerControlledEncoding, "UTF-8//IGNORE", $path)` 转换，最后用转换结果做 `file_get_contents`/`include`/`fopen`。
- `iconv` 源编码可由攻击者控制（如 Cookie 反序列化属性、请求参数、配置项），且目标环境支持 `ISO-2022-CN-EXT`。
- 路径前缀可控或可穿越到目标文件（例如 `basePath` 可控为 `/`）。
- 黑名单只检查转换前的字符串，且没有对编码转换后的结果再做一次校验。

## 利用步骤

1. 确认路径拼接与检查顺序：`$rawPath = $prefix . $userInput;` → 黑名单 → `iconv(...)` → 文件读取。
2. 确认 `encoding` 可控且目标 PHP/glibc 支持 `ISO-2022-CN-EXT`：提交 `encoding=ISO-2022-CN-EXT`，观察是否仍能正常读取普通文件。
3. 构造 payload：`\x1b$)A`（装载 GB2312）`\x0e`（SO 进入双字节）`\xXX\x2e`（把 `..` 的第一个点吞入非法双字节字符）`\x0f`（SI 回到 ASCII）`./` 或剩余路径。
4. 选择 `\xXX` 使 `\xXX\x2e` 为非法 GB2312 字符（首字节在 `0x80-0xA0` 区间），确保 `//IGNORE` 会丢弃它。
5. 将 payload 放在路径参数中提交；黑名单因看不到连续 `..` 放行，iconv 转换后路径恢复为 `../`，读取目标文件。
6. 若黑名单同时拦截目标文件名关键词，先确认关键词检查是否可被同一状态机技巧拆分，否则改走其他入口或不含该关键词的目标文件。

## PoC

原文给出的路径构造示意（未在本机执行，字节值需按目标 iconv 行为实测）：

```text
rawPath = "/" + "\x1b$)A" + "\x0e" + "\xXX\x2e" + "\x0f" + "./" + "target"
```

- `\x1b$)A`：把 GB2312 装载到 G1；
- `\x0e`：SO，切换到 G1 双字节模式；
- `\xXX\x2e`：`\xXX` 与 `.` 组成一个双字节字符，使原始字节流中不出现连续 `..`；
- `\x0f`：SI，切回 ASCII；
- 后续 `./target` 正常拼接。

```php
// 服务端等价逻辑（示意）
$rawPath = $user->basePath . $f;
if (preg_match('/\.\./', $rawPath)) { exit('denied'); }
$converted = @iconv($user->encoding, 'UTF-8//IGNORE', $rawPath);
echo file_get_contents($converted);
```

Payload 需要 URL 编码后放入 `f` 参数；`encoding` 通过 Cookie 反序列化或参数设为 `ISO-2022-CN-EXT`。实际是否能把 `\xXX\x2e` 完整丢弃、以及 `\x0f` 之后的状态是否符合预期，取决于 glibc/ PHP 的 iconv 实现，需在授权环境验证。

## 变体与关联

- **编码变体**：其他带转义/移位状态机的编码（ISO-2022-JP、ISO-2022-KR、HZ-GB-2312 等）可能提供类似的“吞字节”能力；UTF-7、GBK、UTF-16 也能用非法序列/截断做脏字节绕过。
- **检查点变体**：黑名单在 `iconv` 前、`realpath` 前、WAF 层、路由层；只要检查与使用之间存在一次有损转换，就可能复现。
- **关联卡片**：[[web-php-file-inclusion-iconv-ignore-dirty-byte-waf-bypass]]（UTF-7 脏字节插入关键词的同类“检查后归一化”绕过）；[[web-php-file-inclusion-filter-chain-fileless-rce]]（`php://filter` 链的编码语义利用）。
- **边界**：如果应用先 `iconv` 再检查、或检查与使用同一份转换后字符串，本绕过失效；如果 `encoding` 被固定为 UTF-8，或 `//IGNORE` 被禁用（转换失败直接拒绝），也无法利用；关键词黑名单需另行处理。

## 检测与防御

- **顺序修复**：先做编码归一化，再基于归一化后的字符串做路径校验；校验与文件读取必须使用同一份结果。
- **编码白名单**：不信任客户端传入的 `encoding`，只允许业务需要的固定编码；从白名单移除 ISO-2022 系列等带状态机的编码。
- **禁用宽松转换**：不要使用 `//IGNORE` 静默丢弃非法字节；转换失败直接拒绝请求。
- **路径白名单**：文件名只允许 `[A-Za-z0-9._-]`，拼接后 `realpath` 并用 `commonpath`/前缀检查确保仍在允许目录；不要只依赖关键词黑名单。
- **检测**：请求参数中出现 `%1b`、`%0e`、`%0f` 等 ISO-2022 控制字节；路径参数含非 UTF-8 字节或编码切换序列；同一来源反复提交带 `\x1b$` 的路径；WAF 放行但源站访问路径出现 `../`。
- **响应**：发现利用后检查是否已读取敏感文件，轮换相关凭据，审计所有“过滤后 iconv 再使用”的代码路径。
