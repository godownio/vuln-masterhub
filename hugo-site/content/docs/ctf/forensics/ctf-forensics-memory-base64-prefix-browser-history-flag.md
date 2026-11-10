---
id: ctf-forensics-memory-base64-prefix-browser-history-flag
title: 内存镜像按「flag 前缀的 Base64」搜索：Win10 浏览器搜索历史把 base64(irisctf{...) 当查询词留在内存，grep 即得整段
type: scenario
domain: ctf
path: ctf/forensics
technique: memory-base64-flag-prefix-browser-url-search
tags:
- ctf
- forensics
- memory
- strings
- base64
- browser
- url
- google-search
- windows
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:28:00+08:00'
  notes: 已对照原文核对：strings memdump.mem | grep aXJpc → aXJpc2N0ZntpX2FtX2FuX2lkaW90X3dpdGhfYmFkX21lb 命中、命中行为 Google 搜索 URL、解码得 irisctf{...} 与原文及截图(05/06.png)一致；Base64 锚点已按 3 字节整数倍修正为 irisctf{i -> aXJpc2N0Zntp（原 irisctf{ 8 字节实为 aXJpc2N0Zns=），已核验正确。未验证点：未跑 strings/grep；卡内 flag 只写 irisctf{...} 未抄原文值。注：staging 同名 md 为修正前旧稿，KB 已为准。
url: /docs/ctf/forensics/ctf-forensics-memory-base64-prefix-browser-history-flag/
draft: false
kb_aliases:
- Windy Day
- base64(flag前缀) 内存搜索
- aXJpc2N0Zntp 命中
- 浏览器历史 base64 泄漏 flag
- strings memdump | grep base64
- 内存镜像浏览器取证
---

## 一句话结论

当明文 `flag{...}` 在内存镜像里搜不到（被整体 Base64 过或被程序当数据编码）时，可以先把已知的 flag 外层前缀凑够 3 字节分组（如 `irisctf{i` 共 9 字节）做 Base64，得到 `aXJpc2N0Zntp` 这样的短特征串，再在镜像里 `strings | grep` 这个前缀；一旦命中，命中行往往就是完整的 `base64(flag)`，直接解码即得 flag——本题的泄漏点是浏览器把「被 Base64 的 flag」当成 Google 搜索词，URL 明文留在内存里。

## 原理

- **Base64 是前缀稳定的**：Base64 按 3 字节一组编码，已知明文前缀只有凑满 3 字节的整数倍时，前面的分组才会与后半段无关地固定编码（`irisctf{i` 9 字节 → `aXJpc2N0Zntp`）；若截断在分组中间（如 `irisctf{` 8 字节），最后一个 Base64 字符会因后续字节而异（`aXJpc2N0Zns=`，用于 grep 时宜只取前 8 位 `aXJpc2N0`）。因此锚点取「整分组的前缀」最稳，不必知道完整 flag。
- **内存里留的是完整 URL**：浏览器把搜索词拼进 `https://www.google.com/search?client=firefox-b-d&q=<query>`；若 query 本身是 Base64 串，则整段（含后面的 `...W9yeX0=` 尾串）都以明文存在进程内存/缓存中。镜像里 `strings` 直接可见，甚至能看到同一串被反复写入（缓存/历史多条）。
- **为什么先猜编码**：现代浏览器在内存中保留的是完整 URL 文本；做题时若直接 `grep irisctf{` 无命中，下一步应尝试常见编码：Base64、URL 编码、hex、gzip；Base64 前缀是最省事的一种（无需还原上下文）。
- **为什么比 vol3 插件快**：Volatility 插件依赖符号与 profile，对只有 memdump 的题目常「看不出东西」；`strings` + 编码前缀 grep 是零依赖的第一步筛查，命中后再用取证工具（如 Axiom）定位来源进程/时间线即可。
- **可复用点**：把「已知外层前缀 → 计算其 Base64/URL 编码形式 → 用作内存搜索锚点」做成固定动作，可套用到任何「flag 被编码后落在内存」的题。

## 触发条件

- 拿到 Windows/Linux 内存镜像（raw/dmp/mem），可直接用 `strings` 读取。
- flag 有已知外层格式前缀（CTF 常见 `xxx{`），且被 Base64 等编码后留在内存。
- 镜像里存在浏览器搜索结果页 URL、剪贴板、编辑器缓存等把该串当文本保存的位置。

## 利用步骤

1. 先用最直接的明文搜索做对照：`strings memdump.mem | grep "irisctf{"`。
2. 无命中时，把外层前缀填到 3 字节整数倍（如 `irisctf{i` 9 字节）做 Base64：`printf 'irisctf{i' | base64` → `aXJpc2N0Zntp`（注意去掉换行；只截到 `irisctf{` 时得到的是 `aXJpc2N0Zns=`，末尾字符会被后续字节影响）。
3. 用该前缀搜索内存：`strings memdump.mem | grep "aXJpc"`，观察命中行是否是可打印的 Base64 长串。
4. 逐步加长锚点（如 `aXJpc2N0ZntpX2FtX2FuX2lkaW90`）缩小到唯一命中行，减少误报。
5. 把命中行里属于 Base64 的部分（去掉前后 URL 参数噪声）取出，`base64 -d` 解码得到完整 flag。
6. 需要溯源时再用取证工具（Axiom/Volatility）按命中串查来源：本题命中为 Google 搜索 URL，时间线与浏览器进程可还原。

## PoC

```bash
# 1) 明文对照（本题无命中）
strings memdump.mem | grep "irisctf{"

# 2) 计算前缀的 Base64（取到 3 字节整数倍，9 字节 irisctf{i）
printf 'irisctf{i' | base64          # -> aXJpc2N0Zntp

# 3) 用编码前缀做锚点
strings memdump.mem | grep "aXJpc"

# 4) 加长锚点收敛
strings memdump.mem | grep "aXJpc2N0ZntpX2FtX2FuX2lkaW90X3dpdGhfYmFkX21lb"

# 5) 解码
echo '<命中的Base64串>' | base64 -d
```

命中行形态（原文截图，浏览器搜索 URL）：

```text
https://www.google.com/search?client=firefox-b-d&q=aXJpc2N0ZntpX2FtX2FuX2lkaW90X3dpdGhfYmFkX21lbW9yeX0=
```

解码结果：

```text
irisctf{i_am_an_idiot_with_bad_memory}
```

PoC 未在本机执行；flag 为原文靶场数据。

## 变体与关联

- **编码变体**：URL 编码（`irisctf%7B`）、hex（`697269736374667b`）、gzip/deflate 压缩后的串、UTF-16LE 双字节排列；对同一前缀分别生成这些形态轮流 grep，成本很低。
- **载体变体**：剪贴板、编辑器未保存缓冲区、HTTP 请求体、聊天软件缓存、DNS 查询（base32/hex）；命中位置决定后续溯源方向。
- **长前缀技巧**：CTF flag 内层常见由下划线连接的英文短语，可先用 `aXJpc2N0Znt`（只到 `{`）粗筛，再用「命中行长度」筛选出完整串。
- **关联**：[[ctf-forensics-memory-image-flag-keyword-search]]（明文/多编码关键词搜索，本卡是「明文搜不到时的编码前缀」补充）、[[ctf-forensics-chrome-heap-snapshot-flag-search]]（浏览器侧另一种载体：DevTools 堆快照）、[[ctf-forensics-pcap-shell-history-base64-nc-image-exfil]]（Base64 外传 + 图片尾部署 flag 的流量版本）。
- **边界**：flag 若被加密（非编码）或只以分片形式存在，前缀搜索无效；镜像若被压缩/分页换出，命中可能不完整；`strings` 默认最小长度 4，短锚点会引入大量噪声。

## 检测与防御

- 本卡是取证侧技巧。对应的防御/检测视角：敏感数据不应以 Base64「假脱敏」形式进入 URL/日志/剪贴板——Base64 不是加密，应改用真正的加密与密钥隔离。
- 蓝队可对终端内存与浏览器历史做敏感数据扫描（用已知前缀的编码形态做规则），并把「flag/密钥被当作搜索词」视为数据外泄信号。
