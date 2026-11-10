---
id: web-php-file-inclusion-php-filter-bucket-brigade-dechunk-sizing
title: php://filter 桶队尺寸控制：zlib.inflate 生成多桶 + dechunk 每桶前置尺寸与零填充，使 0x100 等指定大小的 bucket 按需出现
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-filter-bucket-brigade-dechunk-size-control
aliases:
- PHP filter bucket brigade
- 桶队尺寸控制
- dechunk 分桶
- zlib.inflate 多 bucket
- dechunk 俄罗斯套娃
- php://filter 堆风水
- CVE-2024-2961 前置
tags:
- php
- filter
- php-filter
- bucket-brigade
- dechunk
- zlib-inflate
- heap-shaping
- cve-2024-2961
- file-inclusion
cve:
- CVE-2024-2961
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V364
  verified_at: '2026-11-09T03:36:13+08:00'
  notes: 已对照原文全文与图01-09核对：bucket brigade 与三桶 0x5/0x1e/0x3e8、string.upper 逐桶转换、zlib.inflate 把 0x937 单桶膨胀为 4 个 0x8000 桶、HTTP-chunked 8/11/d/0 示例、朴素 dechunk 遇终止 0 只剩桶1、每桶零填充+桶尾尺寸+数据使四桶变为 0x148/0x100/0xa0/0x30、俄罗斯套娃桶内嵌 0x108/0x100/0xf0 多组尺寸、0x100 块 LSB=0 时单字节溢出将其加 0x48 控制空闲链表，均与原文及图示一致。CVE-2024-2961 主链已有 verified 卡，本卡仅为其前置桶尺寸原语，不重复，未拆分。未验证点：未实际运行过滤器链；dechunk 是否保留底层 0x8000 缓冲、convert.iconv.latin1.latin1 作为按长度重分配过滤器的具体行为为按 PHP 实现推断（文章未展开），PoC 的 0x7f00 填充与桶边界需按真实实现校准；PHP 7.0.0-8.3.7 是整条 exploit 的适用范围而非本原语受影响版本，已 set-versions --clear。cve 字段标 CVE-2024-2961 属下游关联（库内主链卡 cve 为空，建议后续统一，不影响本卡结论）。dedup 首候选为自身 exact，两条 related 均为 filter chain 内容构造用法，非同一原语；dup-scan.json（2026-11-08 19:10）早于建卡且无本卡 pair；无 sources/文章 ID/URL，path web/php/file-inclusion 合法。
---

## 一句话结论

`php://filter` 在过滤流时把数据表示为 bucket brigade，每个 bucket 有自己的缓冲区大小；单个文件/HTTP 响应通常只产生一个 bucket，`zlib.inflate` 可以把一个输入桶解压成多个 0x8000 的桶，而 `dechunk` 能按 HTTP-chunked 语法把 bucket 的“有效长度”改成任意值，但它遇到长度为 0 的 chunk 会停止解析后续桶。利用“每个桶里先填大量零、把目标尺寸放在桶尾再跟数据”的布局，可以让 dechunk 跨桶继续解析，从而给每个桶单独指定大小（如 0x100/0x148/0xf0），并在多轮 dechunk 中让不同大小的桶按需“显形”或消失——这是把单字节溢出（CVE-2024-2961）升级为堆风水/RCE 的关键前置原语。

## 原理

- **bucket brigade**：PHP 读取资源后把流内容切成若干 bucket（双向链表），每个 bucket 有缓冲区与有效长度；过滤器对每个输入 bucket 分配同样大小的输出缓冲区，转换后生成新的 bucket 链。常规文件读取/HTTP/FTP 只产生一个包含全部内容的 bucket，攻击者无法用它做堆填充或控制空闲链表。
- **zlib.inflate 制造多桶**：`zlib.inflate` 把输入流解压到一个 8 页（0x8000）缓冲区；不够时再分配新的 0x8000 块，每块成为一个 bucket。于是一个压缩流可以产生任意数量的 0x8000 bucket（但 0x8000 大小不利于精确堆风水，且释放后不进入常规小空闲链表）。
- **dechunk 调整桶有效长度**：`dechunk` 按 HTTP-chunked 格式解析：十六进制大小 + CRLF + 数据 + CRLF，遇到大小为 0 的 chunk 就结束。它会把一个 bucket 的有效长度改成第一个 chunk 指定的大小，从而“缩小”bucket 而保留底层 0x8000 分配；但若桶 1 末尾就是 `0` 终止符，解析停止，桶 2/3/4 会被丢弃，退回单桶。
- **跨桶续接技巧**：在每个 0x8000 桶中，先放大量 `0` 字符（ASCII 0x30，不是 chunk 终止的二进制 0）填充到桶尾附近，再放目标十六进制尺寸 + CRLF + 数据 + CRLF。dechunk 在桶 1 里读到一个 chunk 后不会遇到终止大小 0（因为填充的是字符 '0'，且尺寸字段在桶尾），解析沿流进入桶 2，继续读下一个尺寸，依此类推；最终每个桶被赋予各自指定的大小。
- **俄罗斯套娃**：每次 dechunk 都重新解释同一段流，桶大小随每轮前缀尺寸变化；某些轮次桶变成 0x100（在堆风水中“显形”为可分配/可释放块），另一些轮次变成更小的尺寸（从视野中“消失”）。这样在固定的过滤器链里可以对同一批桶在不同利用步骤中呈现不同大小，满足“分配指定大小 + 释放指定块”的堆布局需求。
- **与 convert.iconv 配合**：`convert.iconv.latin1.latin1` 等按有效长度重新分配并释放旧块；dechunk 改变有效长度后，后续过滤器会按新长度分配/释放，从而把受控 bucket 变成 0x100 等目标大小的空闲块，供 CVE-2024-2961 的 1 字节溢出改写其 `next_free_slot` 指针。
- **为什么必须 0x100**：PHP 空闲链表中 0x100 块的地址最低字节恒为 0，单字节溢出把 LSB 改成固定值（如 0x48）时效果确定（指针加 0x48），不依赖随机地址；其他尺寸没有这个性质。

## 触发条件

- 目标存在可控制 `php://filter` 过滤链的入口（LFI/文件读取/包含、文件写入、解析库读取 URL 等），且 PHP 支持 `zlib.inflate`、`dechunk`、`convert.iconv` 过滤器。
- 攻击者能控制流内容（例如 `data://`、上传的压缩文件、HTTP 响应、或 `php://temp` 空流 + 过滤器生成内容）。
- 需要 PHP 7/8 的 bucket brigade 行为与过滤器实现（不同版本细节可能不同，需实测）。
- 目标 glibc 存在 CVE-2024-2961（作为该原语的下游利用），或另有需要按大小分配/释放堆块的场景。

## 利用步骤

1. **构造多桶**：先让流经过 `zlib.inflate`，把压缩数据解压成 N 个 0x8000 的 bucket。
2. **给每个桶加尺寸前缀**：在每个 0x8000 桶内，从桶头开始填大量 ASCII `'0'`，把目标十六进制尺寸放在桶尾附近，再放该尺寸的数据和 CRLF；尺寸之间用数据隔开，避免在桶 1 出现终止 chunk。
3. **接 dechunk**：`dechunk` 解析跨桶流，使 bucket #1/#2/#3/#4 的有效长度分别变成 0x148/0x100/0xa0/0x30 等指定值；验证方式是在后续过滤器输出/`get_headers` 类行为中观察 bucket 大小。
4. **按需显形**：对不同利用步骤准备不同的尺寸序列（俄罗斯套娃），让 0x100 桶在需要时出现；再用 `convert.iconv.latin1.latin1` 等按有效长度重分配/释放，把桶变成目标大小的空闲块。
5. **续接堆利用**：在 0x100 空闲块上执行 CVE-2024-2961 的单字节溢出（`convert.iconv.UTF-8.ISO-2022-CN-EXT` 触发），改写 `next_free_slot`，最终劫持 `_zend_mm_heap.custom_heap._free` 等函数指针。

## PoC

```text
# 概念布局（每个 0x8000 bucket 内部）：
#   '0' * padding  +  "<hex-size>\r\n" + data + "\r\n"
# 压缩后经 php://filter 链：
php://filter/zlib.inflate|dechunk|convert.iconv.latin1.latin1|.../resource=data:,<zlib-compressed stream>
```

```python
# 生成示意：为多个 bucket 各自指定 chunk 尺寸
def bucket_payload(size_hex: str, data: bytes, pad: int = 0x7f00) -> bytes:
    # 大量 ASCII '0' 填充，使解析器不会在本桶遇到终止 chunk
    return b"0" * pad + size_hex.encode() + b"\r\n" + data + b"\r\n"

stream = b"".join([
    bucket_payload("148", b"A" * 0x148),
    bucket_payload("100", b"B" * 0x100),
    bucket_payload("a0",  b"C" * 0xa0),
    bucket_payload("30",  b"D" * 0x30),
])
# zlib.compress(stream) 后作为 data: 资源或上传文件喂给 php://filter/zlib.inflate|dechunk
```

完整利用需结合目标 PHP 版本的过滤器实现与 glibc 溢出，见关联 CVE 卡。

## 变体与关联

- **CVE-2024-2961 主链**：单字节溢出 + Zend MM `free_slot` 劫持 + `_zend_mm_heap.custom_heap._free = system`，见 [[web-php-rce-glibc-iconv-iso2022cn-ext-heap-overflow-cve-2024-2961]]。
- **PHP filter chain 无文件 RCE**：用 `convert.iconv` 注入 + base64 提纯在内存构造 PHP 代码，见 [[web-php-file-inclusion-filter-chain-fileless-rce]]；本卡的桶队控制可与 filter chain 组合做更精确的堆布局。
- **dechunk 其他用途**：绕过内容长度检查、改变流有效长度以触发过滤器重分配；桶大小控制也可用于其他依赖 Zend MM 大小类的漏洞。
- **边界**：桶大小与 PHP 版本/过滤器实现相关；0x8000 是 zlib.inflate 的默认块大小，若目标版本不同需重新确认；dechunk 的 CRLF 与大小解析必须精确，否则解析提前终止。

## 检测与防御

- **检测**：HTTP 参数中出现长 `php://filter` 链、连续 `convert.iconv`/`zlib.inflate`/`dechunk`；请求体/资源为高压缩比数据且包含大量 `0` 填充与十六进制尺寸字段；PHP 进程堆异常。
- **防御**：禁用不必要的 `php://filter`/`zlib.inflate`/`dechunk` 过滤器（`disable_functions` 无法禁用过滤器，需在应用层白名单协议）；禁止用户控制过滤链；及时更新 glibc（CVE-2024-2961 修复）与 PHP。
- **加固**：文件读取接口只允许固定路径/协议，不允许 `php://`；对传入的 filter 名称做白名单；升级到修复后的 glibc/PHP 组合。
