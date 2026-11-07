---
id: web-generic-http-smuggling-gzip-multi-member-decompression-differential
title: 多成员 gzip 请求体解压范围错位：网关校验首 member、后端执行全部 member
type: scenario
domain: web
path: web/generic/http-smuggling
technique: gzip-multi-member-decompression-differential
aliases:
- gzip 多 member 解压差异
- gzip member drift
- Content-Encoding gzip 走私
- 解压范围错位
- 首 member 校验绕过
- zlib unused_data 参数覆盖
tags:
- gzip
- zlib
- content-encoding
- parser-differential
- request-smuggling
- waf-bypass
- authorization-bypass
- http
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V1
  verified_at: '2026-11-04T21:53:51+08:00'
  notes: 已对照原文与 9 张图片核对；未在真实网关复跑，Java 全量解压行为按原文记录
---

## 一句话结论

把两个合法 gzip member 直接拼接成一个 `Content-Encoding: gzip` 请求体：只解压首个 member 的网关/WAF 看到的是 `mode=read` 并放行，而后端全量解压得到的 `mode=read&...&mode=write` 由末个同名参数覆盖，最终执行 `write`，检查点与执行点使用了两份不同的明文。

## 原理

RFC 1952 的 gzip 是连续 member 的序列：每个 member 由 10 字节固定头、压缩块和 8 字节 trailer（CRC32 + ISIZE，小端）组成，member 之间没有分隔符，前一个 trailer 结束处就是下一个 `1f 8b 08` 头的开始。多个完整 member 首尾相接是合法 gzip 数据。

zlib 的 `inflate()` 在 gzip 窗口（`16 + MAX_WBITS`）下读完第一个 member 的 trailer 就返回 `Z_STREAM_END`，不会自动继续解析第二个 member；剩余字节留在 `avail_in` / `next_in`。CPython 的 `zlib.decompressobj` 同样在首个 member 结束时把未消费输入存进 `unused_data` 并置 `eof=True`。关键是：`eof` 只表示“当前 member 正常结束”，不表示“输入缓冲已消费完”；`unused_data` 非空就说明后面还有 content。

相反，`gzip.decompress()`、部分 `GZIPInputStream` 实现会把所有 member 连续解压成一份明文。于是同一份网络字节出现两种视图：

- 网关视图：首个 member 明文 `mode=read&report=monthly`，校验通过；
- 后端视图：完整明文 `mode=read&report=monthly&mode=write`，按出现顺序解析同名参数，后者覆盖前者，业务动作变为 `write`。

这不是参数校验写漏，而是授权判断和业务执行没有共享同一份解压结果。压缩编码本身没有改变 HTTP 字段，参数覆盖发生在解压后的表单解析阶段，因此常规的请求头/参数规则很难覆盖两个视图的差异。

## 触发条件

- 服务接受 `Content-Encoding: gzip` 的请求体，且不拒绝尾随数据/多 member；
- 入口网关、WAF 或鉴权层为了检查而解压请求体，但只消费首个 member（基于 zlib `inflate()` 的流式解压很常见）；
- 后端框架再次解压完整请求体并解析参数（如 Python `gzip.decompress()`、会连续读取 member 的 Java `GZIPInputStream` 等）；
- 参数解析对同名键采用“后者覆盖前者”的语义；
- 安全决策（放行/拒绝、权限模式、租户/动作选择）取自首 member，而实际执行取自全量明文；
- 攻击者能控制请求体字节，构造两个各自完整、CRC/ISIZE 正确的 member。

注意组件差异：zlib `inflate()` 只解首 member，而 OpenJDK 25 的 `GZIPInputStream` 实测会读完所有 member。网关侧实际使用哪种解压语义决定能否利用，必须按目标组件验证。

## 利用步骤

1. 确认入口对 gzip 请求体做检查，且后端会再次解压；用单 member 正常请求建立基线。
2. 构造两个完整 member：首 member 放允许通过的值（如 `mode=read&report=monthly`），第二个 member 放要覆盖的参数（如 `&mode=write`）。
3. 直接拼接两份 gzip 字节作为请求体，保留 `Content-Encoding: gzip` 与表单 `Content-Type`。
4. 观察响应或副作用：网关判定为 `read`，业务实际执行 `write`，且请求体中第二个 `1f 8b 08` 位于首 member trailer 之后（示例偏移 44）。
5. 若要确认组件语义，在目标同栈环境用 zlib `inflate()` 与后端解压函数分别处理同一份字节，比较首 member 明文、剩余字节和完整明文。

## PoC

构造双 member 请求体：

```bash
python3 -c "
import gzip
first  = gzip.compress(b'mode=read&report=monthly', mtime=0)
second = gzip.compress(b'&mode=write', mtime=0)
open('multi.bin','wb').write(first + second)
print('first_len=', len(first), 'total=', len(first)+len(second))
"
```

发送：

```bash
curl -sS -X POST 'http://target/endpoint' \
  -H 'Content-Encoding: gzip' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @multi.bin
```

最小验证逻辑（网关只取首 member，后端全量解压）：

```python
import gzip, zlib
from urllib.parse import parse_qsl

raw = open('multi.bin','rb').read()
d = zlib.decompressobj(16 + zlib.MAX_WBITS)
gateway_plain = d.decompress(raw) + d.flush()
print('gateway_mode=', dict(parse_qsl(gateway_plain.decode()))['mode'])  # read
print('eof=', d.eof, 'unused_len=', len(d.unused_data))                  # True, >0
full = gzip.decompress(raw)
print('application_mode=', dict(parse_qsl(full.decode()))['mode'])       # write
```

真实组件验证：用 `-lz` 链接的 C 程序对同一份 `multi.bin` 调 `inflateInit2(&zs, 16 + MAX_WBITS)`，会返回 `Z_STREAM_END`，明文只有首 member，`avail_in=31` 且 `next_in` 起始为 `1f 8b 08`；同一字节交给 Python `gzip.decompress()` 则得到两段合并明文。

修复对照：若在解压后检查 `unused_data` 非空即拒绝，则追加任意第二个 member 都会返回 400；只校验 CRC32/ISIZE 不够，修改首 member trailer 的 CRC 会报 `incorrect data check`，但仍需单独检查尾随字节。

## 变体与关联

- 覆盖目标不限于 `mode`：任何“先校验、后用同名参数决定动作”的字段都可被第二个 member 覆盖，例如角色、租户、操作类型、回调地址、金额等。
- 组件差异变体：zlib/部分 C 网关只解首 member；Java `GZIPInputStream` 读完全部 member；应用层 `gzip.decompress` 也读全部。只有“前端首 member + 后端全量”的组合形成错位。
- 只追加不覆盖的 member（如 `note=archive`）不会改变动作，但已经造成解压范围不一致；当追加内容触及策略参数时才升级为执行偏移。
- 关联：HTTP 请求走私（CL/TE）同样是前后端对请求边界理解不一致；本场景是请求体压缩容器层面的同类解析差异，可归入请求走私/解析差异家族。

## 检测与防御

- 单 member 策略：解压后同时检查 `eof` 与 `unused_data`；`unused_data` 非空即拒绝，不能只看 `eof=True` 或只校验 CRC32/ISIZE。
- 解压只做一次：网关负责解压时把完整明文或不可变解析结果交给业务端，禁止应用再次解压；应用负责解压时，网关不要基于首 member 明文做参数授权。
- 参数解析只做一次，并让授权判断与业务执行引用同一份解析对象；禁止在不同层各自解析同名参数。
- 日志与告警：记录 member 数量、`unused_data` 长度、CRC32/ISIZE 校验结果、网关视图参数与业务视图参数；对“网关参数与执行参数不一致”“eof 为真但仍有剩余压缩字节”告警。
- 若业务确需多 member，需在协议层明确约定 member 数量与参数合并规则，并对合并后的参数重新做完整校验。
- 排查原则：按实际组件验证解压语义，不要假设所有 gzip 解析器行为一致。
