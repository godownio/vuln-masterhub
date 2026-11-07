---
id: web-generic-sqli-blind-log-pcap-response-length-recovery
title: 从访问日志/pcap 按响应差异还原布尔盲注：ord/substr ASCII 逐字符提取
type: scenario
domain: web
path: web/generic/sqli
technique: blind-sqli-log-pcap-response-length-recovery
aliases:
- 盲注日志还原
- 盲注流量还原
- 响应长度盲注
- blindsql.txt
- ORD(MID()) 盲注
- 布尔盲注取证
tags:
- sqli
- blind
- log-analysis
- pcap
- tshark
- response-length
- forensics
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V201
  verified_at: '2026-11-07T02:10:25+08:00'
  notes: 已对照原文与全部61张图核对；未复跑PoC
---

## 一句话结论

布尔盲注每个请求只泄露一个比特，但访问日志或 pcap 会保留每个请求的 URL 与响应长度/状态码；只要真/假条件对应稳定的响应差异，就能按注入位置把“真”请求的 `val` 作为下界、“假”请求的 `val` 作为上界，二分收敛到唯一 ASCII 码，逐字符还原被注出的数据。

## 原理

- **布尔盲注的 oracle**：`id=1 AND ascii(substr((select flag from sql.flag),N,1))=V` 在条件为真/假时让页面走不同分支，响应体长度、状态码、重定向或响应时间不同。攻击者靠这个差异逐字符猜解；日志/pcap 记录的是同一批请求，因此离线也能复现 oracle。
- **日志中的两个关键字段**：请求行包含完整 URL（可能被 URL 编码），访问日志末尾包含状态码与响应字节数，例如 `"GET /... HTTP/1.1" 200 6`；pcap 中可用 `http.request.uri` 与 `frame.len`（或 `http.content_length`、`http.response.code`）配对。
- **定界算法**：对同一注入点、同一字符位置 `pos`，收集所有 `val` 与响应是否为“真”。真请求说明目标字符码 `> val`（若谓词是 `>`）或 `= val`（若谓词是 `=`），假请求说明 `<= val`。用 `low = max(val+1)`、`high = min(val)` 收敛；当 `low == high` 时即字符码。等值谓词则直接取真请求的 `val`。
- **为什么响应长度能区分**：盲注 payload 命中时页面返回正常内容（例如 1091 字节），未命中时返回错误页/空结果（例如 1124 字节）；长度差通常来自模板分支、错误信息或结果行数。若长度不稳定，可改用状态码、重定向 Location、响应时间等更稳的 oracle。
- **日志噪声处理**：扫描器/爆破会留下大量 403/404；只保留目标注入参数出现的请求，按 URL 解码后正则提取 `ORD/MID/SUBSTR/ASCII` 等表达式；多线程扫描时同一位置可能乱序，按 `(source, pos, val)` 聚合即可，不依赖时间顺序。
- **pcap 特殊点**：`frame.len` 包含以太网/IP/TCP 头，和 HTTP body 长度不同，但同一会话内相对差异稳定；`tshark -T fields` 输出可能一行一个字段，需要按请求分组；URL 中的 `%20`、`%27` 要先解码再正则。

## 触发条件

- 目标存在布尔盲注，且真/假响应在长度、状态码、重定向或时间上有稳定差异。
- 能拿到 Web 访问日志（Apache/Nginx/IIS）或包含完整 HTTP 请求/响应的 pcap。
- 日志保留请求行与响应大小/状态码；pcap 保留双向流量或至少有响应帧。
- 注入 payload 可从 URL/请求体中解析出字符位置与比较值（`ascii(substr(...))=N`、`ord(mid(...))>N` 等）。
- 真/假响应差异在该时间段内稳定，未被 WAF 随机页、缓存或压缩打乱。

## 利用步骤

1. **定位注入请求**：在日志中搜索目标参数（如 `id=`）与 SQL 关键字（`ascii`、`substr`、`ord`、`mid`、`select`），排除扫描器的 403/404 噪声。
2. **确定 oracle**：统计同一参数下响应长度/状态码的分布，找出两个稳定簇；真值簇通常对应正常页面，假值簇对应错误/空页面。记录 `TRUE_LEN`、`FALSE_LEN`（或状态码）。
3. **解析 payload**：URL 解码后提取 `(source, pos, val)`；`source` 是被注出的子查询/列名，`pos` 是字符位置，`val` 是比较值。正则示例：`ORD\s*\(\s*MID\s*\(\s*(.+?)\s*,\s*(\d+)\s*,\s*1\s*\)\s*\)\s*>\s*(\d+)`。
4. **聚合上下界**：按 `source` 分组、按 `pos` 聚合；真请求更新 `low = max(low, val+1)`，假请求更新 `high = min(high, val)`。等值谓词则记录真请求的 `val`。
5. **还原字符**：`low == high` 时 `chr(low)`；若 `low > high` 说明 oracle 判断反了或有噪声，检查真/假长度是否对调。
6. **拼接**：按 `pos` 排序拼接，检查 `flag{...}`、表名、列名等语义；对同一位置多组 payload 交叉验证。
7. **pcap 流程**：`tshark -r x.pcapng -Y http -T fields -e http.request.uri -e frame.len`，按请求顺序配对；或分别导出 `http.request.uri` 与 `http.response.code`/`http.content_length`，再套同一聚合脚本。

## PoC

日志版（Apache combined 格式，响应长度在行尾；`ascii(substr(...))=val` 等值谓词）：

```python
import re
from collections import defaultdict
from urllib.parse import unquote

TRUE_LEN = 6      # 真条件响应字节数
FALSE_LEN = 22    # 假条件响应字节数

pat = re.compile(r"ascii\(substr\(\(select flag from sql\.flag\),(\d+),1\)\)=(\d+)", re.I)
hits = defaultdict(list)

for line in open("blindsql.txt", encoding="utf-8", errors="ignore"):
    m = re.search(r'"(GET|POST) (\S+) HTTP/[^"]+" (\d{3}) (\d+)', line)
    if not m:
        continue
    url, status, size = unquote(m.group(2)), int(m.group(3)), int(m.group(4))
    if status != 200 or size not in (TRUE_LEN, FALSE_LEN):
        continue
    for pos, val in pat.findall(url):
        if size == TRUE_LEN:
            hits[int(pos)].append(int(val))
        # 假请求只说明 != val，对等值谓词不提供额外上界

flag = "".join(chr(max(set(v), key=v.count)) for _, v in sorted(hits.items()))
print(flag)
```

若谓词是 `> val`，则改用上下界：真请求 `low = max(low, val+1)`，假请求 `high = min(high, val)`，`low == high` 时取 `chr(low)`。

pcap 版（`ORD(MID(...)) > val`，真/假长度 1091/1124）：

```python
import re, subprocess
from urllib.parse import unquote

out = subprocess.check_output([
    "tshark", "-r", "blindsql.pcapng", "-Y", "http",
    "-T", "fields", "-e", "http.request.uri", "-e", "frame.len",
], text=True)
pat = re.compile(r"ORD\s*\(\s*MID\s*\(\s*(.+?)\s*,\s*(\d+)\s*,\s*1\s*\)\s*\)\s*>\s*(\d+)", re.I)

limits = {}
for line in out.splitlines():
    if "\t" not in line:
        continue
    uri, flen = line.split("\t")
    uri, flen = unquote(uri), int(flen)
    for src, pos, val in pat.findall(uri):
        d = limits.setdefault((src, int(pos)), {"low": 32, "high": 126})
        if flen == 1091:      # true: ord > val
            d["low"] = max(d["low"], int(val) + 1)
        elif flen == 1124:    # false: ord <= val
            d["high"] = min(d["high"], int(val))

print("".join(chr(v["low"]) for _, v in sorted(limits.items()) if v["low"] == v["high"]))
```

## 变体与关联

- **等值谓词**：`ascii(substr(...))=N` 时真请求直接给出字符码，不需要上下界；日志中只保留真响应长度即可。
- **比较谓词**：`> val` / `< val` 时按上下界收敛；注意真/假方向，写反会得到空串或乱码。
- **时间盲注**：若响应长度无差异，用响应时间 (`%D`/`elapsed`) 或 pcap 时间差做 oracle；聚合逻辑相同。
- **状态码/重定向 oracle**：以 200/500、302 Location、WAF 拦截页区分真假。
- **多线程/乱序**：按 `(source,pos,val)` 聚合，不依赖请求顺序；同一 `val` 出现多次时取多数票。
- **关联卡片**：[[web-generic-sqli-blind-ascii-case-restore-login]]（大小写陷阱下的 ASCII 还原）；[[web-generic-sqli-exists-left-boolean-oracle]]（EXISTS+left 盲注）；[[ctf-forensics-pcap-irc-dcc-nested-archive-password]]（pcap 取证思路）。

## 检测与防御

- **检测**：监控同一参数短时间内大量结构相似的请求，尤其是包含 `ascii(`、`substr(`、`ord(`、`mid(`、`select` 的 URL；统计响应长度在固定两值间跳变的模式。
- **日志审计**：保留完整 URL、状态码、响应大小与时间；对 200 但长度异常的请求做聚合分析，不要只看 4xx/5xx。
- **防御**：参数化查询/预编译，禁止拼接 SQL；最小数据库权限；WAF 只能提高门槛，不能替代参数化。
- **响应一致性**：统一错误页与响应长度，减少布尔/时间侧信道；对敏感查询加限速与验证码。
