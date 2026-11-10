---
id: web-generic-file-inclusion-nginx-alias-off-by-slash-traversal
title: nginx alias 缺少尾部斜杠导致 /images../ 路径穿越任意文件读取
type: scenario
domain: web
path: web/generic/file-inclusion
technique: nginx-alias-missing-trailing-slash-path-traversal
tags:
- nginx
- alias
- path-traversal
- arbitrary-file-read
- misconfiguration
- autoindex
- reverse-proxy
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-11
  verified_at: '2026-11-08T07:27:29+08:00'
  notes: 已对照原文配置与图 01-03 核对：location /images {alias /app/src/images/; autoindex on;} 无尾斜杠，/images../ 返回 Index of /images../（html/images/ponies/resources/secretbackend），/images../secretbackend/index.js 读出 Basic 凭据常量，与卡内路径、PoC 一致；卡未复述 base64 凭据。原文为 CTF 环境，无组件受影响版本，未 set-versions。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-nginx-alias-off-by-slash-traversal/
draft: false
kb_aliases:
- nginx alias off-by-slash
- alias 路径穿越
- /images../ 目录遍历
- nginx 不安全配置任意文件读取
---

## 一句话结论

nginx 配置 `location /images { alias /app/src/images/; }` 的 location 不带尾部斜杠时，请求 `/images../` 会被拼成 `/app/src/images/../` 逃出别名目录；配合 `autoindex on` 可列目录并读取 Web 根之外的任意文件（本例读到反向代理后端 `secretbackend/index.js`，拿到硬编码 Basic 认证凭据进入受保护后端）。

## 原理

- `alias` 把匹配到的 location 前缀替换为目标文件系统路径。location 是 `/images`（无尾斜杠）时，URI `/images../` 也能命中，前缀 `/images` 被替换为 `/app/src/images/`，剩余 `../` 拼上去得到 `/app/src/images/../`，即上级目录。nginx 不拒绝这种含 `..` 的结果路径，于是越过别名边界。
- 为什么加尾斜杠就安全：写成 `location /images/ { alias /app/src/images/; }` 时，`/images../` 不以 `/images/` 开头（`/images` 后面是 `.` 不是 `/`），不会命中该 location，也就不会形成逃逸路径。这就是题目所谓「off by a single slash」。
- `autoindex on` 会把逃逸后的目录内容以列表页返回，形成「目录遍历 + 任意文件读取」原语；即使不开 autoindex，只要知道文件名也可直接请求。
- 后端隔离被打破：`/secretbackend/` 原本由 `proxy_pass` 代理到内网 `secretbackend:3000` 并需要 Basic 认证，但 `/images../secretbackend/index.js` 走的是静态 alias 路径，绕过代理直接读到后端源码；源码里硬编码了 Basic 认证头常量，base64 解码即账号口令，从而进入本应受保护的后端。
- 完整链：路径穿越读源码 → 拿到硬编码凭据 → 用该凭据访问后端（本例凭据/响应中含目标数据），危害明确。

## 触发条件

- nginx 使用 `location /xxx { alias /path/; }` 且 location 无尾部斜杠；
- 目标敏感文件位于 alias 目录的上级/同级（相对 `..` 可达）；
- `autoindex on` 开启，或攻击者能猜到具体文件名；
- 静态目录与后端源码/配置处于同一文件系统可达路径。

## 利用步骤

1. 从提供/推断的 nginx.conf 中找 `alias` 且 location 无尾斜杠的块。
2. 请求 `/images../`，确认返回 `Index of /images../` 与上级目录列表。
3. 逐级拼接 `/images../secretbackend/` 列目录、`/images../secretbackend/index.js` 读源码。
4. 从源码中提取硬编码凭据、环境变量名或配置，访问受保护后端。

## PoC

```bash
curl "http://<target>/images../"
curl "http://<target>/images../secretbackend/"
curl "http://<target>/images../secretbackend/index.js"
```

```nginx
location /images  { alias /app/src/images/; autoindex on; }   # 危险：无尾斜杠
location /images/ { alias /app/src/images/; }                 # 安全：location 与 alias 都带斜杠
```

## 变体与关联

- 变体：`root` 与 `alias` 混用、`merge_slashes` 与 URL 规范化差异、`..%2f`/双重编码绕过、穿越去读 `.htpasswd`/应用配置/私钥；`proxy_pass` 后拼接 URI 不当造成同源路径混淆。
- 关联：任意文件读取/LFI、反向代理配置审计、目录列表信息泄露；本例后续用读到的凭据配合其它题的竞态/JWT 缺陷。

## 检测与防御

- 防御：`location` 与 `alias` 尾斜杠保持一致；尽量用 `root` 代替 `alias`；关闭 `autoindex`；对 `$uri` 做规范化并拒绝含 `..` 的路径；把只应内部访问的后端 location 标记 `internal` 并限制来源。
- 加固：后端源码/凭据不要放在静态根可达的文件系统路径下；用最小权限运行 nginx worker。
- 检测：访问日志出现 `/images../`、`..%2f` 等含 `..` 的路径且返回目录列表或 `.js`/`.env` 等非静态内容；静态 location 返回了后端源码文件。
