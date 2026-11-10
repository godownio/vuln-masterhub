---
id: web-generic-ssrf-file-hosts-internal-segment-recon
title: SSRF 支持 file:// 时先读 /etc/hosts：拿到容器主机名与内网网段再定向扫端口
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-file-scheme-hosts-internal-recon
tags:
- ssrf
- file-protocol
- recon
- internal-network
- etc-hosts
- cidr
- container
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:38:40+08:00'
  notes: 已对照原文与图01/02/03核对：快照功能用 file:///flag 直接读根目录 flag（图01）、file:///etc/hosts 回显含 172.18.240.5 ccc2276fa960 的非回环条目（图02）、据提示推出 172.18.240.0/24 后 Yakit 扫 6379 得到 1 与 7 响应不同（图03）；卡内 hosts 行与 C 段示例逐字一致。未验证点：卡内端口探测用 http://IP:6379 示例，原文实际用 Yakit 探针，二者等价但未复跑；原文未给产品版本，未设 affected_versions。
url: /docs/web/generic/ssrf/web-generic-ssrf-file-hosts-internal-segment-recon/
draft: false
kb_aliases:
- file:///etc/hosts 侦察
- SSRF 读 hosts 找内网 C 段
- 快照 SSRF 内网网段
- 主机名反查内网
- file 协议内网拓扑
---

## 一句话结论

当一个「网址快照 / 预览 / 抓图」类功能把用户提交的 URL 直接交给服务端抓取并把响应正文回显时，先用 `file:///etc/hosts` 读回容器/主机的 hosts 文件，就能从其中的 `<IP> <主机名>` 行直接得到内网网段与同网段机器名，把「盲扫整个内网」变成「在已知 C 段里定向扫少数主机」；这一步通常是后续打内网 Redis/数据库/管理端口的前置侦察。

## 原理

- `file://` 是 URL 的一种协议，服务端抓取函数（curl、`URL.openStream`、`requests.get`、`fetch`）若未限制协议，会按本机文件系统路径读取目标文件并把它当作「快照内容」返回页面。
- `/etc/hosts` 是静态名称解析表，容器编排与运维经常在里面写入同网段主机：`172.18.240.5  ccc2276fa960` 这类行同时泄露「内网 IP」和「对端主机名/容器名」，主机名的哈希形态还能反证这是编排系统分配的容器而非物理机。
- 只看 `127.0.0.1`/`::1` 行没有价值，关键是找形如 `<私有网段 IP> <名字>` 的非回环条目：它给出 C 段（如 `172.18.240.0/24`），把端口扫描范围从 `/8` 收敛到 255 个地址。
- 拿到网段后，用批量请求把「快照接口」当作端口探针：内网不可达的地址/端口返回连接失败或长超时，可达端口返回不同的响应长度/错误文案；配合「常见端口字典里优先放 6379/3306/6379+1」的经验，能快速定位未授权服务。
- 之所以成立：应用把「用户可控 URL」当成可信输入，且把抓取结果原样回显；文件读取和端口探测都只是这个 SSRF 原语的两种用法。

## 触发条件

- 存在服务端抓取 URL 并回显正文的功能（网址快照、页面预览、图片代理、webhook 测试、远程配置拉取）。
- 协议未做白名单（允许 `file://`），或虽禁止但可按大小写/编码/重定向绕过。
- 进程对 `/etc/hosts` 等文件可读（普通用户即可）。
- 目标处于容器/多主机网络，hosts 或编排 DNS 中存在同网段条目。

## 利用步骤

1. 提交 `file:///etc/hosts`，观察回显是否包含非回环条目；若被拦，换 `file:///proc/net/route`、`file:///proc/net/tcp`（后者列出本机监听端口与对端地址）作为补充。
2. 从 `<私有IP> <主机名>` 行提取网段（如 `172.18.240.0/24`）；主机名形如随机哈希说明是容器。
3. 以该网段为范围、以内网常见端口（6379 Redis、3306 MySQL、8080/7001 中间件、22、9200）为字典，用快照接口批量请求 `IP:端口`，按响应差异筛选存活服务。
4. 对存活服务转向对应协议利用：Redis 用 `dict://IP:6379/keys *` 读键、`config get dir` 探目录；数据库/HTTP 管理面按各自手法。
5. 记录证据（回显原文与响应长度差异），再进入下一步利用。

## PoC

```http
POST / HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

url=file:///etc/hosts
```

```text
# 回显（节选形态）
127.0.0.1        localhost
::1              localhost ip6-localhost ip6-loopback
172.18.240.5     ccc2276fa960          <-- 关键：内网 IP + 容器名
```

```text
# 由上一行推出网段 172.18.240.0/24 后，用同一接口做端口探测
url=http://172.18.240.1:6379     -> 超时/连接失败
url=http://172.18.240.7:6379     -> 返回 Redis 的 inline 协议报错，长度与其它 IP 不同
```

## 变体与关联

- 变体：`/proc/net/tcp` 读本机已建立连接的对端 IP；`/etc/resolv.conf` 读内网 DNS；`/proc/1/cgroup` 与 `/etc/hostname` 判断容器与编排环境。
- 变体：把「快照」接口当作端口探针时，用 `dict://`、`gopher://` 请求比 `http://` 更容易从协议报错里区分「端口开放但非 HTTP」。
- 关联：`[[web-generic-ssrf-redis-inline-protocol-crlf]]` 是本卡侦察出的 Redis 端口之后的利用侧（inline 协议、`CONFIG SET` 写文件）；`[[web-generic-ssrf-preview-panel-target-url-localhost]]` 是同一「快照/预览」入口打本机内部路由的用法。
- 边界：应用禁用 `file://` 且无法绕过、进程无读权限、hosts 中无同网段条目、网络策略隔离内网东西向流量时，侦察失效。

## 检测与防御

- 检测：抓取接口的 URL 出现 `file://`、`/etc/hosts`、`/proc/` 等路径；同一接口短时间内向大量内网 `IP:端口` 发起请求（尤其 6379/3306 等非常见 Web 端口）。
- 修复：URL 协议白名单限定 `http`/`https`；解析后校验目标主机与端口，禁止回环地址、私有网段与文件协议；抓取结果只返回渲染后的图片/摘要，不回显原始正文。
- 加固：抓取组件以最小权限运行于独立网络域；出站防火墙限制内网横向；hosts 不写入敏感主机名。
