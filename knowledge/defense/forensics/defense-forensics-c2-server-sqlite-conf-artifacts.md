---
id: defense-forensics-c2-server-sqlite-conf-artifacts
title: C2 服务端目录取证：SQLite clients/listeners/tunnels 与 setting.conf 还原基础设施
type: scenario
domain: defense
path: defense/forensics
technique: c2-server-sqlite-conf-forensics
aliases:
- VShell 服务端取证
- C2 数据库取证
- clients listeners tunnels 表
- setting.conf 凭据
- FRP 隧道取证
- v_windows_amd64 分析
tags:
- forensics
- c2
- vshell
- sqlite
- frp
- configuration
- listeners
- ir
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T02:06:35+08:00'
  notes: 已对照原文与图片 40-49 核对；v_windows_amd64.exe、clients Id=5 B411NAS、listeners 8085->47.89.230.121:10001、download 5 文件、setting.conf web 凭据均一致；末段示例块实际是 B411 NAS 的 frpc.toml，不是 FRP 管理器 vshell-2 配置，引用时需区分
---

## 一句话结论

在 Windows 镜像中发现了 C2 服务端目录 `v_windows_amd64`：可执行文件 `v_windows_amd64.exe`、SQLite 数据库 `db/data.db`（`clients`/`listeners`/`tunnels`/`hosts` 等表）、配置 `conf/setting.conf` 和 `download/` 目录；通过数据库与配置可还原客户端 ID、监听端口、下载文件数量及 Web 管理凭据，再结合 FRP 管理器配置/日志可定位内网穿透隧道与最后连接时间。

## 原理

- 商业/开源 C2 服务端（案例为 VShell，`v_windows_amd64.exe`，服务端版本 4.9.3）需要持久化客户端、监听器、隧道等状态，通常使用 SQLite 数据库和本地配置文件；这些文件在磁盘镜像中就是完整的作战记录。
- `db/data.db` 中：
  - `clients` 表记录 `Id`、`HostName`、`OsName`、`ProcessName`、`InternalIp` 等，案例中 Linux 客户端 `B411NAS` 的 `Id=5`；
  - `listeners` 表记录监听地址、外连地址、端口、密钥等，案例中 `0.0.0.0:8085` 对应外部 `47.89.230.121:10001`；
  - `tunnels` 表记录隧道；`download/` 目录保存通过平台下载的文件，文件数量可直接统计。
- `conf/setting.conf` 是管理平台配置，包含 `web_title`、`web_port=8088`、`web_ip=0.0.0.0`、`web_basic_auth=true`、`web_username=wang`、`web_password=wang@0528@vshell`、`license` 等；拿到账号口令后可登录平台查看实时状态，或直接读库。
- SQLite 的 `-wal`/`-shm` 可能含未合并的最新记录，取证时应与主库一起复制并用 `immutable=1` 或先做 WAL checkpoint，避免读到旧快照。
- FRP 图形化管理工具（案例 FRP 管理器 1.26.1）的配置与日志记录了隧道名、本地/远程端口和连接结果；与 C2 `listeners` 表交叉比对可确认 C2 客户端如何经 FRP 暴露到公网。

## 触发条件

- 磁盘/主机镜像中存在可疑的 C2 服务端目录，特征包括 `v_windows_amd64.exe`、`db/`、`conf/`、`download/`、`web` 管理端口。
- 数据库未被加密，或能获得/破解配置中的管理凭据。
- 取证环境有 SQLite 工具（`sqlite3`、DB Browser for SQLite）和文本编辑器。
- 需要关联网络侧证据时，另有 FRP/隧道工具的配置或日志。

## 利用步骤

1. 定位服务端目录与可执行文件，记录文件名、版本、签名与哈希；查看 `conf/setting.conf` 获取 Web 端口、账号口令、License。
2. 复制 `db/data.db`、`data.db-wal`、`data.db-shm` 到工作目录，先对副本操作，保留原始证据哈希。
3. 列出表结构，查询 `clients`、`listeners`、`tunnels`、`hosts`、`download` 等表，导出客户端 ID、主机名、内外网 IP、监听端口与隧道配置。
4. 统计 `download/` 目录文件数量与文件名，判断攻击者通过该 C2 下发/回收了哪些工具与数据。
5. 查找 FRP 管理器配置与日志，提取隧道名、本地端口、远程端口、最后成功连接时间；与 `listeners` 表交叉验证。
6. 若配置中有 Web 凭据，可在隔离环境启动服务端登录管理平台核对；不要在联网环境直接运行未知 C2 样本。
7. 汇总成基础设施图谱：C2 服务端 → 监听器 → 客户端 → FRP 隧道 → 外部 VPS，并固定证据。

## PoC

```bash
# 1) 查看数据库表与关键记录（对副本操作）
sqlite3 data.db ".tables"
sqlite3 -header -column data.db "SELECT Id,HostName,OsName,ProcessName,InternalIp FROM clients;"
sqlite3 -header -column data.db "SELECT Id,ListenAddr,ConnectAddr,Mode FROM listeners;"
sqlite3 -header -column data.db "SELECT * FROM tunnels;"

# 案例结果（节选）：
# clients: Id=5, HostName=B411NAS, OsName=linux_amd64, ProcessName=[kworker/0:2]
# listeners: 0.0.0.0:8085 -> 47.89.230.121:10001, mode=tcp
# download 目录: 5 个文件

# 2) 读取管理平台配置
grep -E 'web_title|web_port|web_username|web_password|basic_auth' conf/setting.conf
```

```ini
# setting.conf 关键字段（案例）
web_title=管理平台
web_port=8088
web_ip=0.0.0.0
web_basic_auth=true
web_username=wang
web_password=wang@0528@vshell
```

```ini
# FRP 管理器配置（案例，隧道 vshell-2）
serverAddr = "47.89.230.121"
serverPort = 7000
[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 10022
[[proxies]]
name = "http"
type = "tcp"
localIP = "127.0.0.1"
localPort = 80
remotePort = 10080
```

说明：案例中 C2 客户端 `B411NAS` 的 `Id=5`、监听本地端口 `8085`、`download/` 下 5 个文件，均来自数据库与目录统计；`vshell-2` 隧道与最后成功连接时间来自 FRP 管理器配置/日志。

## 变体与关联

- 变体：Cobalt Strike、Sliver、Havoc 等服务端的 `.profiles`、SQLite/JSON 数据库、`downloads/` 目录，同样可按“配置 + 数据库 + 下载目录”三件套取证。
- 变体：数据库使用 WAL 模式时，最新客户端/监听器记录可能只在 `-wal` 中；直接复制主库会漏证据。
- 变体：C2 服务端可能以 Docker/服务方式运行，需同时检查容器卷、systemd 单元、计划任务与日志。
- 关联：[[defense-forensics-veracrypt-key-from-mobile-notes-cross-evidence]]（本案例 C2 目录位于挂载后的加密分区）、[[defense-forensics-multisource-timeline-log-clear]]（多源时间线）、[[pentest-c2-dns-only-egress-dnscat2-iodine]]（C2 通道对照）。

## 检测与防御

- 防御：对 C2 服务端目录、管理端口（如 8088）和 FRP 默认端口（7000）做资产扫描与告警；禁止将管理平台暴露到公网。
- 防御：管理平台使用强口令 + MFA，定期轮换；配置文件权限最小化，避免明文口令。
- 检测：主机上出现 `v_windows_amd64.exe`、`db/data.db`、`conf/setting.conf`、`download/` 组合；FRP 客户端配置中出现陌生 `serverAddr` 与 `remotePort`；监听端口与进程不匹配。
- 响应：隔离主机、保留数据库/配置/日志副本并计算哈希；提取客户端 ID 与监听器后，排查对应内网主机与外部 VPS；轮换可能泄露的凭据。
