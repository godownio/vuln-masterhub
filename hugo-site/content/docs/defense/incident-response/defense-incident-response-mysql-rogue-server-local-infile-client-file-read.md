---
id: defense-incident-response-mysql-rogue-server-local-infile-client-file-read
title: MySQL 蜜罐溯源反制：伪造服务端发 LOAD DATA LOCAL INFILE 请求读取攻击者客户端本地文件（微信/Chrome 取证）
type: scenario
domain: defense
path: defense/incident-response
technique: rogue-mysql-server-local-infile-client-file-read
tags:
- mysql
- honeypot
- counterattack
- load-data-local-infile
- file-read
- client-side
- attribution
- wechat
- navicat
- protocol
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V432
  verified_at: '2026-11-09T18:50:54+08:00'
  notes: 已对照原文及 38 张图核对：0xFB LOCAL INFILE 请求包结构、recv 循环、PFRO.log→用户名→微信 config.data/AccInfo.dat→wxid/手机号→二维码闭环与原文代码(exp_dicc.py)和截图(Response TABULAR 含 C:/Windows/win.ini、客户端回传 win.ini 内容、Read Success)一致。注意：原文客户端手写 LOAD DATA LOCAL INFILE 语句截图报 1146 表不存在，真正读回靠伪造服务端下发请求，卡内客户端 SQL 仅概念等价。原文未给版本，已 clear。dedup 与 aj-report/weaver/clickhouse JDBC local infile 卡仅 related（角色方向相反），force/new 理由成立。
url: /docs/defense/incident-response/defense-incident-response-mysql-rogue-server-local-infile-client-file-read/
draft: false
kb_aliases:
- 伪造 MySQL 服务端读客户端文件
- LOAD DATA LOCAL INFILE 反制
- MySQL 蜜罐反制
- 读取攻击者微信 wxid
- Rogue-MySql-Server
---

## 一句话结论

在弱口令/任意口令可登录的 MySQL 蜜罐里，服务端不必等客户端执行任何 SQL：完成握手后主动发一个 MySQL 协议的 LOCAL INFILE 请求包（0xFB + 文件路径），允许 local_infile 的客户端（如 Navicat）就会把本机指定文件内容回传给服务端；据此可读取攻击者 Windows 主机的 win.ini、PFRO.log（取用户名）、微信 config.data/AccInfo.dat（取 wxid、手机号）与 Chrome Login Data/History，完成溯源反制。

## 原理

- **方向决定危害**：`LOAD DATA LOCAL INFILE` 是「客户端读本地文件并上传给服务端」的机制。协议上由服务端返回一个 LOCAL INFILE 请求包（首字节 0xFB，后跟文件名），客户端据此读取本地文件，再把内容作为后续数据包发回。文件由连接方（攻击者）的机器读取，因此恶意/蜜罐服务端可以让攻击者交出自己主机上的任意可读文件。
- **不必等待特定 SQL**：服务端可以在回复客户端的任何请求时返回该请求包，而不要求客户端真的先发过 `LOAD DATA LOCAL INFILE` 语句。伪造服务端只要模仿正常握手（greeting、登录 OK、`SET NAMES utf8mb4` 等交互）让客户端保持会话，然后发送构造包即可。
- **协议细节**：伪造包结构为 `长度字节 + "\x00\x00\x01\xFB" + 文件路径`（包体为 0xFB+路径，序列号 1）；客户端随后回传文件内容，Wireshark 中表现为服务端 `Response TABULAR` 指定路径、客户端回一个 `Request[Malformed Packet]` 携带文件字节。
- **前提是客户端允许本地加载**：客户端需开启 local_infile 能力（Navicat 等 GUI 客户端默认允许；mysql CLI 需 `--local-infile`，新版 JDBC 驱动默认 `allowLoadLocalInfile=false`）。原文用 Navicat 连接蜜罐后成功读回 win.ini，说明该路径在常见攻击者工具链上成立。
- **收包要循环**：文件内容分多个 TCP 段到达，脚本用 `recv` 循环直到单次读取不足 1024 字节，避免大文件被截断；每个连接读一个文件，下次连接轮换下一个目标路径。
- **溯源闭环**：先读 `C:/Windows/PFRO.log` 拿 Windows 用户名，回填到用户目录路径；再读微信 `config.data` 提取 wxid，回填 `AccInfo.dat` 路径拿微信号/手机号/邮箱；最后把 wxid 生成 `weixin://contacts/profile/<wxid>` 二维码，连同 IP、系统、机器名写入面板，形成攻击者画像。

## 触发条件

- 攻击者会主动连接防守方暴露的 MySQL（3306 或非标端口），且因弱口令/任意口令蜜罐而连接成功；
- 攻击者使用支持 local_infile 的客户端（Navicat、开启 local-infile 的 mysql CLI 等），且未关闭本地文件加载；
- 服务端能完成 MySQL 握手并以足够正常的响应维持会话，再下发 LOCAL INFILE 请求；
- 目标路径在客户端当前用户权限下可读（Windows 常见用户目录与系统目录均满足）。

## 利用步骤

1. 部署伪造 MySQL 服务端（自写脚本或 Rogue-MySql-Server 类项目），监听 3306，设置为弱口令或任意账号可登录，诱导爆破与连接。
2. 客户端连入后完成 greeting、登录、`SET NAMES` 等握手交互并保持会话。
3. 服务端按队列发送 LOCAL INFILE 请求包，依次读取侦察路径：`C:/Windows/win.ini`、`C:/Windows/system.ini`、`C:/Windows/PFRO.log`（Windows 用户名）、`C:/Users/<user>/Documents/WeChat Files/All Users/config/config.data`（wxid）、`C:/Users/<user>/Documents/WeChat Files/<wxid>/config/AccInfo.dat`（微信号/手机号/邮箱）、`C:/Users/<user>/AppData/Local/Google/Chrome/User Data/Default/Login Data` 与 `.../Default/History`。
4. 接收并按路径保存回传内容；从 PFRO.log 提取用户名回填后续路径，从 config.data 提取 wxid 回填 AccInfo.dat 路径，从 AccInfo.dat 用 11 位数字正则提取手机号。
5. 将 wxid 转二维码并把 IP、操作系统、机器名、微信号、手机号、首次时间写入管理面板（原文面板即按这些字段展示）。
6. 单连接读一个文件并在下一次连接轮换目标；读取失败（内容过短）时回退到路径队列首位重试其它路径。

## PoC

伪造服务端下发 LOCAL INFILE 请求并接收文件（核心逻辑）：

```python
# 握手完成后，向客户端索取指定本地文件
wantfile = chr(len(filename) + 1) + "\x00\x00\x01\xFB" + filename
conn.sendall(wantfile.encode())

content = b""
while True:
    data = conn.recv(1024)
    content += data
    if len(data) < 1024:      # 最后一段不足 1024 字节即结束
        break
with open(save_path, "wb") as f:
    f.write(content)
```

客户端侧等价概念验证（Navicat/mysql CLI 开启 local_infile 时）：

```sql
LOAD DATA LOCAL INFILE 'C:/Windows/win.ini' INTO TABLE test FIELDS TERMINATED BY '\n';
```

原文实测：脚本 `exp_dicc.py 3306` 启动后连续打印 `Read Success! ---> C:/windows/win.ini` 与 `C:/windows/system.ini`；面板成功记录攻击者微信 wxid、手机号并生成二维码。

## 变体与关联

- 变体：同一协议包对任何允许 local infile 的客户端生效（Navicat、DBeaver、mysql CLI、开启 allowLoadLocalInfile 的 JDBC），与客户端执行过什么 SQL 无关。
- 变体：读取目标可扩展到浏览器 `Login Data`（无法直接解密口令但可拿到账号列表）与 `History`（浏览记录），以及 SSH 私钥、配置文件等任意用户可读文件。
- 关联：[[web-java-deserialization-fake-mysql-server-protocol-greeting-warnings-blob]]（同为伪造 MySQL 服务端协议栈，但目标是诱导 JDBC 反序列化而非读客户端文件）、[[web-java-rmi-jrmp-listener-fake-registry-scanner-counterattack]]（同为「服务端反向打客户端」的蜜罐反制思路）。

## 检测与防御

- 攻击者侧：连接来源不明/可疑的 MySQL 时关闭 local_infile 与驱动本地文件加载；在隔离虚拟机/沙箱中操作，避免真实身份文件暴露；对服务器主动返回的异常请求包保持警惕。
- 防守方：蜜罐应完整模拟握手并做好文件与日志取证，注意反制必须在授权与合法边界内进行；对回传文件只做最小必要采集与脱敏存储。
- 检测：流量侧关注「服务端在客户端未发 LOAD DATA 语句时返回 0xFB 包、客户端随即发送大块文件内容」的组合；主机侧关注数据库客户端进程异常读取系统目录或微信/浏览器配置目录。
