---
id: iot-protocol-zkteco-standalonecomm-download-picture-path-traversal
title: ZKTeco standalonecomm CMD_DOWNLOAD_PICTURE 目录穿越：图片文件名未校验读取任意文件（含 /etc/shadow）
type: scenario
domain: iot
path: iot/protocol
technique: zkteco-standalonecomm-download-picture-path-traversal
tags:
- iot
- zkteco
- biometric-terminal
- protocol
- path-traversal
- arbitrary-file-read
- root
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V322
  verified_at: '2026-11-08T15:54:54+08:00'
  notes: 已对照 img39 与原文核对：GetAdPicturePath(s,128,payload+8) 后 ReadPhotoBuf 未校验文件名，可穿越读取 /etc/shadow；未复跑协议包，confidence medium 合理。
url: /docs/iot/protocol/iot-protocol-zkteco-standalonecomm-download-picture-path-traversal/
draft: false
kb_aliases:
- CMD_DOWNLOAD_PICTURE
- ZKTeco 任意文件读取
- standalonecomm 路径穿越
- 4370 协议下载图片
- GetAdPicturePath
---

## 一句话结论

ZKTeco 终端的 `standalonecomm` 服务在处理 4370/TCP 协议的 `CMD_DOWNLOAD_PICTURE` 命令时，把数据包中的图片文件名直接交给 `GetAdPicturePath`/`ReadPhotoBuf` 打开读取，未过滤 `../` 或绝对路径；攻击者（COMKey 默认 0 或已知口令）可构造目录穿越文件名读取任意系统文件，服务以 root 运行时可读 `/etc/shadow`、数据库与配置。

## 原理

- 4370/TCP 协议由 `standalonecomm` 实现（原文服务进程以 root 运行）。解析命令后进入一个大的 `switch` 分发器，`CMD_DOWNLOAD_PICTURE` 分支从 `UserPacketPayload + 8` 取出文件名（`GetAdPicturePath(s, 128, UserPacketPayload + 8)`），随后 `ReadPhotoBuf` 打开该路径读文件并回传。
- 代码没有对文件名做 `..`、`/`、绝对路径或白名单校验；`GetAdPicturePath` 只是把用户字符串拼进广告图片目录。传入 `../../../../etc/shadow` 即可逃逸目录，由 root 进程读取。
- 该命令属于认证后命令，但 COMKey 默认为 0（无认证）或可爆破/反算，因此未修改默认口令的终端可被直接利用。
- 原文在同一命令分发器中还发现任意文件上传（可写任意路径）与 SQL 注入；文件下载只是其中一类 sink。所有服务以 root 运行，文件读取可直接拿到 `/etc/shadow`、数据库（含 COMKey 明文）、配置与固件。
- 与普通 Web 路径穿越不同，这里的数据包是二进制协议，需要先完成 `CMD_CONNECT`/`CMD_AUTH` 并构造正确的命令头、长度与 payload。

## 触发条件

- 目标 4370/TCP 可达，`standalonecomm` 正常运行。
- COMKey 为默认 0，或攻击者已通过爆破/抓包/数据库读取获得 COMKey。
- 攻击者能实现 zk-protocol 的数据包封装（协议文档公开）。
- 目标文件对 root 可读（服务以 root 运行，通常全部可读）。

## 利用步骤

1. 连接 4370/TCP，完成 `CMD_CONNECT`，按默认/已知 COMKey 完成 `CMD_AUTH`（或确认无需认证）。
2. 构造 `CMD_DOWNLOAD_PICTURE` 命令：命令头 + payload，payload 偏移 8 处放文件名，例如 `../../../../etc/shadow` 或指向应用数据库的相对路径。
3. 发送命令并解析响应中的文件数据；先读一个已知无害文件（如 `/etc/hostname`）验证穿越，再读 `/etc/shadow`、数据库或配置。
4. 若文件名长度受限，可缩短 `../` 层数或使用绝对路径；Windows 目标试 `..\\..\\` 与盘符。
5. 用读到的数据库内容取 COMKey、用户 PIN/生物特征模板或云服务配置；测试后停止扩大并记录。
6. 同分发器中的上传命令若可写任意路径，可进一步写入启动脚本/服务文件，但需单独验证，勿在未授权环境尝试。

## PoC

协议交互（概念，具体包头字段按 zk-protocol 文档构造）：

```text
CMD_CONNECT (0x03e8) -> SessionId
CMD_AUTH (0x044e) + MAC -> CMD_ACK_OK (0x07d0)
CMD_DOWNLOAD_PICTURE (命令号见 zk-protocol) + payload[8:] = "../../../../etc/shadow"
```

```text
# 响应中应包含 root:... 与 zkteco:... 的 shadow 行
```

说明：原文通过反编译确认 `GetAdPicturePath` 未校验文件名并读取任意文件，给出的利用脚本为 `read_file.py`；本卡未复跑协议包，具体命令号/包头需按固件与协议文档调整，故 confidence 记为 medium。

## 变体与关联

- 变体：同一分发器中其他带文件名参数的命令（下载、删除、上传）也缺少过滤，可复用同一思路。
- 变体：任意文件上传可写 Web 目录/启动脚本，配合服务以 root 运行可升级为 RCE。
- 关联：[[iot-protocol-zkteco-4370-comkey-reversible-mac-auth]]（协议认证与 COMKey）、[[iot-protocol-zkteco-standalonecomm-delete-picture-command-injection]]（同一服务的命令注入）、[[iot-protocol-zkteco-pushcomm-shell-command-server-hijack]]（另一服务的命令执行）。
- 边界：COMKey 已改强口令且无法获得、4370 被隔离、固件对文件名做了规范化/白名单时，本卡不成立；仅文件读取不直接等于 RCE，但 root 文件读取通常可进一步升级。

## 检测与防御

- 检测：4370/TCP 会话出现含 `../`、`/etc/`、盘符的文件名；`CMD_DOWNLOAD_PICTURE` 等下载命令读取非广告图片目录的文件；`standalonecomm` 进程异常打开 `/etc/shadow`、数据库或配置。
- 防御：对文件名做规范化并校验必须位于允许目录内，拒绝绝对路径与 `..`；不要用用户输入直接拼路径。
- 防御：修改默认 COMKey、限制 4370/TCP 来源、升级固件；服务以最小权限运行，避免 root 读取全部文件。
- 加固：对协议命令做长度/字段校验与审计，关闭不需要的下载/上传命令。
