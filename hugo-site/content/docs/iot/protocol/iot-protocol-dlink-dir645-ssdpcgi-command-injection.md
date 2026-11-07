---
id: iot-protocol-dlink-dir645-ssdpcgi-command-injection
title: D-Link DIR-645 cgibin ssdpcgi HTTP_ST 环境变量命令注入（CVE-2024-22651 同类）
type: scenario
domain: iot
path: iot/protocol
technique: ssdp-st-header-env-sprintf-system-command-injection
tags:
- iot
- upnp
- ssdp
- dlink
- router
- firmware
- command-injection
- cve-2024-22651
- mips
cve:
- CVE-2024-22651
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: D-Link DIR-645 A1；D-Link DIR-815 firmware v1.04（CVE-2024-22651）
verification:
  verified_by: verifier-V132
  verified_at: '2026-11-06T05:49:15+08:00'
  notes: 已对照原文及12张图核对：ssdpcgi_main getenv→sprintf→lxmldbc_system→system 链、HTTP_ST/REMOTE_* 注入、CVE-2024-22651 与 DIR-850L 补丁分析一致；原文仅用 QEMU -E 环境变量复现，未给真实 M-SEARCH 报文，真机网络触发链路未逐包验证。
url: /docs/iot/protocol/iot-protocol-dlink-dir645-ssdpcgi-command-injection/
draft: false
kb_aliases:
- DIR-645
- DIR-815
- CVE-2024-22651
- ssdpcgi
- ssdpcgi_main
- cgibin
- HTTP_ST
- lxmldbc_system
- M-SEARCH 命令注入
- D-Link 路由器命令执行
---

## 一句话结论

D-Link DIR-645 A1 的 `cgibin` 中 `ssdpcgi_main` 把 SSDP M-SEARCH 请求派生的 `HTTP_ST`、`REMOTE_ADDR`、`REMOTE_PORT`、`SERVER_ID` 环境变量原样拼进 `"%s ssdpall %s:%s %s &"` 一类命令模板，经 `lxmldbc_system()` 的 `vsnprintf` 后交给 `system()`；`HTTP_ST` 用 `upnp:rootdevice;命令>` 这类“合法前缀 + 分号”即可注入任意命令，以 root 权限执行。同一 `ssdpcgi_main` 缺陷已被记为 CVE-2024-22651（描述指向 DIR-815 firmware v1.04）。

## 原理

- **入口**：`cgibin` 是多合一 CGI 分发器，按 argv 选择处理函数；当传入名称为 `ssdpcgi` 时跳到 `ssdpcgi_main`。
- **取参**：`ssdpcgi_main` 在 `argc == 2` 时执行 `getenv("HTTP_ST")`、`getenv("REMOTE_ADDR")`、`getenv("REMOTE_PORT")`、`getenv("SERVER_ID")`，只检查指针非空，不检查内容。这些变量由设备的 SSDP/UPnP 请求处理路径填充，`HTTP_ST` 对应 M-SEARCH 的 `ST` 头。
- **拼接**：按 `HTTP_ST` 前缀选择命令模板并直接 `sprintf` 成整条 shell 命令，例如：
  - `ssdp:all` → `"%s ssdpall %s:%s %s &"`
  - `upnp:rootdevice` → `"%s rootdevice %s:%s %s &"`
  - `uuid:` → `"%s uuid %s:%s %s &"`
  - 含 `:device:` / `:service:` → `"%s devices ..."` / `"%s services ..."`
  第一个 `%s` 仍是原始 `HTTP_ST` 值，因此合法前缀后追加 `;` 即可截断。
- **执行**：`lxmldbc_system(format, ...)` 内部 `vsnprintf(s, 0x400, format, va)` 后 `return system(s)`。`system()` 走 `/bin/sh -c`，用户可控字符串中的 `;`、`|`、`&&`、`$()`、反引号在拼好的命令串里重新获得 shell 语义。
- **为什么成立**：过滤只发生在“分支选择”层面（前缀 `strncmp`），没有任何字符转义或白名单；命令串在 shell 解析前已把用户输入当作命令文本的一部分，因此前缀匹配反而给了攻击者一个可预测的注入锚点。
- **权限**：`cgibin` 由设备 Web/SSDP 服务以 root 启动，注入命令继承 root。

## 触发条件

- 目标为 D-Link DIR-645 A1，或使用同一 `cgibin`/`ssdpcgi_main` 代码的固件（CVE-2024-22651 记录的是 DIR-815 firmware v1.04）。
- 设备的 SSDP/UPnP 处理路径可达，且会把 M-SEARCH 的 `ST` 头传入 `cgibin ssdpcgi` 的 `HTTP_ST` 环境变量；`REMOTE_ADDR`/`REMOTE_PORT`/`SERVER_ID` 同样由请求侧派生。
- `HTTP_ST` 必须以代码识别的前缀开头（`ssdp:all`、`upnp:rootdevice`、`uuid:`、`urn:`、含 `:device:`/`:service:` 的 URN），否则不进入对应模板；前缀后接 `;` 即可。
- 注意：原文的 PoC 是在 QEMU 用户态直接以 `-E` 设置环境变量复现，未给出真实 M-SEARCH 报文；“远程可达”依据 CVE-2024-22651 的描述与代码对环境变量的取值逻辑，真机网络触发链路未在原文中逐包展示。

## 利用步骤

1. 解包固件（binwalk/unsquashfs），定位 `htdocs/cgibin`，在 IDA 中交叉引用 `getenv("HTTP_ST")` 与 `lxmldbc_system`，确认 `ssdpcgi_main` 与命令模板。
2. 本地用 QEMU 用户态复现：以 `-0 "ssdpcgi"` 指定 argv[0]，用 `-E` 注入四个环境变量，运行 `./htdocs/cgibin ssdpcgi`；可在 `ssdpcgi_main+172`（案例地址 `0x40A79C`）下断点观察拼接后的命令串。
3. 令 `HTTP_ST="upnp:rootdevice;ls>"`、`REMOTE_PORT=";ls;"`，观察 `ls` 输出与 `router: not found` 等 shell 执行痕迹，确认命令注入。
4. 真机/仿真网络路径：向设备的 SSDP 端口发送 `ST` 头为 `upnp:rootdevice;<命令>;` 的 M-SEARCH（UDP 1900），或经设备 Web 侧触发 `ssdpcgi` 的入口；无回显时用写文件、DNS/HTTP 带外或反弹 shell 验证。
5. 命令执行后可按需读取 `/etc` 配置、写入持久化脚本或反弹 shell；精简 busybox 注意可用命令与路径。

## PoC

原文的 QEMU 用户态最小复现（MIPS 小端）：

```bash
# 在固件根文件系统目录内执行；pay 为 0x100 字节填充，原文用 cyclic(0x100)
qemu-mipsel -L . \
  -0 "ssdpcgi" \
  -E HTTP_ST="upnp:rootdevice;ls>" \
  -E REMOTE_ADDR="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  -E REMOTE_PORT=";ls;" \
  -E SERVER_ID="router" \
  -g 6666 \
  ./htdocs/cgibin ssdpcgi
```

原文另一张截图使用 `uuid:` 分支：`HTTP_ST="uuid:<0x100 字节填充>>"`、`REMOTE_ADDR="192.168.1.101"`、`REMOTE_PORT="LAN-1"`、`SERVER_ID="LAN-1"`，同样进入 `lxmldbc_system`。

核心拼接逻辑（IDA 伪代码要点）：

```c
haystack = getenv("HTTP_ST");
v3 = getenv("REMOTE_ADDR");
v5 = getenv("REMOTE_PORT");
v4 = getenv("SERVER_ID");
if (haystack && v3 && v5 && v4) {
    if (!strncmp(haystack, "upnp:rootdevice", 0xF))
        sprintf(buf, "%s rootdevice %s:%s %s &", haystack, v3, v5, v4);
    /* 其他前缀分支同样汇聚到 */
    lxmldbc_system(buf);   /* vsnprintf(s,0x400,fmt,va); system(s); */
}
```

无真实 M-SEARCH 报文 PoC；网络触发需按设备 SSDP 服务实现补齐。

## 变体与关联

- **注入点变体**：`HTTP_ST` 是主注入点；同一 `sprintf` 行里的 `REMOTE_ADDR`、`REMOTE_PORT`、`SERVER_ID` 在旧版同样未校验，可任选其一注入。
- **前缀变体**：`ssdp:all`、`upnp:rootdevice`、`uuid:`、`urn:`、`:device:`、`:service:` 等分支最终都调用 `lxmldbc_system`，按目标分支选择前缀即可。
- **补丁对比（DIR-850L）**：修复版对 `HTTP_ST` 做白名单（`ssdp:all`→固定串、`upnp:rootdevice`→固定串、`uuid:`→按 `%08llX-%04llX-...` 重新格式化数字、其余仅匹配固定 URN 列表），`REMOTE_ADDR` 用 `inet_pton`/`inet_ntop` 校验 IPv4/IPv6，`REMOTE_PORT` 要求 `strlen < 6` 且 `strtol` 转数字，`SERVER_ID` 走 `"BRIDGE-1"` 等白名单；任一校验失败置 `dword_439F60 = 0` 不执行。该白名单很紧，原文测试未找到绕过。
- **关联**：[[iot-protocol-huawei-hg532-upnp-deviceupgrade-command-injection]]（UPnP 请求字段拼 `system()` 的同类路由器 RCE）、[[iot-firmware-boa-pin-command-injection]]（D-Link 固件 CGI 参数拼 `system()`）、[[code-analysis-reverse-firmware-qemu-user-mips-ldpreload-gdb]]（QEMU 用户态仿真方法）。

## 检测与防御

- **检测**：SSDP M-SEARCH 的 `ST`/`USN` 头出现 `;`、`|`、`&&`、`$(`、反引号、换行；`cgibin`/`ssdpcgi` 进程出现异常子进程或长时间阻塞在 `system()`；设备 `/tmp`、`/var` 出现异常文件；UDP 1900 出现非常规扫描与畸形 ST 头。
- **防御**：升级到修复固件（DIR-850L 一类的白名单+类型校验实现）；无法升级时在边界封禁 WAN 侧 UDP 1900 与 UPnP/SSDP，关闭不必要的 UPnP 服务。
- **代码层**：不要用 `sprintf` + `system()` 拼接请求头/环境变量；改用 `execve` 传 argv，或对 `ST` 做严格白名单（固定 URN 列表）并在拼接前做字符集校验。
- **加固**：`cgibin` 与 Web 服务降权运行；设备管理面限制在可信网段；固件签名与安全启动。
