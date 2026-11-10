---
id: iot-tplink-wr740-httpdebug-backdoor-pty-cmd
title: TP-Link WR740 固件调试后门：httpDebugInit 注册隐藏 URL + 硬编码 osteam/5up + pty 命令执行
type: scenario
domain: iot
path: iot
technique: tplink-wr740-httpdebug-backdoor-pty
aliases:
- TP-Link WR740 后门
- httpDebugInit
- httpRpmConfAdd
- linux_cmdline.html
- start_art.html
- DebugResultRpm.htm
- userRpmNatDebugRpm26525557
- CmdRpmHtm
- osteam/5up
- 路由器调试后门
tags:
- iot
- router
- tplink
- firmware
- backdoor
- httpd
- command-execution
- pty
- hardcoded-credentials
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: wr740nv1_en_3_12_4_up.bin（WR740N v1 固件，原文复现版本）
verification:
  verified_by: verifier-V284
  verified_at: '2026-11-08T05:12:08+08:00'
  notes: 已对照原文与全部14张图片核对：图9 CmdRpmHtm 伪代码 pty_started/httpGetEnv(cmd)/strcmp(exit)/osteam/5up/write(pty,v6,v9)，图10 write 到 pty 说明，图11 httpDebugInit 经 httpRpmConfAdd 注册 start_art.html->ArtRpmHtm、linux_cmdline.html->CmdRpmHtm、DebugResultRpm.htm->DebugResultRpmHtm，图12-13 FirmAE 检查 192.168.1.1 Web 可达（-c/-r），图14 先 admin/admin 认证后访问隐藏 URL 填写 osteam/5up+ls，回显 BusyBox v1.01 与目录列表，均与原文一致。图1-7 为 FirmAE/binwalk/bc/fdisk 环境排错（部分为 D-Link DIR-868L 示例），卡片未将其误作漏洞内容。affected_versions 按原文固件 wr740nv1_en_3_12_4_up.bin（WR740N v1）保留（IoT 设备卡，非组件区间规则）。dedup 0 related/new；dup-scan 无涉及 pair。PoC 未复跑。
---

## 一句话结论

TP-Link WR740N v1 固件 `wr740nv1_en_3_12_4_up.bin` 的 httpd 中存在调试后门：`httpDebugInit` 通过 `httpRpmConfAdd` 注册三个不在界面暴露的 URL，其中 `/userRpmNatDebugRpm26525557/linux_cmdline.html` 由 `CmdRpmHtm` 处理——它从请求参数 `cmd` 取命令，校验硬编码的用户名 `osteam` 与密码 `5up`，再用 `write(pty, cmd, strlen(cmd))` 把命令写入伪终端执行，结果回显在页面。攻击者先以 Web 管理口令（仿真中为默认 `admin/admin`）登录，再访问该隐藏 URL 即可执行任意命令；文章在 FirmAE 仿真中执行 `ls` 验证成功。

## 原理

- **隐藏 URL 注册**：httpd 中的 `httpDebugInit()` 调用 `httpRpmConfAdd(2, "/userRpmNatDebugRpm26525557/start_art.html", &ArtRpmHtm)`、`httpRpmConfAdd(2, "/userRpmNatDebugRpm26525557/linux_cmdline.html", &CmdRpmHtm)`、`httpRpmConfAdd(2, "/userRpm/DebugResultRpm.htm", &DebugResultRpmHtm)`。函数名与 URL 中的 `NatDebugRpm26525557` 表明这是调试用途的后门入口，正常管理界面不会链接到它。
- **CmdRpmHtm 的命令执行**：伪代码显示当 `pty_started` 为真时，`Env = httpGetEnv(a1, "cmd")` 取命令；`strcmp(Env, "exit")` 不为 0 时继续；随后用 `httpGetEnv(a1, <用户名常量>)` 与 `httpGetEnv(a1, "passwd")` 分别与 `osteam`、`5up` 比较，任一不符就把 `####User or Password not correct###` 写入输出缓冲区；匹配后执行 `write(pty, Env, strlen(Env))`。`pty` 是连接到 shell 的伪终端，写入的字符串被 shell 当作命令执行，结果通过页面输出（示例页面显示 BusyBox 版本与 `ls` 结果）。
- **硬编码凭据与默认口令**：调试后门使用独立的硬编码 `osteam/5up`，不随管理员密码变化；但入口仍需先通过 Web 管理登录（示例登录 `admin/admin` 默认口令），因此是认证后后门。默认口令使该后门在未改密的设备上很容易被利用。
- **HTTP 处理方式**：`httpRpmConfAdd` 把 URL 与处理函数绑定，`httpGetEnv` 从请求中取参数；`start_art.html`/`DebugResultRpm.htm` 分别用于启动调试与结果查看，属于同一调试后门组件。
- **为什么可行**：调试代码被编入量产固件，隐藏路径没有从路由表移除，硬编码账密和 pty 执行逻辑完整保留；攻击者只要能登录 Web 管理面并访问该路径，就能以 httpd 权限（通常 root）执行命令。
- **边界**：属于固件特定后门，其他型号/固件版本不一定存在相同路径；需要 Web 管理登录或已劫持会话；设备若只允许 LAN 管理，攻击面限于内网/已横向进入的网络。

## 触发条件

- 目标运行 TP-Link WR740N v1 固件（原文 `wr740nv1_en_3_12_4_up.bin`），httpd 中包含 `httpDebugInit` 与调试路由。
- 攻击者可访问路由器 Web 管理面并能登录（默认 `admin/admin` 或已获取口令/会话）。
- `/userRpmNatDebugRpm26525557/linux_cmdline.html` 可访问，调试 pty 已启动（`pty_started` 为真）。
- 攻击者知道硬编码调试凭据 `osteam/5up`（可从固件字符串/IDA 中提取）。

## 利用步骤

1. 固件解包：`binwalk -Me wr740nv1_en_3_12_4_up.bin`，定位 `squashfs-root` 中的 `/usr/bin/httpd`。
2. 用 firmwalker.sh 等扫描敏感信息（passwd、`HttpDebugRpm.htm`、`/usr/bin/httpd` 等），确认 Web 服务为 httpd。
3. IDA 静态分析 httpd：定位 `httpDebugInit`，跟随 `httpRpmConfAdd` 找出隐藏 URL 与处理函数；进入 `CmdRpmHtm` 查看 `cmd`/用户名/密码比较与 `write(pty, cmd, strlen(cmd))`。
4. 在 FirmAE 中仿真（或使用真实设备）：`sudo ./run.sh -c tp-link '<固件路径>'` 检查可仿真，`sudo ./run.sh -r tp-link '<固件路径>'` 启动，确认 Web 服务在 `192.168.1.1` 可达。
5. 用 `admin/admin` 登录路由器 Web 管理面。
6. 访问 `http://192.168.1.1/userRpmNatDebugRpm26525557/linux_cmdline.html`，在页面填写 Username=`osteam`、Password=`5up`、Command=`ls`，点击 SEND；页面回显 BusyBox 版本与目录列表即命令执行成功。
7. 将 Command 换成 `id`、`cat /etc/shadow` 等验证权限与影响；在授权测试中记录输出并清理痕迹。

## PoC

无独立脚本；操作要点如下：

```text
# 1) 固件解包与定位
binwalk -Me wr740nv1_en_3_12_4_up.bin
# httpd: squashfs-root/usr/bin/httpd
# IDA: httpDebugInit -> httpRpmConfAdd 注册
#   /userRpmNatDebugRpm26525557/start_art.html   -> ArtRpmHtm
#   /userRpmNatDebugRpm26525557/linux_cmdline.html -> CmdRpmHtm
#   /userRpm/DebugResultRpm.htm                  -> DebugResultRpmHtm
# CmdRpmHtm: cmd 参数 -> 检查 osteam/5up -> write(pty, cmd, strlen(cmd))

# 2) FirmAE 仿真
sudo ./run.sh -c tp-link '/path/wr740nv1_en_3_12_4_up.bin'
sudo ./run.sh -r tp-link '/path/wr740nv1_en_3_12_4_up.bin'

# 3) 浏览器（先 admin/admin 登录）
http://192.168.1.1/userRpmNatDebugRpm26525557/linux_cmdline.html
# Username: osteam
# Password: 5up
# Command:  ls   -> SEND
```

页面示例回显：BusyBox v1.01 版本信息、`####User or Password not correct###`（错误凭据提示）以及 `ls` 的目录列表（`dev-model.conf`、`etc`、`home`、`media`、`samba`、`var`、`www` 等）。

## 变体与关联

- [[iot-tplink-ax1800-luci-locale-country-command-injection]]：同为 TP-Link 路由器的命令注入，但那张卡是 LuCI locale/country 参数拼接，本卡是固件内置调试后门 + 硬编码凭据 + pty。
- [[iot-dlink-nas-sharing-cgi-messagebus-backdoor-base64-system-rce]]：D-Link NAS 硬编码 messagebus 后门 + system 命令注入，可对照厂商后门的发现与利用方式。
- [[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]：MIPS 路由器固件系统级仿真（QEMU malta + httpd），与本卡 FirmAE 仿真互补。
- 变体：其他 TP-Link/路由器固件可能存在类似 `NatDebug`/`DebugRpm` 隐藏调试路径，可在 strings/IDA 中搜索 `httpDebugInit`、`httpRpmConfAdd`、`DebugRpm`、硬编码账号与 `pty` 使用点。
- 边界：认证后利用；若管理员修改默认口令且限制 LAN 访问，入口门槛提高；不同固件版本可能删除或改名调试路径。

## 检测与防御

- **检测（固件/主机）**：固件字符串中出现 `NatDebug`、`httpDebugInit`、`httpRpmConfAdd`、`linux_cmdline.html`、`osteam`、`5up`、`User or Password not correct`；httpd 二进制中存在 `write` 到 pty 的调试处理函数。
- **检测（网络）**：Web 访问日志出现 `/userRpmNatDebugRpm26525557/`、`start_art.html`、`linux_cmdline.html`、`DebugResultRpm.htm`；请求参数含 `cmd`、`passwd` 与硬编码用户名；异常命令输出（`id`、`cat /etc/shadow`、`ls`）。
- **防御**：升级/更换移除调试后门的固件；修改默认 `admin/admin` 口令并限制 Web 管理仅内网/管理网；WAF/反向代理屏蔽 `NatDebug`/`DebugRpm` 路径；对固件做发布前审计（搜索隐藏路由、硬编码凭据、pty/system 执行）；关闭不必要的远程管理。
- **响应**：阻断并审计相关 URL 访问；检查设备是否被植入持久化；恢复出厂/刷入可信固件并修改所有口令。
