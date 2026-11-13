---
id: iot-tapo-third-account-rtsp-config-ciphertext-backdoor
title: Tapo 摄像头 RTSP 后门账户：改 user_management 的 third_account（passwd 大写 MD5 + 复用另一台 App 生成的 RSA ciphertext），写回 flash 重启后用 VLC 看流
type: scenario
domain: iot
path: iot
technique: tapo-third-account-rtsp-config-ciphertext-backdoor
tags:
- iot
- camera
- rtsp
- backdoor-account
- config-tampering
- persistence
- uart
- tapo
- physical-access
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V682
  verified_at: '2026-11-13T13:54:05+08:00'
  notes: 已对照原文与25图核对：图12 user_management 中 root 段含 username/passwd/ciphertext/sharepwd，third_account 默认 username/passwd 为 '---' 且 ciphertext 为长 base64；图14-17 Binary Ninja uci_lookup_next('ciphertext')→rsa_decrypt→private_decrypt（PEM_read_bio_RSAPrivateKey、rsa_base64_decode、RSA_private_decrypt）；图13 App 的 RTSP 第三方账户风险提示；图18 shell.py 自动进入 root shell；图19 VLC 播放 rtsp://192.168.1.139/stream1 成功。passwd 需大写十六进制、ciphertext 跨设备复用（第二台设备实测）与原文一致。原文明确省略部分步骤且不发布后门 Python 代码、'仅凭本文无法完全复现'，卡 confidence medium 如实。与 rtsp-weakauth-unauth-surveillance-view、app-login-hook 等 dedup 候选非同一条链。原文无版本标记，未设 affected_versions。未在本环境复现。
url: /docs/iot/iot-tapo-third-account-rtsp-config-ciphertext-backdoor/
draft: false
kb_aliases:
- Tapo RTSP 后门
- third_account 后门
- user_management 配置修改
- ciphertext 复用
- RTSP 账户持久化
- Tapo 摄像头 UART 后门
---

## 一句话结论

通过 UART root shell 拿到 Tapo 摄像头的 `/tmp/etc/uc_conf/user_management` 后，把默认禁用的 `third_account`（RTSP 专用账户）改成已知用户名与**大写十六进制 MD5** 的口令，并把 `ciphertext` 设为从另一台设备上由官方 App 生成的合法 RTSP 账户密文（RSA 加密、密钥硬编码在 `libdecrypter.so` 且设备间通用），写回 flash 重启，即可用 `rtsp://<ip>/stream1` 直接观看实时视频；该账户在 App 里默认不可见，只有用户主动启用 RTSP 功能时才可能被发现。

## 原理

- **配置结构**：`uc_convert -t 0` 解出的 `/tmp/etc/uc_conf/user_management` 包含：
  ```text
  config root 'root'
      option username 'admin'
      option passwd '<MD5>'
      option ciphertext '<长 base64>'
      option sharepwd '<...>'
  config third_account 'third_account'
      option username '---'
      option passwd '---'
      option ciphertext '<长 base64>'
  ```
  `root` 是 App 主账户；`third_account` 用于 RTSP/NVR/NAS 第三方访问，默认用户名为 `---`（禁用），必须在 App 中主动启用 RTSP 才会创建。
- **两套校验并存**：App/配置层用 `passwd`（密码的简单 MD5，注意必须是**大写**十六进制，否则校验不过）；RTSP 流媒体认证使用 `ciphertext`（RSA 加密的凭据数据）。只改 username/passwd 而不同时改 ciphertext，VLC 会返回认证失败——作者实测如此。
- **ciphertext 为什么能跨设备复用**：`libdecrypter.so` 的 `rsa_decrypt → private_decrypt` 从固件中加载 RSA 私钥（`PEM_read_bio_RSAPrivateKey` + `rsa_base64_decode` + `RSA_private_decrypt`），私钥硬编码/所有设备相同；因此在一台设备上通过 App 生成合法 RTSP 账户得到的 ciphertext，可以复制到另一台设备的配置里并被接受。
- **持久化**：把修改后的 `user_management` 写回 flash 的 config 分区并重启，后门账户随配置生效；它不出现在 App 的普通账户列表里，只有用户主动打开 RTSP 设置时才可能看到 `third_account`。攻击者随后在同一局域网用 VLC 访问 `rtsp://<ip>/stream1` 即可（原文成功看到实时画面）。
- **前提**：需要物理接触 + UART root shell（见关联卡）；ciphertext 需要另一台同族设备/App 生成，或逆向 `libdecrypter.so` 的 RSA 私钥自行加密。原文明确省略了部分步骤与用于后门的 Python 代码，"仅凭本文无法完全复现"，故本卡 confidence 记为 medium。

## 触发条件

- 能物理接触设备并通过 UART/U-Boot 获得 root shell（或能以其他方式读写 `/tmp/etc/uc_conf/user_management` 与 config 分区）。
- 设备已启用过（root 账户已配置）；`third_account` 处于默认禁用状态。
- 有一台同族设备/官方 App 可生成合法 RTSP 账户 ciphertext，或能提取 `libdecrypter.so` 中的 RSA 私钥。
- 攻击者与摄像头在同一网络（RTSP 默认 554/stream1）。
- 配置分区可写且无签名校验。

## 利用步骤

1. UART root shell 下执行 `uc_convert -t 0` 解出配置，读取 `/tmp/etc/uc_conf/user_management`。
2. 准备后门账户：`username 'backdoor'`；`passwd` 设为口令的 **大写** MD5（如 `Password206` 的 MD5）；`ciphertext` 填入另一台设备 App 生成的合法 RTSP 账户密文。
3. 用设备自带的 `vi` 修改 `user_management` 的 `third_account` 段，保存。
4. 将修改后的配置写回 config 分区/flash（按设备的分区与挂载方式），重启摄像头。
5. 在同一局域网用 VLC 打开 `rtsp://<camera-ip>/stream1`，用后门用户名/口令认证，观看实时画面。
6. 清理/恢复：攻击者通常会把配置改回或保留后门；防守方需比对配置哈希/备份。

## PoC

```text
# 配置片段（示意，原文截图）
config third_account 'third_account'
    option username 'backdoor'
    option passwd '<MD5(Password206) 大写>'
    option ciphertext '<从另一台设备复制的合法 RTSP ciphertext>'

# 设备内编辑
vi /tmp/etc/uc_conf/user_management
# 写回 config 分区并 reboot

# 攻击者侧
vlc rtsp://192.168.1.139/stream1
```

## 变体与关联

- **同族设备**：TC100/TC200/TC60 的 RTSP 配置结构类似；ciphertext 跨设备复用依赖相同的硬编码 RSA 私钥。
- **其他摄像头持久化**：`[[iot-camera-wifi-psk-shell-injection-jffs2-persistence]]` 通过 Wi-Fi 配网命令注入改 root 口令并写入 jffs2 持久化；本卡是配置层 RTSP 后门账户，二者都以“配置/分区可写且无完整性校验”为根因。
- **RTSP 直接弱口令**：`[[rtsp-weakauth-unauth-surveillance-view]]` 是不需要物理接触的弱口令/未授权访问；本卡是在已 root 设备上植入隐蔽账户。
- 前置：`[[iot-hardware-tapo-tc60-uart-uboot-init-sh-root-shell-sd-dump]]`；配置解密：`[[iot-hardware-tapo-config-des-ecb-model-version-hash-key]]`。

## 检测与防御

- **配置完整性**：对 config 分区做签名/HMAC，启动时校验；不允许手工修改 `user_management` 生效。
- **账户检查**：在 App/固件中显式展示 `third_account` 状态；即使用户未启用 RTSP，也监测该段是否被改为非 `---`；定期比对配置与备份。
- **网络侧**：RTSP 554 仅限可信内网，监测异常客户端连接与 `stream1` 拉流；对摄像头 VLAN 隔离。
- **硬件/固件**：关闭 UART、启用安全启动、每设备唯一密钥，防止物理接触后改配置。
- **响应**：发现疑似后门账户时，导出配置、比对 `third_account` 与 ciphertext 来源，重置设备并升级固件。
