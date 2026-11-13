# IoT 协议

## 这层是什么

MQTT、CoAP、Modbus、Zigbee 等。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Android BLE HCI 抓包：btsnoop_hci 日志提取与 Wireshark 分析](iot-protocol-ble-android-hci-btsnoop-capture.md) | verified | high | 2026-11-06 |
| [BLE 智能灯泡 GATT 协议逆向与重放：nRF Sniffer 抓 ATT Write 后直接控制开关](iot-protocol-ble-smart-bulb-att-write-replay.md) | verified | high | 2026-11-06 |
| [BLE 空口抓包：nRF Sniffer + Wireshark 跟踪 CONNECT_IND 与跳频](iot-protocol-ble-ota-nrf-sniffer-capture.md) | verified | high | 2026-11-06 |
| [CAN 功能帧定位：candump 录制后用 canplayer 二分重放收窄到单帧，再用 cansend/ SavvyCAN 位级 fuzz 找出控制字段](iot-protocol-can-bisection-replay-bit-fuzz.md) | verified | medium | 2026-11-10 |
| [CAN 总线仲裁 ID 逆向与伪造：ICSim/cansniffer 定位功能帧 + cansend 注入](iot-protocol-can-arbitration-id-discovery-spoofing.md) | verified | high | 2026-11-06 |
| [CAN 总线重放攻击：candump 记录合法帧 + canplayer 回放](iot-protocol-can-replay-candump-canplayer.md) | verified | high | 2026-11-06 |
| [CAN 报文车速信号识别与路程估算：按 ID 分组找单字节变化帧，积分 36s 得行驶距离](iot-protocol-can-speed-signal-distance-integration.md) | verified | high | 2026-11-07 |
| [CAN 日志 + 信号映射表隐藏数据提取：按 sig_N 末值拼出 ASCII 字符串](iot-protocol-can-signal-map-log-hidden-data.md) | verified | high | 2026-11-06 |
| [CAN 日志信号挖掘：按 ID 估周期、定位变化字节/位并区分计数器与校验](iot-protocol-can-log-signal-mining.md) | verified | high | 2026-11-06 |
| [CAN/ISO-TP 多帧重组“先拷贝后检查长度”：越界写覆盖完成回调指针并 ROP 读取 flag](iot-protocol-can-isotp-reassembly-length-check-after-copy-overflow.md) | verified | high | 2026-11-07 |
| [D-Link DIR-645 cgibin ssdpcgi HTTP_ST 环境变量命令注入（CVE-2024-22651 同类）](iot-protocol-dlink-dir645-ssdpcgi-command-injection.md) | verified | high | 2026-11-06 |
| [HART-IP Command 9 状态字段高两位隐蔽信道：四元符号 + 设备身份派生 XTEA 密钥的外传](iot-protocol-hartip-command9-quadrant-covert-channel.md) | verified | high | 2026-11-05 |
| [IPMI 2.0 Cipher 0 认证绕过：已知用户名 + 任意密码登录 BMC（CVE-2013-4782）](iot-protocol-ipmi-cipher-zero-auth-bypass.md) | verified | high | 2026-11-05 |
| [IPMI 2.0 RAKP 哈希泄露：无认证获取用户 HMAC-SHA1 并离线破解](iot-protocol-ipmi-rakp-hash-disclosure.md) | verified | high | 2026-11-05 |
| [MQTT logs topic 命令注入：SM4+0xBF+Base64 封装 info 字段，换行逃逸 system 执行命令](iot-protocol-mqtt-logs-topic-sm4-command-injection.md) | verified | high | 2026-11-09 |
| [MQTT 消息回调命令注入：绕过 clientid 过滤 + 全局 cmd 缓冲区未清零的两阶段利用](iot-protocol-mqtt-callback-clientid-filter-global-cmd-buffer-injection.md) | verified | high | 2026-11-06 |
| [NFC 数字钥匙中继攻击：NFCgate tag/reader + 中继服务器延长通信距离](iot-protocol-nfc-digital-key-relay-attack.md) | verified | high | 2026-11-06 |
| [PPCS P2P 明文 UDP 控制协议逆向与模拟：PPP/DRW 包头 + JSON 指令自构造（含明文 pwd）](iot-protocol-ppcs-p2p-plaintext-udp-json-simulator.md) | verified | medium | 2026-11-08 |
| [RTPS/DDS writer 身份无认证伪造：克隆 guidPrefix/entityId/SN 下发伪造控制指令](iot-protocol-rtps-dds-writer-spoofing.md) | verified | medium | 2026-11-06 |
| [RTSP 公开流 OSD 泄露 Base64 凭据：抓取维护流并用 H.264 解包读 flag](iot-protocol-rtsp-osd-credential-leak-h264-capture.md) | verified | high | 2026-11-06 |
| [RTSP 弱口令/未授权访问实时监控流（Basic/Digest 爆破后 VLC 直连查看）](rtsp-weakauth-unauth-surveillance-view.md) | verified | high | 2026-11-08 |
| [SOME/IP-SD 无认证：伪造 StopOffer 下线制动服务，再冒充服务分片下发加密制动指令](iot-protocol-someip-sd-stopoffer-spoof-tp-command.md) | verified | high | 2026-11-05 |
| [UDS RoutineControl 0x31 例程 ID 爆破：枚举隐藏 routineIdentifier 并执行取结果](iot-protocol-uds-routinecontrol-rid-bruteforce.md) | verified | high | 2026-11-06 |
| [UDS RoutineControl 0x31 停发 ECU 周期报文 + CAN 注入接管车辆](iot-protocol-uds-routinecontrol-can-injection-takeover.md) | verified | high | 2026-11-06 |
| [ZKTeco 4370/TCP 协议 COMKey 认证缺陷：默认 0 + 6 位可爆破 + 可逆 MAC 从抓包还原口令](iot-protocol-zkteco-4370-comkey-reversible-mac-auth.md) | verified | high | 2026-11-08 |
| [ZKTeco pushcomm 云服务 SHELL 指令：把设备指向恶意 HTTP 服务器即执行任意 root 命令](iot-protocol-zkteco-pushcomm-shell-command-server-hijack.md) | verified | high | 2026-11-08 |
| [ZKTeco standalonecomm CMD_DELETE_PICTURE 命令注入：图片名拼进 system("rm %s") 以 root 执行](iot-protocol-zkteco-standalonecomm-delete-picture-command-injection.md) | verified | high | 2026-11-08 |
| [ZKTeco standalonecomm CMD_DOWNLOAD_PICTURE 目录穿越：图片文件名未校验读取任意文件（含 /etc/shadow）](iot-protocol-zkteco-standalonecomm-download-picture-path-traversal.md) | verified | medium | 2026-11-08 |
| [佳能打印机 DryOS NetBIOS 名称解析堆溢出：标签偏移空转推高写指针，2 字节 WWW 改函数指针执行 shellcode](iot-protocol-canon-dryos-netbios-name-parser-heap-overflow-function-pointer-rce.md) | verified | medium | 2026-11-13 |
| [华为 HG532 UPnP DeviceUpgrade SOAP 命令注入](iot-protocol-huawei-hg532-upnp-deviceupgrade-command-injection.md) | verified | high | 2026-11-04 |
| [固件 Web 接口把推流目标 IP 交给用户控制：请求 url= 参数即让设备把加密图像经 RTP 推出，抓包剥 12 字节头后用固件里的 aes_key.bin 解密](iot-protocol-firmware-push-api-rtp-aes-exfil-decrypt.md) | verified | medium | 2026-11-09 |
| [摄像头 P2P DownloadFile 任意路径下载：读 /proc/mounts 后拉取 /dev/root 与 /dev/mtdblock 镜像挂载提取文件系统](iot-protocol-camera-downloadfile-arbitrary-file-read-mtd-mount.md) | verified | high | 2026-11-08 |
| [车联网 MQTT 诊断服务：VIN 的 31 进制滚动哈希当 auth，set_vin 全局 arg 经 sleep(2) 竞态注入读 flag](iot-protocol-mqtt-vin-hash-auth-set-vin-command-injection.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
