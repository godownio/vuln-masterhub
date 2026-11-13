# 车联网

## 这层是什么

车机 ADB/调试口、车载摄像头服务、蓝牙 HID、GNSS 欺骗与车云接口。

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
| [CAN 扩展帧 UDS 诊断寻址与 ECU 枚举：遍历 18DAxxF1 发现 ECU 并用 ccplus 做服务扫描](iot-vehicle-can-extended-frame-uds-ecu-discovery.md) | verified | high | 2026-11-11 |
| [OBD-II 物理接入读取 CAN 总线报文：针脚定义、接线与请求/响应帧解析](iot-vehicle-obd-can-bus-access.md) | verified | medium | 2026-11-11 |
| [特斯拉车网关 UDP 20100/20101 端口伪造 CAN 报文：车内部件沦陷后直接控制后备箱/门锁](iot-vehicle-tesla-gateway-udp-can-injection.md) | verified | medium | 2026-11-13 |
| [车机 adb shell 二次密码认证：导出 /system 下 verify_sh 逆向出硬编码口令 adb36987 绕过](iot-vehicle-adb-shell-verify-sh-hardcoded-password.md) | verified | high | 2026-11-13 |
| [车机 GPS L1 信号欺骗：gps-sdr-sim 生成伪卫星信号经 HackRF 发射伪造定位](iot-vehicle-gps-l1-spoofing-gps-sdr-sim-hackrf.md) | verified | high | 2026-11-07 |
| [车机 OTA 握手泄露 session_key：AES-CBC 前置 IV 解密 ota/init 双向流量读取 admin flag](iot-vehicle-ota-handshake-session-key-aes-cbc-zero-iv.md) | verified | high | 2026-11-07 |
| [车机 U 盘 automount 用磁盘 LABEL 拼挂载路径：LABEL 设为 ../../usr/bin 目录穿越覆盖系统命令反弹 shell](iot-vehicle-usb-label-mount-path-traversal-logger-shell.md) | verified | medium | 2026-11-13 |
| [车机 WiFi 热点同名同密码仿冒：克隆 SSID+PSK+BSSID 后车机自动重连，形成中间人入口](iot-vehicle-wifi-evil-twin-auto-reconnect-mitm.md) | verified | medium | 2026-11-08 |
| [车机摄像头调试服务 TCP 20000 未授权 console：camera 矩阵与 PTS/倒车辅助参数篡改](iot-vehicle-camera-debug-console-20000-unauth.md) | verified | medium | 2026-11-07 |
| [车机特殊模式口令开启 ADB：adb shell 数据窃取与 SUID 后门提权 root](iot-vehicle-adb-special-mode-password-root.md) | verified | medium | 2026-11-07 |
| [车机蓝牙 HID 键盘仿冒：未授权配对后模拟按键控车与 PIN/密钥爆破](iot-vehicle-bluetooth-hid-keyboard-spoofing.md) | verified | medium | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
