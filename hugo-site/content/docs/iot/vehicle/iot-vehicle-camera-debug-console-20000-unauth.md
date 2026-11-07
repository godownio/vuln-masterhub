---
id: iot-vehicle-camera-debug-console-20000-unauth
title: 车机摄像头调试服务 TCP 20000 未授权 console：camera 矩阵与 PTS/倒车辅助参数篡改
type: scenario
domain: iot
path: iot/vehicle
technique: vehicle-camera-debug-console-unauth
tags:
- iot
- vehicle
- automotive
- camera
- unauth
- debug-console
- parking-assist
- adas
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:42:59+08:00'
  notes: 已对照原文与图片10-17核对：20000 console、camera get/set FrontView、dump_pixmap、ptsside/revge 命令一致；已修正 pts side warning 为原文的 ptsside；PoC 未复跑。
url: /docs/iot/vehicle/iot-vehicle-camera-debug-console-20000-unauth/
draft: false
kb_aliases:
- 车机摄像头 20000
- camera get/set FrontView
- PTS side warning
- 泊车影像篡改
- hucam 调试控制台
- 车载摄像头未授权
---

## 一句话结论

车机/车载摄像头调试守护进程在 TCP 20000 暴露明文命令行 console，没有认证；攻击者用 `nc` 连接后可通过 `camera get/set` 读取和篡改泊车摄像头视图矩阵、用 `dump/dump_pixmap` 导出原始图像、用 `user ptsside` 与倒车辅助命令修改 PTS 侧边警告和挂 R 挡辅助逻辑，并能上传/下载文件，直接影响泊车影像与辅助驾驶提示。

## 原理

- **调试接口未下线**：摄像头模块在开发/产线阶段使用文本协议调试端口（本例 20000/TCP），量产后仍绑定在车机网络上；`nmap` 直接识别为 open，`nc <ip> 20000` 无需任何凭据即可进入 console。
- **命令直接映射到底层能力**：`help` 列出的命令包括 `calib`（重算摄像头标定）、`camera get/set`（读取/设置视图/投影矩阵）、`coding`（读写编码参数）、`dump`/`dump_pixmap`（导出相机原始输入/最新 pixmap）、`event`（模拟 GUI 事件）、`mgsi`（信号状态）、`hucam`（模拟来自车机头单元的控制命令）等；协议没有认证/会话/授权层，输入命令即执行。
- **车辆语义明确**：`camera get 2 FrontView` 返回 `ViewMatrix`；`set` 可改同一矩阵，从而改变泊车/环视画面拼接；`user ptsside ... 1 = ON` 控制 PTS 侧边警告，`user revge...` 控制挂 R 挡时的辅助功能逻辑。这些参数直接影响驾驶员看到的影像与安全提示。
- **为什么成立**：车载中间件常把“调试/标定/产线测试”接口做成无鉴权的本地 console，依赖“只有内部网络能访问”这一错误假设；车机网络一旦被接入（Wi-Fi/以太网/ADB 转发），攻击者即可直连。
- **证据边界**：原文为模拟渗透，截图对敏感信息做了打码；`camera set` 的完整参数格式未完整展示，实际利用需按 `help` 与目标固件确认。

## 触发条件

- 车机/摄像头模块开放 20000/TCP（或同类调试端口），且攻击者可路由到该地址。
- 摄像头服务未启用认证/白名单，或依赖网络隔离作为唯一防护。
- 目标提供 camera/calib/dump/PTS/倒车辅助等调试命令。
- 攻击者已接入车机内网（同一 Wi-Fi、以太网口、ADB 端口转发等）。

## 利用步骤

1. 对车机网段做端口扫描，确认 `20000/tcp open`（或从固件/APK 中发现的同类调试端口）。
2. `nc <target> 20000` 连接，输入 `help` 获取命令列表与参数格式。
3. 用 `camera get 2 FrontView` 读取当前视图/投影矩阵，记录正常值以便恢复。
4. 用 `camera set` 修改矩阵，观察泊车/环视画面拼接变化；用 `dump`/`dump_pixmap` 导出图像确认画面来源。
5. 用 `user ptsside <...> 1` 打开/关闭 PTS 侧边警告，用倒车辅助命令修改挂 R 挡逻辑，验证对驾驶员提示的影响。
6. 如需进一步利用，尝试 `hucam` 模拟头单元命令、`dump` 上传/下载文件，评估是否能写入可执行路径或覆盖配置。

## PoC

```bash
# 发现服务
nmap -p 20000 <target>

# 进入 console
nc -v <target> 20000
help
camera get 2 FrontView
camera set 2 FrontView <matrix...>
dump
dump_pixmap
user ptsside <value> 1
```

`hucam` 可用于模拟来自头单元的相机控制命令；具体参数以目标 `help` 输出为准。

说明：原文在模拟环境完成连接与命令演示，截图打码；本库未复跑，`camera set` 参数格式需按目标确认，故 confidence 定为 medium。

## 变体与关联

- 变体：端口不一定是 20000；可在固件/APK 中搜索 `camera`、`calib`、`hucam`、`dump_pixmap` 字符串定位同类服务。
- 变体：若服务支持文件上传且落点可执行/可被加载，可从“影像篡改”升级为代码执行；原文只演示了文件上传/下载能力。
- 变体：`event` 可模拟 GUI 事件，可能与车机 UI 操作联动；`mgsi` 可读取信号状态辅助判断车辆状态。
- 关联：[[iot-vehicle-bluetooth-hid-keyboard-spoofing]]（同一车机攻击面的无线输入注入）、[[iot-protocol-rtsp-osd-credential-leak-h264-capture]]（摄像头流未授权访问）、[[pentest-initial-access-zlmediakit-file-index-camera-stream-unauth]]（摄像头流媒体未授权）。
- 限制：无法确认该 console 是否在量产车默认开启；篡改泊车影像涉及人身安全，只应在授权测试环境验证。

## 检测与防御

- 修复：量产固件关闭调试 console，或至少绑定 127.0.0.1/内部专用网段；禁止无认证的命令执行接口。
- 加固：为调试服务增加认证与命令白名单；车机内网分区，隔离摄像头/ADAS 调试网段与娱乐网段；禁用不必要的 `hucam`/`event`/文件上传命令。
- 检测：车机网络出现对 20000/TCP 的连接；console 日志出现 `camera set`、`dump_pixmap`、`user ptsside`、`hucam` 等命令；泊车影像参数被非诊断流程修改。
- 响应：恢复摄像头标定与视图矩阵，检查是否写入持久化配置或上传恶意文件。
