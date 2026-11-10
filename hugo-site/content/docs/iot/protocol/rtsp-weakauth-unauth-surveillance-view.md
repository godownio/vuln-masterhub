---
id: rtsp-weakauth-unauth-surveillance-view
title: RTSP 弱口令/未授权访问实时监控流（Basic/Digest 爆破后 VLC 直连查看）
type: scenario
domain: iot
path: iot/protocol
technique: weak-credential
tags:
- rtsp
- camera
- weak-password
- unauthorized-access
- surveillance
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-21
  verified_at: '2026-11-08T12:52:35+08:00'
  notes: 已对照原文核对：Basic/Digest 认证与 401/200 未授权判断(图13/21)、用户名x密码xURI 三维爆破与 Digest/Basic 双跑(图34)、厂商路径字典(海康/大华/TP-Link/live.ch00_1/onvif1/live.sdp)、TAS-Tech 指纹+ispyconnect、FOFA port=554 语法(图37)与 shodan has_screenshot、VLC 取流成功(图36/40)均吻合；卡为弱口令/未授权场景，原文无组件版本，无需 affected_versions；dedup 候选 iot-protocol-rtsp-osd-credential-leak-h264-capture 为 OSD 凭据泄露不同链。
url: /docs/iot/protocol/rtsp-weakauth-unauth-surveillance-view/
draft: false
kb_aliases:
- RTSP 未授权访问
- 摄像头弱口令
- 554 端口爆破
---

# RTSP 弱口令/未授权访问实时监控流（Basic/Digest 爆破后 VLC 直连查看）

## 一句话结论

RTSP 服务（TCP 554/8554）在 Basic/Digest 认证使用弱口令或未配置认证（DESCRIBE 直接返回 200）时，攻击者用通用字典爆破用户名/密码/流路径后，即可用 VLC 以 `rtsp://user:pass@IP:554/<厂商路径>` 直接观看实时监控画面，造成隐私泄露与现场情报暴露。

## 原理

RTSP 是文本协议，认证分两步：客户端发 `DESCRIBE`，服务端回 `401 Unauthorized` 并带 `WWW-Authenticate: Basic`（base64 明文凭据）或 `Digest`（MD5 挑战）；若回 `200 OK` 则完全未授权。认证仅保护"取流"动作，凭据空间小（用户名多为 `admin`，密码常为空/`admin`/设备安全码），且各厂商流路径固定可枚举（如海康 `/h264/ch1/main/av_stream`、大华 `/cam/realmonitor?channel=1&subtype=0`、TP-Link `/stream1`、通用 `/live/ch00_1`、`/onvif1`、`/live.sdp`），因此可对"用户名×密码×URI"三维字典做高并发爆破；Digest 的 MD5 响应对固定 challenge 可离线构造，爆破无额外成本。爆破得到凭据后无需任何漏洞利用，用标准播放器即可取流。

## 触发条件

- 目标 554/8554 端口暴露 RTSP 服务（视频监控、会议、智能家居设备），可通过 FOFA `port="554" && protocol="rtsp" && category="视频监控"` 或 shodan `port:554 has_screenshot:true` 定位。
- 设备使用默认/弱口令，或未启用认证；响应 `OPTIONS`/`DESCRIBE` 时观察 `Server` 头识别厂商（如 TAS-Tech）后到 ispyconnect 查对应路径与默认密码。
- 攻击者可达该端口（演练内网或公网暴露面）。

## 利用步骤

1. 发送 `OPTIONS`/`DESCRIBE` 探测：`200 OK` 未授权直接取流；`401` 则从 `WWW-Authenticate` 判断 Basic/Digest。
2. 按 `Server` 头/指纹确定厂商，选择对应流路径字典（uri.txt）与用户名/密码字典。
3. 用 RTSP 爆破工具（如 RTSP-Cracker-Pro、hydra、无影）批量跑 Digest 与 Basic 两种认证，导出成功的 RTSP URL。
4. 将 URL 填入 VLC"打开网络串流"，直接查看实时监控画面；可进一步遍历 channel/subtype 查看全部通道。

## PoC

```text
DESCRIBE rtsp://192.168.1.55:554/11 RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n
# 未授权：RTSP/1.0 200 OK（直接可取流）
# 有认证：RTSP/1.0 401 Unauthorized + WWW-Authenticate: Basic/Digest
# 爆破成功后：
rtsp://admin:admin@192.168.1.56:554/live/sys01  → VLC 打开即可观看
```

## 变体与关联

- 同一取流能力可作为进入内网的跳板：监控画面中包含键盘/屏幕可辅助凭据窃取，部分 NVR/摄像头在取得管理凭据后可继续打设备自身漏洞。
- Basic 认证的 base64 凭据可被同网段嗅探直接还原（无 TLS 时），与明文凭据泄露场景关联。
- 各厂商默认密码表（乐橙为机身安全码、萤石为安全码、TP-Link/警卫视/乔安默认空）是字典构建的重要来源。

## 检测与防御

- 强制强口令并禁用空密码；RTSP 服务不暴露公网，管理面收敛到内网/VPN。
- 升级支持 RTSPS/TLS 的设备；对同 IP 高频 `DESCRIBE` 失败（401）告警。
- 资产测绘：定期用空间测绘核查 554 暴露面；未授权（200 OK 无凭据）设备立即整改。
