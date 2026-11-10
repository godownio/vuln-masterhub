---
id: iot-zkteco-qr-sqli-auth-bypass
title: ZKTeco 终端二维码 SQL 注入：20 字节限制下用 ' or 1=1 -- 伪造有效用户
type: scenario
domain: iot
path: iot
technique: zkteco-qr-sqli-auth-bypass
tags:
- iot
- zkteco
- biometric-terminal
- qr-code
- sqli
- auth-bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V322
  verified_at: '2026-11-08T15:55:27+08:00'
  notes: 已对照 img47 与原文核对 Vice_Card 拼接 SQL、or 1=1 恒真与 20 字节限制；未在设备上复跑，confidence medium 合理。
url: /docs/iot/iot-zkteco-qr-sqli-auth-bypass/
draft: false
kb_aliases:
- 二维码 SQL 注入
- Vice_Card SQLi
- ZKTeco QR 认证绕过
- USER_INFO 注入
- 二维码身份伪造
---

## 一句话结论

ZKTeco 生物识别终端把二维码内容直接作为 `Vice_Card` 拼进 `select ... from USER_INFO where Vice_Card='%s'`，未做参数化；攻击者让设备扫描含 `' or 1=1 --` 的二维码，即可匹配到任意用户记录，被终端识别为有效身份并进入该用户的验证流程。二维码数据被限制在约 20 字节，足以做认证绕过，但难以用 UNION 提取任意字段。

## 原理

- 设备支持二维码作为身份验证方式；扫码后把二维码字符串当作 `Vice_Card` 字段拼进查询，原文反编译可见 SQL 模板：`select ID, User_PIN, Name, Privilege, Verify_Type, ..., from USER_INFO where Vice_Card='%s'`。
- 字符串拼接未使用预编译/转义，输入 `'` 即可闭合引号；`or 1=1 --` 使 WHERE 恒真并注释掉后续内容，查询返回第一条用户记录，设备将其视为有效用户并展示该用户的验证方式（生物识别/密码）。
- 二维码载荷长度限制约 20 字节（原文分析），`' or 1=1 --`（11 字节）足够；更长 PAYLOAD 会被截断，因此 UNION SELECT 取数难以构造。
- 该终端还会因二维码数据过大/摄像头等待超时触发 `reboot`（原文代码 `wait_cnt > 2` 后 `system("reboot")`），属 DoS 路径，不在本卡范围。
- 危害是物理门禁身份伪造：攻击者无需知道真实用户 PIN/生物特征，只要设备接受二维码并匹配到一条记录，就可能进入后续验证或记录伪造；具体能走到哪一步取决于设备的验证策略。

## 触发条件

- 设备启用二维码身份验证，且扫码输入进入 `Vice_Card` 查询。
- 攻击者能向设备摄像头展示自制二维码（物理接近或远程视频/屏幕）。
- 目标固件未对二维码内容做参数化查询或字符白名单。
- 设备允许约 20 字节的二维码数据（默认）。

## 利用步骤

1. 确认设备支持二维码验证，并在界面上选择二维码登录/验证。
2. 生成包含 `' or 1=1 --` 的二维码（注意结尾空格/注释符与 20 字节上限）。
3. 让设备扫描；观察是否直接显示某用户的验证方式（如密码/指纹）或被识别为有效用户。
4. 根据目标 SQL 方言微调：`' or 1=1--`、`'or 1=1--`、`' or '1'='1`（注意长度）；若被截断，缩短 payload。
5. 记录设备返回的用户 ID/权限，评估是否能绕过门禁或进入管理流程；测试到身份被接受即停止。
6. 不要使用超长二维码触发重启（DoS），除非测试范围明确允许。

## PoC

二维码文本载荷（示意）：

```text
' or 1=1 --
```

```text
# 反编译中的 SQL 模板
select ID, User_PIN, Name, Privilege, Verify_Type, ... from USER_INFO where Vice_Card='%s' or 1 =1 -- aaaaaaaaaaaaaaa'
```

说明：原文用带 SQL 注入的二维码使设备将测试者识别为有效用户（图 13），但未给出完整二维码字符串与返回数据；20 字节限制使具体 payload 需按设备实际拼接位置调整，故 confidence 记为 medium。

## 变体与关联

- 变体：`' or '1'='1`、`' or 1=1#`（MySQL）、`' or 1=1/*` 等短 payload；按数据库类型与截断长度选择。
- 变体：其他把二维码/卡号/PIN 拼进 SQL 的功能（考勤、开门记录查询）可能有同类注入；网络协议中的字符串字段也被原文指出存在大量 SQL 注入。
- 关联：[[iot-protocol-zkteco-4370-comkey-reversible-mac-auth]]（协议侧认证缺陷）、[[iot-protocol-zkteco-standalonecomm-download-picture-path-traversal]]（同设备任意文件读取）、[[web/generic/sqli]] 下通用 SQL 注入卡（参数化/绕过基础）。
- 边界：二维码内容做了参数化查询/白名单、长度限制更严、或设备在扫码后要求额外认证时，单纯的 `or 1=1` 不足以完成门禁绕过；仅认证绕过不等于提取数据。

## 检测与防御

- 检测：二维码内容出现 `'`、`or`、`--`、`/*`、`#`；设备日志/数据库出现异常 `USER_INFO` 查询；同一设备短时间内多次无效扫码。
- 防御：使用参数化查询/预编译语句，不要拼接二维码内容；对二维码做格式与长度白名单（如仅允许数字/固定前缀）。
- 防御：对二维码身份增加二次验证（PIN+生物特征），限制单次扫码的有效期/签名，使用签名二维码防伪造。
- 加固：升级固件修复 SQL 注入与超长二维码重启问题；限制二维码数据长度并做异常处理。
