---
id: defense-forensics-adcs-abuse-certocm-log-ca-edb-template-serial
title: AD CS 证书滥用取证：certocm.log 定位可疑 CA 名，再用 ESEDatabaseView 解析 CertLog 下 CA 数据库 .edb 的 Certificates/RequestAttributes 表定位恶意证书模板与序列号
type: scenario
domain: defense
path: defense/forensics
technique: adcs-forensics-certocm-log-ca-database-edb-certificate-template-serial
aliases:
- AD CS 取证
- hack-CA.edb
- CertLog 数据库解析
- 证书模板与序列号溯源
tags:
- defense
- forensics
- windows
- adcs
- certificate
- pki
- incident-response
- ese-database
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-34
  verified_at: '2026-11-08T17:59:39+08:00'
  notes: 已对照原文与图核对：img03 certocm.log出现hack-CA、img08 Certificates表、img10 RequestAttributes表MyTem(RequestID=3)、img11序列号5400000003eedab5344b2e5da5000000000003均佐证；与ESC系列攻击卡视角(sink)不同，dedup差异成立
---

## 一句话结论

域控被利用 AD CS（如 CVE-2022-26923）滥用证书提权后，取证时先在 Windows 根目录查 certocm.log（AD CS 安装配置日志），从大量安装失败记录末尾定位可疑 CA 名称（如 hack-CA），再在 Windows/System32/CertLog 下用 ESEDatabaseView 打开同名 .edb 证书数据库，Certificates 表给证书模板与序列号，RequestAttributes 表按 RequestID 关联出 Certificates 表未直接显示的恶意模板（如 MyTem），最终还原「问题模板名-证书序列号」。

## 原理

- AD CS 安装/配置的全过程写入 `%SystemRoot%\certocm.log`：成功记录（生成 CA 证书、密钥签名名称、注册 DS 对象 CN=Certification-Authorities 等）与失败记录（NTE_BAD_FLAGS/BAD_KEYSET）混在一起，攻击者部署的恶意 CA 通常出现在日志尾部且伴随可疑命名。
- CA 的证书数据库是 ESE 数据库 `%SystemRoot%\System32\CertLog\<CA名>.edb`（配套 edb*.log 事务日志、edb.chk 检查点），保存已签发/吊销证书与请求记录；`certsrv\CertEnroll` 目录则发布 .crt/.crl 文件。
- edb 内多张表：`Certificates`（含 $CertificateTemplate、$SerialNumber、$Subject 等 36 列）能直接看到模板名与序列号；`RequestAttributes` 表按 RequestID 记录申请属性（$AttributeName=CertificateTemplate），当某请求只出现在 RequestAttributes 而未在 Certificates 表显示模板名时，用 RequestID 在 Certificates 表的对应行（其 $CertificateTemplate 列可能是长 OID 1.3.6.1.4.1.311.21.8...）关联出模板名与序列号。
- 攻击者用问题模板注册的证书序列号即题目还原目标；模板名可从 RequestAttributes 的 CertificateTemplate 值直接读取。

## 触发条件

- 已获取域控镜像/文件系统（含 Windows 目录）。
- 目标部署过 AD CS 且留有 certocm.log、CertLog 数据库（默认不清理）。

## 利用步骤

1. FTK Imager 等工具挂载镜像，在 Windows 目录下定位 certocm.log，重点看日志尾部可疑 CA 名称（如 hack-CA）。
2. 全盘搜索该 CA 名，锁定 Windows/System32/CertLog/hack-CA.edb（及 certsrv/CertEnroll 下的 crt/crl）。
3. ESEDatabaseView 打开 .edb，依次查看 Certificates、RequestAttributes 表。
4. Certificates 表对照模板与序列号；对没有序列号/模板名显示异常的行，去 RequestAttributes 按 RequestID 找 CertificateTemplate 属性值，再回 Certificates 用 RequestID 关联行（$CertificateTemplate 为 OID 串）取 $SerialNumber。
5. 输出形如 MyTem-5400000003eedab5344b2e5da5000000000003 的「模板名-序列号」。

## PoC

无 PoC（取证分析流程，工具链：FTK Imager + ESEDatabaseView）。

## 变体与关联

- 攻击侧对应场景：CVE-2022-26923 等问题模板注册证书获取域控权限（本文背景）。
- 同目录 edb*.log 事务日志在 edb 被占用/损坏时可辅助恢复；FileSlack 文件亦可能含残留数据。

## 检测与防御

- 对 certocm.log、CertLog 数据库纳入完整性监控；异常新 CA 或新模板注册告警。
- 审计 Web Enrollment 接口与证书模板权限，修复 ESC1~ESC8 类问题模板（含 CVE-2022-26923 补丁）。
