---
id: code-analysis-reverse-windows-self-signed-root-ca-trusted-store
title: 自签根证书入 Root 存储：CertAddCertificateContextToStore 把攻击者 CA 变成 Windows 受信任根，自签载荷显示为有效签名
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: self-signed-root-ca-install-trust
tags:
- windows
- code-signing
- certificate
- root-store
- defense-evasion
- guptiminer
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V444-fix
  verified_at: '2026-11-09T23:15:58+08:00'
  notes: V444 核对指出 API 常量标注错误：0x24000 实为 CERT_SYSTEM_STORE_LOCAL_MACHINE(0x20000)|CERT_STORE_OPEN_EXISTING_FLAG(0x4000)，即本机 Root 而非当前用户；CertAdd 标志 1 = CERT_STORE_ADD_NEW（非 USE_EXISTING=2），备用 3u = REPLACE_EXISTING（非 INHERIT_PROPERTIES=5）。已修正原理与 PoC 注释。机制/命名伪装/检测防御不变。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-self-signed-root-ca-trusted-store/
draft: false
kb_aliases:
- 安装恶意根证书
- 自签 CA 信任
- CertOpenStore Root
- 伪造代码签名信任
- GuptiMiner 证书
---

## 一句话结论

恶意软件在安装阶段把内嵌的自签名根 CA（PEM 明文）导入 Windows 的 `Root` 证书存储：`CryptStringToBinaryA` 解码 → `CertCreateCertificateContext` 建上下文 → `CertOpenStore("Root")` → `CertAddCertificateContextToStore` 写入；此后攻击者用该 CA 签发的恶意 DLL/PE 在系统看来是“可信签名”，绕过了“未签名/自签名不可信”的告警。

## 原理

- Windows 代码签名验证是一条证书链：末端证书必须能追溯到一个位于受信任根存储（`Root`）的 CA。自签证书默认不受信，因此自签名恶意样本通常会被标记为未签名/不可信。
- 攻击者先用自己的 CA 私钥给恶意 DLL 签名（如 GuptiMiner 的两个 PNG 加载器 DLL），此时签名链在本地仍不可信；安装器再把同一 CA 的根证书加入 `Root` 存储，信任锚就位，签名验证随即通过。
- 原文 API 链：二进制中以 PEM 字符串保存根证书 → `CryptStringToBinaryA` 把 Base64/PEM 解码为 DER → `CertCreateCertificateContext(0x10001, pbBinary, cbCertEncoded)` 创建上下文 → `CertOpenStore(0xA, 0, 0, 0x24000, L"Root")` 打开**本机（LocalMachine）**的 Root 存储（`0x24000` = `CERT_SYSTEM_STORE_LOCAL_MACHINE`(0x20000) | `CERT_STORE_OPEN_EXISTING_FLAG`(0x4000)）→ `CertAddCertificateContextToStore(store, ctx, 1, NULL)` 写入（`1` = `CERT_STORE_ADD_NEW`）；失败时还有一组以 `3u`（`CERT_STORE_ADD_REPLACE_EXISTING`）为 ADD 标志的重试。
- 证书命名伪装：GuptiMiner 使用过 `GTE Class 3 Certificate Authority`、`VeriSign Class 3 Code Signing 2010`、`DigiCert Assured ID Code Signing CA` 等与真实 CA 相似的名字（原文声明是人为命名），让证书列表肉眼看上去像正常厂商证书。
- 为什么有效：签名校验只问“能否链到受信任根”，不判断根证书是否由用户/企业主动安装；导入 Root 后，本机所有使用该 CA 签发的载荷都受益，且签名状态会显示为正常，降低用户与部分安全产品的怀疑。

## 触发条件

- 恶意进程具备管理员/SYSTEM 权限（向 Root 存储写入通常需要管理员；当前用户存储可能只需用户权限，但影响范围限于该用户）；
- 恶意软件携带 CA 私钥/已用其签发载荷，且能内嵌根证书 PEM；
- 目标未开启证书存储写入监控/应用白名单（如限制普通程序写 Root 的策略）。

## 利用步骤

1. 生成攻击者自签 CA，签发恶意 DLL/PE（或预先签好）。
2. 将根证书以 PEM/Base64 字符串嵌入安装器二进制。
3. 安装器解码证书并写入 `Root` 存储（API 链见上）。
4. 释放已由该 CA 签名的恶意 DLL，交由白加黑宿主加载；系统签名校验因信任锚已存在而通过。
5. 清理/保留证书（保留以便后续更新载荷继续使用同一签名）。

## PoC

核心调用骨架（按原文反编译归纳）：

```c
BYTE der[8192];
DWORD derLen = 0;
CryptStringToBinaryA(pemString, 0, 0 /*CRYPT_STRING_BASE64HEADER*/,
                     der, &derLen, NULL, NULL);

PCCERT_CONTEXT ctx = CertCreateCertificateContext(
    0x10001 /*X509_ASN_ENCODING|PKCS_7_ASN_ENCODING*/, der, derLen);

HCERTSTORE store = CertOpenStore(
    0xA /*CERT_STORE_PROV_SYSTEM*/, 0, 0,
    0x24000 /*CERT_SYSTEM_STORE_LOCAL_MACHINE|CERT_STORE_OPEN_EXISTING_FLAG*/,
    L"Root");

CertAddCertificateContextToStore(store, ctx, 1 /*CERT_STORE_ADD_NEW*/, NULL);
```

说明：原文调用中还出现以 `3u` 为 add 标志的备用分支（`CERT_STORE_ADD_REPLACE_EXISTING`，已存在则替换）；示例为按反编译还原，未在本机执行。

## 变体与关联

- 变体：写入 `LocalMachine\Root`（需 SYSTEM）可影响全机器；写入 `CurrentUser\Root` 只影响当前用户但权限要求更低。
- 变体：除自签 CA 外，原文还发现攻击者使用**盗用的代码签名证书**（含一份与 Winnti 相关、卡巴斯基多年前披露过的证书）签署样本，这类不需要导入根证书即可显示有效签名；同一证书被多个恶意家族复用，说明泄露范围更广。
- 关联：企业域内伪造信任（Golden Certificate）见 [[pentest-ad-golden-certificate-ca-key-forge]]，与主机侧植入根证书是不同层面的信任滥用。
- 关联：白加黑部署见 [[pentest-persistence-wmi-event-time-window-clean-binary-sideload]]。

## 检测与防御

- 监控 `Root` 证书存储的新增（注册表/证书存储审计、Sysmon 事件、`certutil -store Root` 基线对比）；对比证书主体/颁发者与已知 CA 列表，标记自签、有效期异常、issuer 与 subject 相同、名称仿冒的证书。
- 签名验证不能只看“是否有效”：检查签名链根证书是否为系统内置/企业受控 CA，检查签名时间与证书有效期、吊销状态；对“刚安装的根证书签发的新样本”建立关联告警。
- 限制普通用户程序写证书存储（企业策略/应用白名单）；启用基于签名的应用控制（WDAC）时把受信任根范围与签名规则一起管理。
- 应急：发现可疑根证书后删除并吊销其签发链，重新校验该期间所有“有效签名”的可执行文件。
