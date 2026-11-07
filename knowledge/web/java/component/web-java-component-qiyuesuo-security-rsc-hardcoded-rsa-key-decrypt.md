---
id: web-java-component-qiyuesuo-security-rsc-hardcoded-rsa-key-decrypt
title: 契约锁安全补丁 security.rsc 硬编码 RSA 私钥：离线解密还原 PdfverifierPreventWrapper 过滤配置
type: scenario
domain: web
path: web/java/component
technique: qiyuesuo-security-rsc-hardcoded-rsa-key-decrypt
aliases:
- security.rsc 解密
- PdfverifierPreventWrapper.PARAM
- SecurityResourceOperator
- RSAUtils.decryptByDefaultPrivateKey
- 契约锁补丁规则还原
- 加密资源配置硬编码私钥
tags:
- java
- qiyuesuo
- rsa
- hardcoded-key
- security-patch
- config-decrypt
- static-analysis
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V261
  verified_at: '2026-11-07T17:44:42+08:00'
  notes: 已对照原文与20张图核对：18图为密文security.rsc，19图SecurityResourceOperator静态块从自身JAR读security.rsc/security.html并调readRsc，正文553-638行readRsc逐行key:value、value按逗号拆分、去{cipher}后RSAUtils.decryptByDefaultPrivateKey解密（私钥硬编码在decryptByPrivateKey第二个参数，原文脱敏），20图解密输出PdfverifierPreventWrapper.TYPE=['ofd']、PARAM=['../']与卡内一致；PoC脚本与原文一致。版本阈值核对：原文仅出现分析环境/补丁包版本4.3.4.20230203（图03/04控制台版本、图12包路径qiyuesuo.package.el7.4.3.4.20230203），未给出受影响版本区间，属目标环境版本而非受影响范围，affected_versions保持为空（未设置）。dedup：最高非自身候选web-java-component-qiyuesuo-ofd-zipslip-hotpatch-jar-rce(0.9084)为Zip Slip覆盖热补丁JAR热加载RCE，本卡为security.rsc离线解密还原过滤配置，sink与最终危害不同；其余为通用RSA/硬编码密钥类卡，不重复。未验证点：私钥在原文被xxxx脱敏、PoC未复跑；原文未明确CustomCodeDealLogic.URL_LIST取值（图20被截断）。
---

## 一句话结论

契约锁安全补丁 JAR 内的 `security.rsc` 把键和值都用 RSA 加密，但解密私钥被硬编码在同一个 JAR 的 `RSAUtils.decryptByDefaultPrivateKey`/`SecurityResourceOperator` 中；拿到补丁包即可离线解密，还原 `PdfverifierPreventWrapper.PARAM`（`../`）、`TYPE`（`ofd`）、`OTHER` 后缀黑名单（`.jar/.sh/.bat/.py/.class/.java/.bash/.so`）、`PdfverifierPreventLogic.PDFVERIFIER_URL_LIST`（`/api/pdfverifier`、`/pdfverifier`、`/api/file/uploader/chunk`、`/api/document/createbyfile`、`/api/document/createbyofd` 等）与 `CustomCodeDealLogic.URL_LIST` 等过滤/路由配置，为补丁绕过评估和攻击面分析提供依据。

## 原理

- **资源加载点**：`SecurityResourceOperator` 的 `static` 块通过 `SecurityResourceOperator.class.getProtectionDomain().getCodeSource().getLocation().toURI()` 定位自身 JAR，打开其中的 `security.rsc` 与 `security.html`，分别调用 `readRsc(jarFile, rscEntry)` 与 `readHtml(jarFile, htmlEntry)`。
- **每行是 `key:value`**：`readRsc` 按第一个 `:` 切分，值再按逗号切分成多个密文；每个密文可以带 `{cipher}` 前缀，去掉前缀后交给 `RSAUtils.decryptByDefaultPrivateKey`；键本身也做同样的 RSA 解密。解密结果按“明文键 → 明文值列表”存入 `SECURITY_SRC_MAP`。
- **私钥就在同一个包里**：`decryptByDefaultPrivateKey` 去掉 `{cipher}` 后调用 `decryptByPrivateKey(ciphertext, "…")`，第二个参数是硬编码的 RSA 私钥。也就是说加密只是混淆，不是密钥隔离：任何能读到 JAR 的人都能取出私钥并解密全部配置。
- **还原出的配置直接服务补丁逻辑**：`PdfverifierPreventWrapper` 用 `SecurityResourceOperator.getStringWithKey("PdfverifierPreventWrapper.PARAM")` 取 `PARAM`，在 `hasPathTraversal` 中对每个 `ZipEntry` 判断 `entryName.contains(PARAM)`；另有 `SENSITIVE_KEY_LISTS` 做后缀黑名单。解密后的关键值包括：
  - `PdfverifierPreventWrapper.TYPE = ['ofd']`；
  - `PdfverifierPreventWrapper.PARAM = ['../']`；
  - `PdfverifierPreventWrapper.OTHER = ['.jar', '.sh', '.bat', '.py', '.class', '.java', '.bash', '.so']`；
  - `PdfverifierPreventWrapper.SENSITIVE_URL = ['/document/createbyofd', '/api/document/createbyofd']`；
  - `PdfverifierPreventLogic.PDFVERIFIER_URL_LIST = ['/api/pdfverifier', '/pdfverifier', '/api/file/uploader/chunk', '/file/uploader/chunk', '/api/document/createbyfile', '/document/createbyfile', '/api/document/createbyofd', '/document/createbyofd']`；
  - `CustomCodeDealLogic.URL_LIST = ['/api/code/download', '/code/download']`；
  - 其他：`DBTestPreventLogic.RISK_UPGRADE_URI`（`/setup/dbtest`）、`DangerOpenUrlLogic.PARAM_NAME`（`x-qys-accesstoken`）、`SecurityVersionInfoLogic.URL`（`/security/info`）等。
- 知道这些常量后，才能准确评估补丁拦什么、没拦什么：`hasPathTraversal` 对非 PDF 上传（含 OFD）按 `PARAM=../` 与后缀黑名单过滤；`PDFVERIFIER_URL_LIST`/`SENSITIVE_URL` 说明补丁作者认为同样需要保护的文档创建/分片上传端点不止 `/api/pdfverifier`。
- 该手法本身只完成“配置解密/规则还原”，不等同于绕过；是否能用反斜杠、等价路径编码或其他上传分支绕过，需要结合目标平台与补丁实现另行验证。

## 触发条件

- 能获得契约锁安全补丁包或包含 `security.rsc` 的应用 JAR（例如厂商安全服务包）。
- JAR 内保留 `security.rsc`、`security.html`，且 `RSAUtils` 的默认私钥仍为硬编码值。
- 具备本地运行 Python/Java 的能力，用于离线解密；不需要目标系统账号或网络访问。
- 版本/补丁背景：官方补丁页面列出契约锁 4.3.8–5.3.x 需补丁 ≥2.1.8、4.0.x–4.3.7 需补丁 ≥1.3.8；已分析的是 1.3.8 补丁包中的 `private-security-patch.jar`。这些阈值说明补丁覆盖范围，不表示 `security.rsc` 机制只在对应版本存在。

## 利用步骤

1. 解包/定位安全补丁 JAR，确认存在 `security.rsc`，并在反编译代码中找到 `SecurityResourceOperator.readRsc` 与 `RSAUtils.decryptByDefaultPrivateKey`。
2. 从 `decryptByDefaultPrivateKey` 的第二个参数提取 Base64/DER 私钥；原文的私钥在代码中以字符串常量出现。
3. 把私钥还原为 PEM（`BEGIN PRIVATE KEY`），用 RSA PKCS#1 v1.5 私钥解密：逐行读取 `security.rsc`，对 `key` 与每个逗号分隔的 `value` 去掉 `{cipher}` 后解密。
4. 汇总输出为键值表，重点看 `PdfverifierPreventWrapper.PARAM`、`PdfverifierPreventWrapper.TYPE`、`CustomCodeDealLogic.URL_LIST` 以及其他 `*Prevent*`/`*Logic*` 键。
5. 将还原的常量与补丁代码逐条对照，判断过滤覆盖的条目名特征、后缀黑名单和敏感 URL 列表，再决定是否需要进一步验证绕过。

## PoC

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

private_key_b64 = "<从 RSAUtils.decryptByDefaultPrivateKey 提取的 Base64 私钥>"
pem = "-----BEGIN PRIVATE KEY-----\n" + "\n".join(
    private_key_b64[i:i + 64] for i in range(0, len(private_key_b64), 64)
) + "\n-----END PRIVATE KEY-----\n"
key = RSA.import_key(pem)

def dec(ciphertext_b64: str) -> str:
    ciphertext_b64 = ciphertext_b64.strip()
    if ciphertext_b64.startswith("{cipher}"):
        ciphertext_b64 = ciphertext_b64[len("{cipher}"):]
    return PKCS1_v1_5.new(key).decrypt(base64.b64decode(ciphertext_b64), None).decode()

with open("security.rsc", "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        print("Key:", dec(k))
        print("Values:", [dec(x) for x in v.split(",")])
```

解密结果的关键键值：`PdfverifierPreventWrapper.TYPE = ['ofd']`、`PdfverifierPreventWrapper.PARAM = ['../']`、`PdfverifierPreventWrapper.OTHER = ['.jar','.sh','.bat','.py','.class','.java','.bash','.so']`、`PdfverifierPreventLogic.PDFVERIFIER_URL_LIST = ['/api/pdfverifier','/pdfverifier','/api/file/uploader/chunk','/file/uploader/chunk','/api/document/createbyfile','/document/createbyfile','/api/document/createbyofd','/document/createbyofd']`、`CustomCodeDealLogic.URL_LIST = ['/api/code/download','/code/download']`。

## 变体与关联

- 变体：同一 `SecurityResourceOperator` 还加载 `security.html`（`readHtml`），其他补丁 JAR 也可能用同样的 `{cipher}` + 硬编码私钥模式保护 URL/后缀/正则配置。
- 变体：还原出的 `PDFVERIFIER_URL_LIST` 除 `/api/pdfverifier` 外还列出 `/api/file/uploader/chunk`、`/api/document/createbyfile`、`/api/document/createbyofd` 等文档创建/分片上传端点；这些端点是否也存在同类解压路径穿越需逐个验证，不能仅凭补丁配置下结论。
- 变体：若私钥不在代码中而是通过配置下发，则需要从运行环境或内存中提取；若使用非对称加密但私钥不随包分发，则本手法不成立。
- 关联：[[web-java-component-qiyuesuo-ofd-zipslip-hotpatch-jar-rce]]（同属契约锁补丁/JAR 机制；该卡是利用 Zip Slip 覆盖热补丁 JAR，本卡是离线还原补丁过滤配置）。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（通用 Zip Slip 任意文件写；还原出的 `PARAM=../` 正是契约锁补丁针对该原语的拦截关键字）。
- 关联：[[code-analysis-reverse-crypto-encoding-identification-decrypt]]（通用的加密算法识别与密钥提取方法）、[[defense-forensics-java-rat-encrypted-config-h2-db]]（Java 程序硬编码密钥解密配置的同类思路）。
- 边界：本卡只能还原补丁规则，不证明可绕过；补丁的 `hasPathTraversal` 还依赖 `SENSITIVE_KEY_LISTS` 与其他条件，实际效果需逐版本核对。

## 检测与防御

- 检测（防御方/审计）：JAR 中出现 `security.rsc` 等密文资源；代码中存在 `BEGIN PRIVATE KEY`、`decryptByPrivateKey`、`RSAUtils` 等硬编码私钥特征；对补丁包做静态扫描时重点检查“加密资源 + 同包私钥”的组合。
- 防御：不要把私钥打进客户端/可分发 JAR；配置加密应采用“公钥加密、私钥仅服务端持有”的方式，或使用 KMS/HSM；补丁包做签名校验并在加载前验签；定期轮换密钥；不要把安全过滤规则当作秘密，安全应依赖服务端强校验而非配置保密。
- 检测（攻击面评估）：如果已经能解密配置，优先核对 `PARAM` 与后缀黑名单的字符串匹配方式，检查是否存在未覆盖的路径编码或上传分支，但不要在未验证时下“可绕过”的结论。
