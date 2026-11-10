---
id: tools-burp-galaxy-http-hook-dynamic-key-capture
title: Galaxy Montoya HttpHook 四段拦截 + 动态密钥捕获：/api/getSecret 响应解析后自动加解密
type: scenario
domain: tools
path: tools/burp
technique: galaxy-http-hook-dynamic-key-capture
tags:
- burp
- galaxy
- montoya
- httphook
- aes-cbc
- dynamic-key
- decrypt
- encrypt
- pentest
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V295
  verified_at: '2026-11-08T07:48:13+08:00'
  notes: '已对照原文content.md与全部6个图（含01.gif首帧）核对：Montoya四段hook(hookRequestToBurp/hookRequestToServer/hookResponseToBurp/hookResponseToClient)与图03的①②③④对应；示例Java类ALGORITHM=AES/CBC/PKCS5Padding、jsonKey=data、ThreadLocal flag、/api/getSecret响应解析key/iv、paramMap更新iv、CryptoUtil.aesDecrypt/aesEncrypt、CodeUtil.b64decode/b64encode均与原文代码一致；图04 getSecret返回key/iv、图05加密login、图06解密后明文请求/响应及X-Galaxy-Http-Hook: HttpHook目证。dedup最高分为卡自身exact自匹配，related候选galaxy-jsrpc-auto-encrypt-decrypt-sign(签名场景)与hybrid-rsa-aes-login-bruteforce(登录爆破)均为不同链，不合并；dup-scan无该卡pair。小瑕疵：原理段写response.getPath()判断密钥接口，原文实际以request.getPath()置flag，卡内PoC已用正确flag逻辑。未验证点：未实际安装Galaxy运行该Java hook。无版本，未set-versions。'
url: /docs/tools/burp/tools-burp-galaxy-http-hook-dynamic-key-capture/
draft: false
kb_aliases:
- Galaxy 动态密钥
- HttpHook 四段 hook
- hookRequestToBurp
- hookResponseToClient
- Burp 动态 key/iv
- Montoya API 加解密
---

## 一句话结论

当站点每次会话都从 `/api/getSecret` 动态下发 AES `key`/`iv`、之后请求响应才加密时，可用 Galaxy 的四个 Montoya `HttpHook` 分别完成“解密请求给 Burp 看、加密请求给服务端、解密响应给 Burp、加密响应给客户端”；在 `hookResponseToClient` 中识别密钥接口的响应、解析并保存新的 `key`/`iv`，后续 POST 用新密钥加解密，即可在 Burp 中看到并修改明文、自动重加密重放。

## 原理

- **Montoya 四段拦截点**：Burp 插件可在流量四个方向改写报文：
  - `hookRequestToBurp`：客户端 → Burp（①），在此解密请求体，Burp 中显示明文；
  - `hookRequestToServer`：Burp → 服务端（②），在此把 Burp 中修改后的明文重新加密；
  - `hookResponseToBurp`：服务端 → Burp（③），在此解密响应体；
  - `hookResponseToClient`：Burp → 客户端（④），在此把明文响应重新加密后返回浏览器。
- **动态密钥的难点**：key/iv 不在前端 JS 里，而是页面加载时请求 `/api/getSecret` 由服务端随机生成并返回 `{key, iv}`；每次刷新/会话都可能变化。写死 key/iv 的模板会立即失效。
- **捕获时机**：`/api/getSecret` 的响应会经过 `hookResponseToClient`。在该 hook 中判断 `response.getPath().endsWith("/api/getSecret")`（或按请求 URL/标记），用 `JsonUtil.jsonStrToMap` 解析 `key`/`iv`，保存到插件实例字段 `secret`/`iv` 与 `paramMap`；后续请求的 `decrypt`/`encrypt` 即使用最新密钥。
- **避免误处理密钥接口**：在 `hookRequestToBurp` 中先把 ThreadLocal 标记置 false；若当前请求是密钥接口则置 true。`hookRequestToServer`、`hookResponseToBurp`、`hookResponseToClient` 根据该标记决定是否加解密：密钥接口本身是明文 JSON，不能按密文处理；其他 POST 才走 `data` 字段的 Base64/AES 解密与回写。
- **Java 内做密码学**：Hook 脚本在 JVM 内执行，可直接调用项目自带的 `CryptoUtil.aesDecrypt/aesEncrypt`、`CodeUtil.b64decode/b64encode`、`JsonUtil`，避免 Python/Java 在 PKCS 填充、字符集、Base64 变体上的差异；算法参数 `AES/CBC/PKCS5Padding`、`paramMap={"iv": iv}`。
- **报文封装**：示例把密文放在 JSON 的 `data` 字段（`{"data": "<base64>"}`）。解密时取 `data` 做 Base64 解码再 AES 解密；加密时 AES 加密后 Base64，再包回 `{"data": ...}`。不同站点封装可能不同，按实际抓包调整 `jsonKey`/取值路径。
- **为什么有效**：客户端加密只是提高改包成本，密钥既然下发给浏览器/插件，就能在客户端侧被复用；插件把“解密—修改—重加密”自动化，测试者只需在 Repeater 中改明文。

## 触发条件

- 目标请求/响应体由前端加密（如 AES-CBC），密钥由独立接口动态下发（每次会话/刷新变化），而非硬编码在 JS。
- 能在 Burp 中安装 Galaxy 并编写 Java hook（或使用其模板）；能识别密钥接口路径与密文封装字段。
- 测试者能以合法账号打开页面触发密钥下发，且 Burp 能代理 `/api/getSecret` 请求/响应。
- 加解密算法/模式/填充与 `CryptoUtil` 支持的一致；若为自定义算法，需要自行实现或改用 JsRpc 调用页面函数。

## 利用步骤

1. **抓包识别**：确认页面加载时请求 `/api/getSecret`，响应含 `key`/`iv`；登录等 POST 请求体为 `{"data":"<base64>"}`，响应同样加密。
2. **写 Hook 类**：定义 `secret`、`iv`、`paramMap`、`jsonKey="data"`，以及 `ThreadLocal<Boolean> flag`。
3. **hookRequestToBurp**：`flag.set(false)`；若 `request.getPath().endsWith("/api/getSecret")` 则 `flag.set(true)`；否则对 POST 取 `data` 字段，Base64 解码后 AES 解密，`request.setContent(明文)`。
4. **hookRequestToServer**：`flag` 为 false 时，把 Burp 中的明文 AES 加密、Base64 后包成 `{"data": ...}` 写回。
5. **hookResponseToBurp**：`flag` 为 false 时，取响应 `data` 解密，`response.setContent(明文)`。
6. **hookResponseToClient**：`flag` 为 true 时，解析响应 JSON 的 `key`/`iv`，更新 `secret`/`iv`/`paramMap`；否则把明文响应加密后写回。
7. **验证**：刷新页面触发新的 `/api/getSecret`，在 Burp 中确认请求/响应均为明文；在 Repeater 改明文参数重放，服务端正常响应。
8. **留证**：记录算法、封装字段、密钥接口与 hook 代码；密钥属于敏感信息，测试后清理。

## PoC

```java
import org.m2sec.core.utils.*;
import org.m2sec.core.models.*;
import java.util.*;

public class Test {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String jsonKey = "data";
    private byte[] secret;
    private byte[] iv;
    private static final Map<String, Object> paramMap = new HashMap<>();
    private final ThreadLocal<Boolean> flag = ThreadLocal.withInitial(() -> false);

    public Request hookRequestToBurp(Request request) {
        flag.set(false);
        if (request.getPath().endsWith("/api/getSecret")) {
            flag.set(true);                       // 密钥接口：明文，跳过加解密
        } else if (request.getMethod().equalsIgnoreCase("POST")) {
            byte[] data = decrypt(getData(request.getContent()));
            request.setContent(data);             // Burp 中显示明文
        }
        return request;
    }

    public Request hookRequestToServer(Request request) {
        if (!flag.get()) {
            request.setContent(toData(encrypt(request.getContent())));
        }
        return request;
    }

    public Response hookResponseToBurp(Response response) {
        if (!flag.get()) {
            response.setContent(decrypt(getData(response.getContent())));
        }
        return response;
    }

    public Response hookResponseToClient(Response response) {
        if (flag.get()) {
            Map<?, ?> m = JsonUtil.jsonStrToMap(new String(response.getContent()));
            secret = ((String) m.get("key")).getBytes();
            iv = ((String) m.get("iv")).getBytes();
            paramMap.put("iv", iv);               // 更新动态密钥
        } else {
            response.setContent(toData(encrypt(response.getContent())));
        }
        return response;
    }

    private byte[] decrypt(byte[] c) { return CryptoUtil.aesDecrypt(ALGORITHM, c, secret, paramMap); }
    private byte[] encrypt(byte[] c) { return CryptoUtil.aesEncrypt(ALGORITHM, c, secret, paramMap); }
    private byte[] getData(byte[] body) {
        return CodeUtil.b64decode((String) JsonUtil.jsonStrToMap(new String(body)).get(jsonKey));
    }
    private byte[] toData(byte[] c) {
        HashMap<String, Object> m = new HashMap<>();
        m.put(jsonKey, CodeUtil.b64encodeToString(c));
        return JsonUtil.toJsonStr(m).getBytes();
    }
}
```

## 变体与关联

- **密钥来源变体**：key/iv 可能在登录响应、响应头、Cookie 或每次请求的 nonce 头中；把捕获逻辑放到对应 hook（`hookResponseToBurp`/`hookRequestToBurp`）即可。
- **每次请求动态密钥**：若每个请求的 key/iv 都不同，需要在 `hookRequestToBurp` 从请求头/字段读取并在 `hookRequestToServer` 更新，或在 `hookResponseToBurp` 捕获下一次密钥。
- **加密+签名**：签名仍需动态生成时，可组合 JsRpc 调用页面原函数，见 [[tools-burp-galaxy-jsrpc-auto-encrypt-decrypt-sign]]。
- **固定 key/iv**：不需要动态捕获，直接用 AES 模板即可，见 [[tools-burp-autodecoder-builtin-regex-form-json-rsa-login]]、[[tools-burp-autodecoder-flask-custom-encrypt-decrypt-script]]。
- **上下游代理**：也可用 mitmproxy 在 Burp 上下游透明解密/重签，见 [[tools-burp-encrypted-api-proxy-decrypt-resign]]。
- **边界**：客户端加密不是安全边界；若服务端对请求做二次签名/一次性 nonce/MFA 校验，仅靠加解密 hook 仍会被拦。

## 检测与防御

- **根本问题**：密钥下发给客户端，客户端就可解密/加密任意报文；加密只提高改包成本，不能替代服务端鉴权、输入校验与业务风控。
- **服务端加固**：关键参数在服务端做二次校验；一次性 nonce + 短时效签名；敏感操作要求 MFA/验证码；对高频重放、参数突变做速率限制与告警。
- **测试侧安全**：Galaxy hook 中的 key/iv 与抓包数据按敏感信息处理；Java hook 只加载可信代码；不要在公网暴露调试代理。
- **检测**：同一会话短时间内出现大量 `sign` 正确但参数高度相似的请求、`/api/getSecret` 被反复拉取、密文长度与明文参数变化不匹配，可作为自动化改包特征。
