---
id: web-java-framework-shiro-configured-weak-cipherkey-rememberme-rce
title: Shiro 1.4.0 版本号"已验证安全"仍中招：配置文件里自设 cipherKey（短字符串 copyOf 补齐 16 字节）让 rememberMe 依旧可伪造，审计必须查密钥来源而非只看版本
type: scenario
domain: web
path: web/java/framework/shiro
technique: shiro-configured-weak-cipherkey-rememberme-forgery
tags:
- shiro
- rememberme
- deserialization
- hardcoded-key
- java
- access-control
- audit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-13'
affected_versions: Apache Shiro 1.4.0（原文实测版本；本场景不依赖 CVE-2016-4437 的版本区间）
verification:
  verified_by: verifier-V653-fix
  verified_at: '2026-11-13T05:46:15+08:00'
  notes: 依 12505 复验结论统一修正反序列化入口表述：DefaultSerializer 用 ClassResolvingObjectInputStream（ClassLoader.loadClass）而非原生 ObjectInputStream；其余内容未动。
url: /docs/web/java/framework/shiro/web-java-framework-shiro-configured-weak-cipherkey-rememberme-rce/
draft: false
kb_aliases:
- cipherKey 自配置
- Arrays.copyOf 补齐 16 字节
- Shiro 1.4.0 rememberMe 伪造
- 版本安全但密钥弱
- rememberMe_shiro_key
---

## 一句话结论

Shiro 1.2.5 起 `rememberMe` 的 AES 密钥默认改为运行期随机生成（此前是硬编码常量），单看版本号会得出"大概率没漏洞"的结论；但只要项目配置里显式写了 `cipherKey`（哪怕是一句 `"rememberMe_shiro_key"` 这种业务向字符串，用 `Arrays.copyOf(bytes, 16)` 补/截到 16 字节再 Base64），密钥就重新变成全局可预测的常量，攻击者照样能自己加密 ysoserial payload 塞进 `rememberMe` 触发反序列化 —— 审计的正确入口是**密钥来源**，不是 CVE 版本表。

## 原理

- `CookieRememberMeManager` 的加解密是对称的：`rememberMe = base64(IV ‖ AES-CBC(key, 序列化字节))`。服务端解密后交给 `DefaultSerializer.deserialize()`（`ClassResolvingObjectInputStream`，经 `ClassLoader.loadClass` 解析类名），因此"能不能构造合法密文"等价于"知不知道 key"。
- Shiro 1.2.x 的 `AbstractRememberMeManager` 里 `DEFAULT_CIPHER_KEY_BYTES` 是硬编码常量（CVE-2016-4437 的根因）。1.2.5 之后改为运行期随机生成，所以默认配置确实安全 —— 这正是"版本判断"成立的部分（本例 1.4.0 已在该改动之后）。
- 失效点在于**配置覆盖**：项目为了多节点会话一致，会把 `securityManager.rememberMeManager.cipherKey` 写成固定值；而 Spring/Shiro 的 `setCipherKey(byte[])` 要求 16/24/32 字节，运维常用"业务名 + copyOf 补齐"的写法，于是密钥 = 可猜字符串。
- 一旦 key 可猜，攻击链与 1.2.x 完全相同：本地用该 key 加密 CommonsBeanutils/CommonsCollections gadget（或 JNDI 链），放到 `rememberMe` Cookie 里发一个请求即可。
- 判定的可观测信号：响应中出现 `Set-Cookie: rememberMe=deleteMe`（密钥不匹配时的清除动作）；反之若构造的 Cookie 没被 `deleteMe` 掉，说明 key 猜对了。

## 触发条件

- 目标使用 Shiro 做会话/权限，并启用 rememberMe（登录页有"记住我"，或任意响应里出现 `rememberMe` Cookie）。
- 配置中存在固定的 `cipherKey`（明文、Base64、或"字符串 copyOf 到 16 字节"这类派生写法），且该值可从配置泄露、源码泄露、默认值字典或规律猜出。
- classpath 中存在可用 gadget 依赖（CommonsBeanutils/CommonsCollections）或可利用的 JNDI 链。

## 利用步骤

1. 确认 Shiro：请求带 `rememberMe=xxx`，观察响应是否出现 `rememberMe=deleteMe`。
2. 找密钥：从源码包/配置文件/泄露的 `application.yml` 里搜 `cipherKey`、`setCipherKey`、`rememberMe`；若是"业务字符串 + copyOf"，按同样的补齐规则算出 16 字节。
3. 把密钥按项目代码的方式转成 Base64（`Base64.getEncoder().encodeToString(Arrays.copyOf(keyBytes, 16))`）。
4. 用 ShiroAttack2 或自写脚本：选 gadget 链 → 生成 payload → 用该 key AES-CBC 加密 → 拼 `base64(IV+ct)` 放入 `rememberMe`。
5. 发送请求验证回显；无回显时换 DNS/JRMP 外带确认。

## PoC

```java
// 原文中的密钥派生方式：把业务字符串补齐/截断到 16 字节再 Base64
import java.util.Arrays;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class ShiroKeyDerive {
    public static void main(String[] args) {
        byte[] raw = "rememberMe_shiro_key".getBytes(StandardCharsets.UTF_8);
        String key = Base64.getEncoder().encodeToString(Arrays.copyOf(raw, 16));
        System.out.println(key);   // 即配置文件里 cipherKey 的等价形式
    }
}
```

```text
# Cookie 形态（IV 随机 16 字节，ct = AES-CBC(key, gadget 序列化字节)）
Cookie: rememberMe=base64(IV + ct)
# 若 key 错误，响应会带 rememberMe=deleteMe；无 deleteMe 说明密钥正确
```

## 变体与关联

- 密钥来源变体：默认常量（CVE-2016-4437 区间）、配置写死、从 heapdump/Actuator 里 dump 出来的运行期 key、多环境共用同一 key。
- 利用变体：CommonsBeanutils1/CommonsCollectionsK1 直接命令执行；TemplatesImpl 打 JDK 高版本；JNDI 打不出网环境；无回显走 URLDNS/JRMP。
- 与 Shiro-550（≤1.2.4 默认硬编码 key）的区别：本场景的版本不在 CVE 区间内，靠的是"自配置弱密钥"，检测点从"版本 < 1.2.5"变成"配置里存在固定 cipherKey"。
- 关联：Shiro 路径鉴权绕过（`/xxx/..;/`、静态后缀）常与 rememberMe 组合，前者进后台、后者拿 shell。

## 检测与防御

- 检测：审计时全局搜 `cipherKey`/`setCipherKey`/`rememberMeManager`，确认密钥是否为硬编码或可推导常量；运行时检查响应中是否出现 `rememberMe=deleteMe`（异常的密钥不匹配尝试）。
- 防御：`cipherKey` 用 CSPRNG 生成的 16/24/32 字节并纳入密钥管理（KMS/Vault），禁止业务字符串派生；多节点共享密钥也要走密钥分发而非写死在配置；升级 Shiro 并移除所有自定义 `cipherKey` 配置项；classpath 清理不必要的 gadget 依赖。
