---
id: web-php-deserialization-serializable-nested-unserialize-var-hash-uaf
title: PHP 8 Serializable 接口嵌套反序列化继承 var_hash 导致 UAF
type: scenario
domain: web
path: web/php/deserialization
technique: serializable-nested-unserialize-var-hash-uaf
aliases:
- PHP8 Serializable UAF
- zend_user_unserialize serialize_lock 缺陷
- var_hash 悬垂指针
- CachedData unserialize UAF
- PHP 8.5 unserialize 内存破坏
tags:
- php
- php8
- deserialization
- unserialize
- serializable
- uaf
- memory-corruption
- var-hash
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: PHP 5.1–8.5（原文：自 5.1 引入 Serializable 接口起至 8.5；公开利用插件仅适配 8.4/8.5）
verification:
  verified_by: verifier-V35
  verified_at: '2026-11-05T06:09:58+08:00'
  notes: '已对照原文核对：CachedData::unserialize 内 unserialize($data)->x=0、内层 8 属性 stdClass 填满 nTableSize=8、第 9 属性触发 8→16 扩容释放 arData、外层 R: 引用形成 UAF；原文该成因段标注由 AI 生成，完整利用链另有脚本与截图佐证 RCE，未在本机复现。'
---

## 一句话结论

当应用把用户数据交给 `unserialize()`，且某个实现 `Serializable` 的类在自身 `unserialize()` 方法里再次调用 `unserialize()` 并对返回对象写入新属性时，内层反序列化会继承外层 `var_hash`；属性写入触发 HashTable 扩容并释放旧 `arData`，外层 `var_hash` 留下悬垂指针，后续 `R:N;` 引用即可触发 UAF，进而发展为 PHP 进程内任意读写与 RCE。

## 原理

- `unserialize()` 在解析时维护 `var_hash`，记录已解析变量的槽位，用于解析 `R:N;`/`r:N;` 引用。
- 漏洞点在 Zend/zend_interfaces.c 的 `zend_user_unserialize()`：调用用户自定义的 `Serializable::unserialize()` 方法时，没有递增 `BG(serialize_lock)`。因此该方法内部再次调用 `unserialize()` 时，内层会误以为自己是顶层调用，与外层共用同一份 `var_hash`。
- 内层 payload 反序列化出一个恰好 8 个属性的 `stdClass`，填满 Zend HashTable 初始容量 `nTableSize=8`。随后 `unserialize($data)->x = 0` 写入第 9 个属性，强制容量从 8 倍增到 16，旧 `arData`（约 288 字节）被 `efree` 释放。
- 外层 `var_hash` 仍保存着指向旧 `arData` 中桶（bucket/zval）的指针。外层 payload 继续解析到 `R:N;` 时，引擎按这些已释放槽位取引用，形成典型的 Use-After-Free。
- 释放的 288 字节块可被攻击者控制内容的 PHP 字符串（喷射）重新占用。这样 `var_hash` 中的悬垂指针就指向伪造的 zval/字符串结构，形成类型混淆与任意地址读写的起点。
- 该缺陷是反序列化引擎的引用管理问题，与具体 POP 链无关；只要应用存在上述嵌套反序列化写法，攻击者不需要目标类本身有危险魔术方法。

## 触发条件

- PHP 5.1 至 8.5 之间使用 `Serializable` 接口的版本（公开利用仅适配 8.4/8.5 的偏移）。
- 应用对用户可控数据调用 `unserialize()`，且存在如下模式：某个 `Serializable` 类的 `unserialize()` 内部再次 `unserialize()` 并对结果写入属性。
- 攻击者可提交包含 `C:`（Serializable 对象）、内层 `O:` 对象和若干 `R:` 引用的序列化串；通常可重复请求以完成多阶段内存探测。
- 完整 RCE 还依赖目标进程可被多次请求、内存布局稳定；失败时可能导致 PHP worker 崩溃。

## 利用步骤

1. 定位反序列化入口与类模式：输入进入 `unserialize()`，且类实现 `Serializable`，其 `unserialize()` 内调用 `unserialize($inner)` 后至少写一个属性（如 `->x = 0`）。
2. 构造内层对象：`O:8:"stdClass":8:{...}`，写满 8 个属性，使 `nTableSize=8`；第 9 个属性由应用代码的写入触发，攻击者无需在 payload 中直接写。
3. 构造外层 `C:` 对象，把内层串作为其 `unserialize()` 的参数；再在外层数组中放入大量 280 字节左右的可控字符串用于喷射，并用 `R:N;` 引用被释放的槽位。
4. 利用阶段：从喷射字符串被改写的 zval 中泄露堆地址；在堆附近扫描 ELF 头定位 libphp；解析 `.gnu_hash`/`.dynamic` 找 `executor_globals`；转储 GOT 找 libc 与 `system`；读取 `EG.class_table` 找 `stdClass` class entry；定位可复用的 320 字节 spray 槽；伪造对象并把 handler 指向 `system`。
5. 触发伪造对象，执行命令；由于单次触发受对象头/命令长度限制，长命令可用多次 14 字节 `echo -n ...>>w` 拼接后再 `mv`/`bash`。

## PoC

```php
<?php
// 漏洞端点：Serializable::unserialize() 内再次反序列化并写属性
class CachedData implements Serializable {
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void {
        unserialize($data)->x = 0;   // 内层 8 属性对象 + 第 9 次写入触发 8→16 扩容
    }
}
unserialize($_GET['c']);
```

```text
# 最小触发串结构（<len> 需按实际字节数填写）
C:10:"CachedData":<len>:{O:8:"stdClass":8:{s:2:"p0";i:1;s:2:"p1";i:2;s:2:"p2";i:3;s:2:"p3";i:4;s:2:"p4";i:5;s:2:"p5";i:6;s:2:"p6";i:7;s:2:"p7";i:8;}}
```

```text
# 完整利用的外层结构示意
a:<n>:{i:0;<上面的 C 串>;
        i:1;s:280:"<可控喷射内容>"; ...   # 多次 spray
        i:k;R:<被释放槽位编号>; ...}      # 触发悬垂引用
```

完整 RCE 需要对堆地址、libphp/libc 基址、EG/class_table 做上千次 HTTP 探测，不属于最小 PoC；公开实现已武器化为蚁剑插件并给出 8.4/8.5 版本偏移。

## 变体与关联

- 变体：内层对象不限于 `stdClass`，任何能通过属性写入触发 HashTable 扩容的对象都可填充 `arData`；外层 `R:` 的数量和位置决定悬垂槽位的复用方式。
- 变体：将 UAF 只用于信息泄露（堆地址、ELF 基址、GOT），不直接 RCE；在目标有额外沙箱时用于绕过地址随机化。
- 关联：[[web-php-rce-uaf-memory-corruption-disable-functions-bypass]]（同一 UAF 的后续利用：解析 `zif_system`/libc `system` 绕过 disable_functions）；[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（对比：纯用户态 POP 链，本卡是引擎内存破坏）。
- 边界：应用若不对不可信数据调用 `unserialize()`、或没有“嵌套 unserialize + 写属性”的代码模式，本漏洞不可触发；只发 `C:` 对象但没有内层递归调用不成立。

## 检测与防御

- 检测：审计代码中 `unserialize()` 的调用点及 `Serializable::unserialize()` 内的递归反序列化；监控包含大量 `C:`/`O:`/`R:` 结构的请求、同一端点的反复异常请求，以及 PHP-FPM worker 的 SIGSEGV/重启。
- 修复：升级到包含 `serialize_lock` 修复的 PHP 版本；对不可信数据改用 `json_decode`，必须反序列化时使用 `allowed_classes` 白名单并避免嵌套调用。
- 加固：清除业务代码中不必要的 `Serializable` 实现；以低权限运行 PHP-FPM，配合 `open_basedir`、容器/seccomp、AppArmor 限制进程可访问的文件与系统调用；WAF 只能提高门槛，不能可靠识别内存破坏 payload。
