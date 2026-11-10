---
id: web-php-deserialization-premature-destruct-bypass
title: PHP 反序列化提前析构：畸形序列化串/重复键/私有属性名长度错位让 __destruct 抢在 __wakeup 与异常退出之前
type: scenario
domain: web
path: web/php/deserialization
technique: php-unserialize-premature-destruct
tags:
- php
- deserialization
- destruct
- wakeup
- garbage-collection
- bypass
- pop-chain
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: 7.4.x - 7.4.30；8.0.x
verification:
  verified_by: verifier-T1-17
  verified_at: '2026-11-08T08:51:57+08:00'
  notes: '已对照原文核对：截断串/重复键触发 __destruct 有图 02/04 实测回显 flag；#9618 私有属性名长度错位在图 05/06 验证输出由 __wakeup__destruct 变为 __destruct__wakeup。affected_versions 7.4.x-7.4.30/8.0.x 取自原文 #9618 小节显式列出，仅变体三受版本约束。未验证点：真实站点上未复现；变体二循环引用仅在文末提及未给 PoC。'
url: /docs/web/php/deserialization/web-php-deserialization-premature-destruct-bypass/
draft: false
kb_aliases:
- PHP 提前析构
- fast destruct
- 快速析构
- GC 提前触发 __destruct
- 反序列化绕过 exit/throw
- php-src issue 9618
- 属性名长度错位绕过 wakeup
- 重复键 GC
---

## 一句话结论

当利用点只能通过 `__destruct()` 触发、而业务在 `unserialize()` 之后立刻 `die`/`exit`/`throw`，或 `__wakeup()` 会先重置关键属性时，可以通过畸形序列化串让引擎在解析失败清理阶段、或用重复数组键把对象引用计数降为 0、或用私有属性名长度错位（php-src #9618）把 `__destruct()` 提前到 `__wakeup()` 之前执行，从而拿到原本不可达的析构链。

## 原理

- **析构时机由引用计数决定，而不是脚本结尾**：PHP 对象在 `refcount` 归零时立即释放并调用 `__destruct()`。`unserialize()` 过程中如果临时建立的对象被覆盖或解析失败，引擎必须清理已创建的对象，此时 `__destruct()` 当场执行，根本不会等到后面的 `die`/`throw`。
- **变体一：解析失败提前清理**。`unserialize()` 按长度读取字符串、按 `;`/`}` 分隔字段，格式错误时会中止并释放已构建的对象。把正常 payload `O:1:"B":0:{}` 去掉结尾 `}`（或截断任意位置），解析器读到不完整结构即报错退出，但此前构造的 `B` 对象已被销毁 → `__destruct()` 触发，`throw new Exception` 之后才执行也拦不住。
- **变体二：重复键让对象引用计数归零**。序列化数组 `a:2:{s:1:"a";O:1:"B":0:{}s:1:"b";N;}` 若把第二个键名也改成 `a`（`...s:1:"a";N;}`），反序列化时后一个 `N` 覆盖前一个键，前一个 `B` 对象的唯一引用被抹掉，`refcount` 立即降为 0，`__destruct()` 在反序列化过程中执行。这条路径不依赖 PHP 版本缺陷，属于语言语义。
- **变体三：私有属性名长度错位（php-src #9618，7.4.x–7.4.30 / 8.0.x）**。私有属性序列化为 `s:<长度>:"\0类名\0属性名"`，其中 `\0` 是真实 NUL 字节。把声明的长度改小（如 `s:6:" A end"` 写成 `s:5:"Aend"`，即去掉类名前的 NUL），解析器按错误长度切分，剩余字节错位导致属性表结构异常；引擎在错误路径上先销毁对象，`__destruct()` 早于 `__wakeup()` 执行，于是 `__wakeup()` 里对敏感属性的赋值（如 `$this->znd = "exit();"`）来不及生效。
- **为什么这能扩大危害**：很多链的“闸门”就设在 `__wakeup()` 的重置或 `unserialize` 之后的前置检查上；提前析构把“先重置再使用”变成“先使用再重置/不再重置”，等价于绕过 `__wakeup`，同时绕开 `die`/`exit`/`throw` 造成的链中断。
- **与属性数绕过（CVE-2016-7124）的区别**：后者是声明属性数大于实际，让 `__wakeup()` 整体不执行但仍正常完成反序列化；本卡是利用错误路径/引用计数让 `__destruct()` 抢跑，二者可叠加使用。

## 触发条件

- 应用对用户输入调用 `unserialize()`，且危险操作位于 `__destruct()`。
- 正常流程中析构被阻断：`unserialize()` 后紧跟 `die`/`exit`/`throw`，或 `__wakeup()` 会重置 payload 依赖的属性。
- 变体三需要目标 PHP 处于受影响版本区间（7.4.x ≤ 7.4.30、8.0.x 早期），且类中存在私有属性。
- 目标类可被实例化（无 `allowed_classes` 限制或包含该类）。

## 利用步骤

1. 确认 sink 在 `__destruct()`，并观察 `unserialize()` 之后是否有 `die`/`exit`/`throw` 或 `__wakeup()` 重置。
2. 本地生成正常 payload，确认 `__wakeup` 与 `__destruct` 的打印顺序（如 `__wakeup__destruct`）。
3. 按阻断类型选变体：
   - 有 `throw`/`exit`：删除结尾 `}` 或截断串，观察 `__destruct` 是否先打印。
   - 数组包裹：把第二项的键名改成与第一项相同，让对象被 `N` 覆盖。
   - 有 `__wakeup` 重置：把私有属性名的长度改小 1（去掉类名前的 NUL），观察输出变为 `__destruct...__wakeup`。
4. 在真实目标上发送畸形串，确认危险操作（命令、文件读取、写文件）先于阻断逻辑发生。
5. 若目标已修复 #9618，退回重复键或截断变体；三者不互相依赖。

## PoC

变体一，截断触发提前析构（`throw` 也拦不住）：

```php
<?php
class B {
    function __destruct() {
        global $flag;
        echo $flag;
    }
}
// 正常: O:1:"B":0:{}
// 发送: O:1:"B":0:{
```

变体二，重复键让对象在反序列化中销毁：

```text
a:2:{s:1:"a";O:1:"B":0:{}s:1:"a";N;}
```

（原串第二项键名为 `b`，改成 `a` 后对象被 `NULL` 覆盖。）

变体三，私有属性名长度错位（php-src #9618）：

```text
正常: O:1:"A":2:{s:4:"info";O:1:"B":1:{s:3:"znd";N;}s:6:" A end";s:1:"1";}
畸形: O:1:"A":2:{s:4:"info";O:1:"B":1:{s:3:"znd";N;}s:6:"Aend";s:1:"1";}
```

正常顺序输出 `__wakeup__destruct__call`，畸形串输出 `__destruct__call__wakeup`，说明 `__wakeup` 的 `$this->znd = "exit();"` 已失效。

## 变体与关联

- **变体**：解析失败截断、重复数组键覆盖、私有/保护属性名长度错位、`__PHP_Incomplete_Class` 触发清理、对象属性指向自身造成循环引用（GC 周期回收时析构）。
- **叠加**：与属性数绕过（CVE-2016-7124）、引用别名（`R:2`）组合，可同时绕过“wakeup 不执行”和“wakeup 执行了但被覆盖”两类防护。
- **关联**：[[web-php-deserialization-wakeup-property-count-bypass]]（声明属性数大于实际，跳过 wakeup）；[[web-php-deserialization-wakeup-reference-alias-bypass]]（引用别名让 wakeup 重置被写回）；[[web-php-deserialization-ez-uns-trailing-space-gc-php-filter-traversal]]（重复键 GC 在具体题目链中的应用）；[[web-php-deserialization-destruct-system-webshell-base64]]（destruct 命令执行 sink）。
- **边界**：PHP 8 对部分畸形串的行为已收紧（#9618 修复后不再先析构）；若 `unserialize` 使用 `allowed_classes=false`、或危险操作不在 `__destruct`，该技巧无效。

## 检测与防御

- **不要把安全边界放在 `__wakeup()` 或 `unserialize()` 之后的检查上**：两者都可能被提前析构/解析错误路径绕过。校验应在使用前、且基于不可绕过的状态。
- **禁止用户可控的反序列化**：使用 JSON 等数据格式；必须反序列化时用 `allowed_classes` 白名单限制可实例化类。
- **消除 destruct sink**：`__destruct()` 中不要执行命令、文件写、网络请求等敏感操作；把清理逻辑改为显式调用。
- **检测**：请求中出现不完整序列化串（缺 `}`、长度与内容不符、重复键名）、私有属性名长度与实际不符；同一请求内 `__destruct` 日志早于 `__wakeup`；反序列化入口收到非 `O:` 规范结构。
- **加固**：升级到已修复 #9618 的 PHP 版本；对反序列化做结构校验（长度、键唯一性）并拒绝畸形输入；高危操作使用独立权限进程。
