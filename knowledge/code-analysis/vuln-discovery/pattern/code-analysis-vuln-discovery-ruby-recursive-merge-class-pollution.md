---
id: code-analysis-vuln-discovery-ruby-recursive-merge-class-pollution
title: Ruby 不安全递归合并导致类污染：经 class→superclass→subclasses 穿越改写任意类的实例变量
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery/pattern
technique: ruby-recursive-merge-class-pollution-attribute-write
aliases:
- Ruby 类污染
- 递归合并类污染
- class.superclass.subclasses 污染链
- instance_variable_set 污染
- Ruby deep_merge 污染
tags:
- ruby
- class-pollution
- prototype-pollution
- recursive-merge
- unsafe-deserialization
- code-pattern
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:37:55+08:00'
  notes: 已对照原文核对；本次核对未读取图片；recursive_merge 源码、respond_to?/public_send/instance_variable_set/singleton_class.attr_accessor 骨架、污染当前对象(protected_methods+instance_eval)、污染父类(class.superclass.cmd 新增 @cmd 遮盖 @@cmd)、污染其他类(subclasses+Array#sample 循环 1000 次)与 Doyensec 的 url/signing_key 案例，均与正文一致；PoC 为正文示例整理，执行回显未读图验证
---

## 一句话结论

当 Ruby 服务把请求里的 JSON/Hash 交给"递归合并到对象自身"的 `merge` 实现（`respond_to?` 判断后 `public_send` 取子对象、末端 `instance_variable_set("@#{key}")` 写实例变量），攻击者提交的键名就是实例变量名；再借助 Ruby 对象自带的 `class`、`superclass`、`subclasses` 三个属性逐层跳到目标类，就能改写"别的类"的实例变量，从而实现跨对象、跨类的属性污染（类污染）。这与 JavaScript 原型链污染同源，成因都是对不可信数据做不安全的递归合并。

## 原理

- 这类 `recursive_merge` 的骨架是：遍历 `additional` 的键值；值是 Hash 且 `current_obj.respond_to?(key)` 时，`public_send(key)` 取到子对象后递归；否则 `instance_variable_set("@#{key}", value)` 并 `singleton_class.attr_accessor key`。键名被直接当成实例变量名与访问器名，没有任何白名单。
- 因此 `{"x": 1}` 会变成 `@x = 1`；更关键的是值也可以是 Hash，于是键可以沿"对象已有的 getter"一路走下去。Ruby 所有对象都有 `class`（当前类）、`superclass`（父类）、`subclasses`（Object 的子类数组）三个方法，天然构成一条从任意对象通往任意类的通用路径。
- 污染"当前对象"简单：`a.merge_with({"protected_methods": ["`calc`"]})` 之后，凡是把 `protected_methods` 的返回值交给 `instance_eval`/`eval` 的代码就会执行攻击者的字符串。
- 污染"父类"：`{"class":{"superclass":{"cmd": "`calc`"}}}` 会在父类上新增实例变量 `@cmd`；当业务用 `Base.cmd`（属性读取）而不是 `@@cmd`（类变量）时，新增的实例变量会**遮盖**原类变量，于是读到攻击者的值。注意 `eval(@@cmd)` 这种直接引用类变量的写法不受影响，覆盖不了。
- 污染"其他类"：`subclasses` 返回数组，递归合并到数组时会命中数组的方法；用 `{"sample": {...}}` 让它在合并阶段实际调用 `Array#sample` 随机取一个子类，于是每次污染只命中一个随机类，需要循环多次（几十到上千次）提高命中率；除此之外还能用 `first`/`last`/下标等数组方法做确定性选择。
- 危害不限于 RCE：Doyensec 的案例里污染 `Person` 的 `url` 做 SSRF、污染 `KeySigner` 的 `signing_key` 伪造签名；同一条原语既改配置也改密钥。

## 触发条件

- 应用存在把用户可控 Hash 递归合并进对象（而不是合并进普通 `Hash`）的实现，或使用了带类似语义的库（ActiveSupport `deep_merge` 用于对象、Hashie `deep_merge` 等，视版本与用法）。
- 合并过程信任键名，未过滤 `class`/`superclass`/`subclasses`/`instance_variable_set` 相关键。
- 目标类的方法/属性会被业务在后续请求中读取（RCE 还需要一个把被污染值当代码执行的 sink，如 `eval`、`instance_eval`、反引号、模板渲染）。
- 进程常驻（污染作用于进程内存，重启即失效）；多 worker 时需要对每个 worker 分别打。

## 利用步骤

1. 找到接收 JSON 并"合并进对象"的入口（注册、资料更新、配置合并、批量导入），确认递归合并会走到 `instance_variable_set`。
2. 先用 `{"x":1}` 之类无害键验证对象属性被改写（可通过该对象的 `inspect`、详情接口或行为变化观察）。
3. 判断污染范围：目标是当前对象、父类（`class.superclass`），还是不相干的类（`class.superclass.subclasses.sample`）。
4. 对其他类的情况写循环批量提交，靠 `sample` 的概率逐步命中；有确定性数组方法（`first`/`last`/`at`）时优先用它们。
5. 命中后读回被污染值所影响的行为：签名校验通过、SSRF 发出外连、模板渲染执行命令等。

## PoC

```ruby
# 脆弱实现骨架
def recursive_merge(original, additional, current_obj = original)
  additional.each do |key, value|
    if value.is_a?(Hash)
      if current_obj.respond_to?(key)
        recursive_merge(original, value, current_obj.public_send(key))
      else
        new_object = Object.new
        current_obj.instance_variable_set("@#{key}", new_object)
        current_obj.singleton_class.attr_accessor key
      end
    else
      current_obj.instance_variable_set("@#{key}", value)
      current_obj.singleton_class.attr_accessor key
    end
  end
  original
end
```

```json
// 污染父类的实例变量，遮盖同名的类变量
{"class": {"superclass": {"cmd": "`calc`"}}}

// 污染"其他类"：借 Array#sample 随机命中一个 Object 子类，需循环多次
{"class": {"superclass": {"subclasses": {"sample": {"cmd": "`calc`"}}}}}
```

## 变体与关联

- 变体（确定性命中）：把 `sample` 换成 `first`/`last`/`at` 等数组方法，或先污染目标类的某个已知属性名，避免概率。
- 变体（合并语义）：Rails `ActiveSupport#deep_merge`、`Hashie::Mash` 的 `deep_merge`、自写 `deep_merge!`；只要"值可递归、键可写属性"就成立。
- 关联：[[web-python-recursive-merge-class-pollution-globals-rce]]（Python 递归合并类污染，`__class__.__base__` → `__init__.__globals__`）、[[web-nodejs-prototype-pollution-merge-json-parse]]（JS 原型链污染）；三种语言的共同点是"递归合并 + 键名信任"。
- 边界：Ruby 没有 JS 那样的原型链，所以"污染"实际是给类对象新增/覆盖实例变量与访问器，作用范围是进程内该类对象；只影响读取该属性的代码路径，不影响方法表本身。

## 检测与防御

- 修复：用户可控 Hash 只合并进普通 `Hash`（`Hash#merge`/显式字段白名单），禁止"按 key 反射写实例变量"的通用合并；必须对象化时用 `strong_parameters` 式的字段白名单。
- 加固：对键名做白名单校验，显式拒绝 `class`、`superclass`、`subclasses`、`instance_variable_set`、`singleton_class` 等反射相关键；敏感配置（签名密钥、SSRF 目标、模板）不放在可被合并改写的类属性上。
- 检测：请求体出现 `class`/`superclass`/`subclasses`/`instance_variable_set`/`singleton_class` 键；同一接口短时间内大量重复提交相似 JSON（概率污染特征）；进程内出现异常 `os.popen`/反引号子进程。
- 审计：搜索 `instance_variable_set`、`singleton_class`、`public_send(`, `send(`, `deep_merge` 的调用点，回溯键名是否来自外部输入。
