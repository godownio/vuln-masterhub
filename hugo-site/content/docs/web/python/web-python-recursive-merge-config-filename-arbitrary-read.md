---
id: web-python-recursive-merge-config-filename-arbitrary-read
title: Python 递归 merge 属性污染：config.filename 改为 /flag 后任意文件读取
type: scenario
domain: web
path: web/python
technique: python-recursive-merge-instance-attribute-file-read
tags:
- python
- flask
- merge
- attribute-pollution
- file-read
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:26:52+08:00'
  notes: 已对照原文核对：merge(src,dst) 的 hasattr/getattr/setattr 递归、merge(json.loads(request.data), instance)、instance.config.filename 初始 app.py、payload {"config":{"filename":"/flag"}}、/read 执行 open(instance.config.filename).read() 均一致。未验证点：无靶机，PoC 未复跑；原文未标注受影响版本；frontmatter 无 sources/source_url。
url: /docs/web/python/web-python-recursive-merge-config-filename-arbitrary-read/
draft: false
kb_aliases:
- ez_python
- Python merge 属性污染
- config.filename
- 递归合并读文件
- hasattr setattr merge
- Flask /read 任意文件
---

## 一句话结论

当 Flask 应用把用户 JSON 交给 `hasattr`/`getattr`/`setattr` 的递归 merge，且目标实例的某个属性被用作文件路径（如 `config.filename`）时，提交 `{"config":{"filename":"/flag"}}` 就能把该属性改成任意路径，随后 `/read` 用 `open(instance.config.filename).read()` 读取 flag。

## 原理

- 目标 merge 的典型逻辑：
  ```python
  def merge(src, dst):
      for k, v in src.items():
          if hasattr(dst, '__getitem__'):
              if dst.get(k) and type(v) == dict:
                  merge(v, dst.get(k))
              else:
                  dst[k] = v
          elif hasattr(dst, k) and type(v) == dict:
              merge(v, getattr(dst, k))
          else:
              setattr(dst, k, v)
  ```
- 入口 `merge(json.loads(request.data), instance)` 中，`instance` 是 `Polaris` 实例；`Polaris` 没有 `__getitem__`，但有 `config` 属性且其值是 `Config` 对象。因此 `{"config":{"filename":"/flag"}}` 会走 `hasattr(dst, 'config')` 分支，递归进入 `instance.config`。
- `Config` 对象同样没有 `__getitem__`，`filename` 不是 dict，最终执行 `setattr(instance.config, 'filename', '/flag')`，把原本的 `"app.py"` 覆盖成 `/flag`。
- `/read` 路由直接 `open(instance.config.filename).read()`，于是读取 `/flag` 并返回。
- 这个漏洞不需要 `__class__`/`__base__` 等 dunder 路径；它利用的是“merge 允许用户控制任意属性名 + 业务把属性当文件路径”的组合。若 merge 还允许 dunder，则可进一步做类属性提权、`__globals__` 污染/RCE（见关联卡片）。
- 根因是“把用户输入递归合并进有状态对象”，且没有属性白名单/路径白名单；文件读取 sink 直接信任对象属性。

## 触发条件

- 应用接受 JSON 并递归 merge 到实例/对象，merge 不限制属性名（至少允许普通属性）。
- 目标对象有被业务用作文件路径、命令、模板名、URL 等的属性。
- 读取/执行 sink 直接使用该属性，没有白名单或 `realpath` 校验。
- 攻击者能访问 merge 入口与 sink 路由。

## 利用步骤

1. 阅读 merge 实现，确认递归分支与目标对象结构（`instance.config.filename`）。
2. 发送 `{"config":{"filename":"/flag"}}`，观察是否返回成功/无异常。
3. 访问 `/read`（或对应读取路由），获取文件内容。
4. 若目标属性被覆盖后不可逆，先读小文件验证，再读 flag；必要时用 `../../` 或绝对路径。
5. 若 merge 允许 dunder，继续尝试 `__class__.__base__` 提权或 `__class__.__init__.__globals__` 污染（见关联卡）。

## PoC

```http
POST / HTTP/1.1
Host: target
Content-Type: application/json

{"config":{"filename":"/flag"}}
```

```http
GET /read HTTP/1.1
Host: target
```

响应即 `/flag` 内容。

## 变体与关联

- **属性 sink 变体**：`filename`、`path`、`template`、`cmd`、`url`、`secret_key`；文件读取、模板渲染、命令执行、SSRF。
- **merge 变体**：`hasattr/getattr/setattr`、`__dict__` 递归、字典与对象混合递归、`setattr` 直接写实例；`pydash.set_` 等第三方库。
- **dunder 变体**：`__class__.__base__` 改类属性提权、`__class__.__init__.__globals__` 覆盖 Flask `secret_key`/命令白名单/RCE。
- **关联**：[[web-python-recursive-merge-class-pollution-globals-rce]]（同类 merge 的类污染/globals/RCE 完整链）；[[web-python-pydash-set-attribute-path-pollution]]（`pydash.set_` 路径污染）；[[web-python-framework-pydash-set-jinja-loader-searchpath]]（属性污染改模板加载路径）。
- **边界**：merge 使用属性白名单、只允许标量配置、对象使用 `__slots__`/不可变类型、文件读取使用固定白名单时，本路径失效。

## 检测与防御

- **检测**：请求 JSON 出现 `config`、`filename`、`path`、`__class__`、`__globals__` 等键；merge 后对象属性被改写；`/read` 返回非预期文件。
- **防御**：merge 使用字段白名单，拒绝 dunder 与路径/命令类属性；配置对象与用户输入分离，不把用户 JSON 直接合并进业务对象。
- **加固**：文件读取使用固定目录白名单与 `realpath` 前缀校验；Flask 关闭调试、移除 `/src` 等源码路由。
