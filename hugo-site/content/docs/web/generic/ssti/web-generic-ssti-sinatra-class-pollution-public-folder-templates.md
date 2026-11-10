---
id: web-generic-ssti-sinatra-class-pollution-public-folder-templates
title: Sinatra 类污染利用：改写 public_folder 读任意目录、覆盖 templates 哈希注入 ERB 模板拿 RCE
type: scenario
domain: web
path: web/generic/ssti
technique: sinatra-class-pollution-public-folder-templates-erb
tags:
- ruby
- sinatra
- class-pollution
- ssti
- erb
- arbitrary-file-read
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:37:56+08:00'
  notes: 已对照原文核对；本次核对未读取图片；Sinatra set 经 class_eval 定义类方法、public_folder 四条 superclass 的污染 payload(E:/Server)、templates 为模板名→内容的哈希、template 方法给 templates 赋值、erb :hello 路由覆盖成 <%= `calc` %> 实现 RCE，均与正文一致；set/class_eval 与模板调试截图未读，实际回显未验证；原文本条为 Sinatra 侧利用推演，未见完整端到端请求记录，已在卡内保留置信度 medium
url: /docs/web/generic/ssti/web-generic-ssti-sinatra-class-pollution-public-folder-templates/
draft: false
kb_aliases:
- Sinatra 类污染
- Sinatra public_folder 污染
- Sinatra templates 哈希污染
- set 方法 class_eval 污染
- 类污染写 ERB 模板
---

## 一句话结论

Sinatra 的 `set :public_folder, ...` 本质是用 `class_eval` 给 `Sinatra::Base` 动态定义同名 getter/setter，配置项就是类上的方法；因此拿到 Ruby 类污染原语后，把 `public_folder` 指向任意目录即可把静态文件服务变成任意文件读取，把 `templates` 哈希里的模板名覆盖成含 `<%= ... %>` 的字符串，就能让已有的 `erb :hello` 路由渲染攻击者模板并执行系统命令。

## 原理

- Sinatra 的 `set` 不是在维护一张普通配置表，而是定义访问器：执行 `set :public_folder, path` 后，`Sinatra::Base` 类上就出现了名为 `public_folder` 的方法（读）与赋值方法（写），后续静态文件中间件读这个方法来决定根目录。
- 类污染原语允许给任意类"新增/覆盖实例变量并挂上 attr_accessor"。把 `public_folder` 写到 `Sinatra::Base` 上（或它的父类上，通过属性遮盖生效）后，静态路由就会用攻击者指定的目录做根，`GET /<文件名>` 即可读出该目录下的任意文件——典型目标是把 `public_folder` 指向 `/` 或应用根目录读源码、配置、密钥。
- 模板侧：`Sinatra::Base` 的 `templates` 是一个哈希（模板名 → 模板内容），默认模板目录是 `./views`，也支持 `template :index do ... end` 直接给内容。`erb :hello` 渲染时会先查这个哈希。
- 因此把 `templates` 污染成 `{"hello": "<%= `cmd` %>"}`，再访问那条已经存在的 `erb :hello` 路由，就会以应用进程权限执行 Ruby 代码。ERB 没有沙箱，反引号、`system`、`%x{}`、`File.read` 全部可用。
- 关键点是这不需要新增路由、不需要文件写权限：只改内存中的类属性，污染一次后所有 worker/请求都生效（直到进程重启）。

## 触发条件

- 存在 Ruby 递归合并类污染原语（用户可控 Hash 合并进对象），且能沿 `class`→`superclass`→`subclasses` 走到 `Sinatra::Base`（通常用 `{"class":{"superclass":{"superclass":{"subclasses":{"sample":{...}}}}}}` 的概率路径循环命中）。
- 应用是 Sinatra（或加载了 Sinatra 组件），存在使用 `erb`/`haml` 等模板渲染的既有路由。
- 应用无文件系统只读限制（读文件）/进程有命令执行权限（RCE）。
- 进程常驻，未被立即重启；多 worker 需分别污染。

## 利用步骤

1. 先验证类污染原语：提交 `{"x":1}` 观察对象属性被改写，确认可沿 `class.superclass` 递归。
2. 摸清目标类是 `Sinatra::Base`：`Sinatra::Base.superclass` 为 `Object`，`Object` 的 `subclasses` 里含 `Sinatra::Base`；用 `sample` 循环提交提高命中率。
3. 读文件：提交污染 `public_folder` 为 `/`（或应用目录），再 `GET /etc/passwd`、`GET /<相对路径>` 验证。
4. RCE：先确认有哪些既有模板路由（访问页面看报错/源码），再提交污染 `templates` 覆盖该模板名，内容形如 `<%= \`id\` %>`。
5. 访问对应路由触发渲染；需要回显时把命令输出放进模板输出，盲打时用外带（DNS/HTTP）。
6. 清理：重启进程即恢复，但要假设攻击者已写入文件或建立其他持久化。

## PoC

```json
// 1) 把静态目录改成根目录，配合 GET /<path> 读任意文件
{"class":{"superclass":{"superclass":{"subclasses":{"sample":{"public_folder": "/"}}}}}}

// 2) 覆盖既有模板 hello 的内容，访问 erb :hello 路由即执行
{"class":{"superclass":{"superclass":{"subclasses":{"sample":{"templates": {"hello": "<%= `id` %>"}}}}}}}
```

```ruby
# 脆弱实现骨架（合并进对象，按键写实例变量）
def merge_with(additional)
  recursive_merge(self, additional)
end
# Sinatra 侧对应配置即类方法：
# set :public_folder, File.dirname(__FILE__) + '/static'
# get('/') { erb :hello }
```

## 变体与关联

- 变体（其他 Sinatra 配置项）：`views`、`bind`、`port`、`sessions`、`protection` 等同样是类方法，改 `views` 可切换模板目录读文件；改 `protection` 可关掉 Rack::Protection 的 CSRF/路径检查。
- 变体（框架外）：任何"配置即类方法"的 Ruby 框架（Rails 的部分配置、Grape 的 settings）都有同型落点。
- 变体（回显）：模板里用 `%x{}`/反引号直接输出；无回显时把结果写进可下载目录（污染 `public_folder` 后直接取）。
- 关联：[[code-analysis-vuln-discovery-ruby-recursive-merge-class-pollution]]（原语原理与 `class/superclass/subclasses` 路径构造）、[[web-generic-ssti-ruby-erb-percent-x-command-exec]]（ERB 的 `%x{}` 执行原语）、[[web-python-framework-flask-static-folder-arbitrary-file-read]]（Flask 侧同名落点）。
- 边界：若合并实现过滤 `class`/`superclass`/`subclasses` 键、或只合并进普通 Hash，则本条不成立；若模板引擎开启了严格模式且模板名固定为文件路径，覆盖哈希可能不影响渲染。

## 检测与防御

- 修复：用户数据只合并进普通 Hash 并按字段白名单取值；拒绝含 `class`/`superclass`/`subclasses`/`instance_variable_set` 等反射键的请求。
- 加固：Sinatra 配置在启动时冻结（`freeze`），模板路径使用固定常量而非可写类属性；生产进程最小权限，`public_folder` 不指向应用根之外的目录。
- 检测：请求体出现 `class`/`superclass`/`subclasses`/`public_folder`/`templates` 键；静态路由返回内容与请求扩展名不匹配；进程内出现异常 `sh`/`id` 子进程与模板渲染异常堆栈。
- 审计：搜索 `send(`, `public_send(`, `instance_variable_set`, `class_eval`, `define_method` 的调用点，回溯键名是否外部可控。
