---
id: web-generic-auth-xinhu-logincheck-empty-inheritance-bypass
title: PHP 继承链空方法覆写鉴权绕过：信呼OA ActionNot::logincheck 空实现让 login/api 接口免登录
type: scenario
domain: web
path: web/generic/auth
technique: php-inheritance-empty-logincheck-auth-bypass
tags:
- web
- auth
- php
- xinhu
- oa
- inheritance
- access-control
- unauth
- code-audit
cve: []
severity: high
confidence: high
affected_versions: 信呼OA v2.7.0（原文源码路径 xinhu_utf8_v2.7.0，原文称最新版；未给修复版本）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V248
  verified_at: '2026-11-07T13:17:45+08:00'
  notes: 已对照原文与 13 张图核对：apiAction::initAction 的 =(M=='login|api') 三段鉴权分支、ActionNot::logincheck 空实现（491 行）、Action::initProject→getlogin→logincheck 调用链均与图 6-12 一致；图 13 的 Burp 复现响应 200 OK 且请求 Cookie 数为 0，支持未授权。核实修正：卡内 PoC 路由由 m=task&d=api 改为 d=task&m=login%7Capi（对应 webmain/task/api/loginAction.php）。未验证点：原文 URL 被红段遮盖，未在本机复现。
url: /docs/web/generic/auth/web-generic-auth-xinhu-logincheck-empty-inheritance-bypass/
draft: false
kb_aliases:
- 信呼OA 前台鉴权绕过
- logincheck 空方法
- ActionNot 空实现
- PHP 继承链鉴权绕过
- login/api 模块白名单
- 信呼OA setwxqy 未授权
---

## 一句话结论

信呼OA 的控制器继承链中，`Action` 的真实鉴权方法 `logincheck()` 会调用 `loginnot()`，但中间类 `ActionNot` 用空方法 `protected function logincheck(){}` 覆写了它；`apiAction` 继承 `ActionNot` 后，`Action::initProject() → getlogin() → $this->logincheck()` 动态分派到空实现，鉴权被静默跳过；再叠加 `apiAction::initAction()` 中 `$boss = (M == 'login|api')` 的模块白名单，`login`/`api` 模块下的接口（如 `setwxqyAction`）即可未登录访问。

## 原理

- **控制器初始化链**：路由选择模块文件后 `new` 对应控制器类，触发最顶层 `mainAction::__construct()`，其依次调用 `initMysql()`、`initConstruct()`、`getTheme()`、`initProject()`、`initAction()`；鉴权相关的是 `initProject()` 与 `initAction()`。
- **继承关系**（原文代码）：`loginClassAction`（`webmain/task/api/loginAction.php`）→ `apiAction` → `ActionNot` → `Action` → `mainAction`。
- **initAction 的白名单**：`apiAction` 重写了 `initAction()`，其中 `$boss = (M == 'login|api');` 用于判断当前模块是否属于 login/api 白名单。原文案例的接口满足该条件，`$boss` 为 true，于是三段鉴权分支全部被跳过：
  - `if(!$boss){ ... token invalid / 登录失效 / update ... }`
  - `if(!$this->userrs && !$boss){ ... 用户不存在 ... }`
  - `if(!$boss && $nadminid != $this->adminid){ ... setsession ... }`
- **initProject 的落点**：`loginClassAction` 没有重写 `initProject()`；`apiAction` 没有；`ActionNot` 也没有；于是调用到 `Action::initProject()`，其中执行 `$this->getlogin();`。
- **空 logincheck 的关键**：`Action::getlogin($lx=0)` 在 `$lx==0` 时调用 `$this->logincheck();`。`Action::logincheck()` 原本调用 `$this->loginnot();`（真正的登录校验）；但 `ActionNot`（`class ActionNot extends Action`）用空方法覆写：
  ```php
  protected function logincheck(){}
  ```
  由于 `apiAction extends ActionNot`，`$this` 是 `loginClassAction` 实例，动态分派命中 `ActionNot::logincheck()` 的空实现，而不是 `Action::logincheck()`。结果是没有调用 `loginnot()`，也没有任何鉴权。
- **为什么能利用**：PHP 的方法解析按运行时对象所属类沿继承链向上查找，子类/中间类的同名方法优先；一个“为某些接口准备的空实现”会静默影响整棵子树。只要某个 Action 不重写 `logincheck`/`initProject`/`initAction` 中必要的鉴权逻辑，并且模块名命中 `$boss` 白名单，就可以未登录调用其 action 方法。
- **审计方法**：先定位路由到控制器的加载与 `mainAction::__construct()`，再逐层检查 `initProject`/`initAction`/`logincheck` 是否被重写、重写体是否为空或条件可绕过；重点找“中间类空实现 + 模块白名单字符串比较”的组合。原文的挖掘思路是：选择接口必须满足“到 mainAction 的继承过程中重写了这两个方法、且没有鉴权内容”，`loginAction` 正好满足。

## 触发条件

- 目标为信呼OA v2.7.0（或相同控制器继承结构的版本），存在 `webmain/task/api/loginAction.php` 等 login/api 模块 Action。
- 目标 Action 的继承链中存在 `ActionNot` 这类中间类，用空方法覆写了 `logincheck()`（或 `initProject`/`initAction` 中的鉴权部分）。
- `apiAction::initAction()` 的 `$boss` 白名单条件对目标模块成立（`M == 'login|api'`），从而跳过 token/用户校验。
- 目标 action 方法本身没有额外的权限判断（如角色、对象归属），或额外判断可绕过。
- 攻击者能直接访问对应路由，无需有效 Cookie/Token。

## 利用步骤

1. 获取/审计源码：定位 `webmain/task/api/loginAction.php`，确认类名与继承关系（`loginClassAction extends apiAction`）。
2. 沿继承链向上检查 `initProject()`、`initAction()`、`logincheck()` 的重写情况：
   - `apiAction::initAction()` 中 `$boss` 条件与三段鉴权分支；
   - `ActionNot::logincheck()` 是否为空；
   - `Action::initProject()/getlogin()` 的调用顺序。
3. 选择一个继承链上没有额外鉴权的 action（原文为 `setwxqyAction()`），不带 Cookie 直接请求其路由。
4. 观察响应：若返回业务处理结果/业务错误而非登录跳转/“登录失效”，说明鉴权链被绕过；若返回登录页，检查是否还有其它 `initProject`/`initAction` 重写或全局中间件。
5. 对绕过的 action 继续测试其业务逻辑（原文进一步发现 `base64decode(shouji)` 的 SQL 注入，见关联卡）。
6. 批量枚举 login/api 模块下的 Action 方法，逐个不带 Cookie 请求，寻找同类空实现/白名单组合。
7. 记录请求、响应与继承链证据；在授权范围内验证影响。

## PoC

最小化的类继承结构（按原文代码抽象）：

```php
class mainAction {
    public function __construct() {
        // ...
        $this->initProject();
        $this->initAction();
    }
}

class Action extends mainAction {
    public function initProject() {
        $this->getlogin();
    }
    public function getlogin($lx = 0) {
        // ... 读取 session / 设置当前用户 ...
        if ($lx == 0) $this->logincheck();
    }
    protected function logincheck() {
        $this->loginnot();          // 真正的登录校验
    }
}

class ActionNot extends Action {
    protected function logincheck() {}   // 空实现：静默禁用鉴权
}

class apiAction extends ActionNot {
    public function initAction() {
        $boss = (M == 'login|api');      // 模块白名单
        if (!$boss) { /* token/登录/用户状态校验 */ }
    }
}

class loginClassAction extends apiAction {
    public function setwxqyAction() {
        // 未登录可达的业务逻辑
    }
}
```

不带 Cookie 访问（按信呼路由规则，`webmain/task/api/loginAction.php` 对应 `d=task&m=login|api`；`|` 在 URL 中通常需编码为 `%7C`）：

```http
GET /index.php?d=task&m=login%7Capi&a=setwxqy HTTP/1.1
Host: target
Connection: close
```

若响应为业务 JSON/业务错误（而不是登录页/302 到登录），说明 `ActionNot::logincheck()` 的空实现生效；原文随后在该接口上构造 `shouji` 参数完成 SQL 注入。

说明：原文未给出独立的最小鉴权绕过 PoC，以上是按源码与调用流程图整理的结构化复现；`M` 常量取原始 `m` 路由参数（此处为 `login|api`，与 18575 中 `m=agent|api` 对应 `webmain/task/api/agentAction.php` 的规则一致），实际取值以目标路由为准。未在本机执行。

## 变体与关联

- 变体：其他中间类可能用空方法覆写 `initProject()`/`initAction()`/`checkLogin()`/`auth()`；审计时对所有“空方法体”的鉴权相关方法保持敏感。
- 变体：白名单条件可能是 `M == 'login|api'`、`in_array(M, [...])`、正则或大小写不敏感比较；只要能让业务模块落入白名单，就可能跳过校验。
- 变体：若 `logincheck()` 不是空而是 `return true;`、只记录日志、或仅在特定参数下执行，也同样可绕过。
- 关联：[[web-generic-sqli-xinhu-setwxqy-base64-mobile-getone]]（本鉴权绕过暴露的前台 SQL 注入）、[[web-generic-auth-xinhu-publicsave-arbitrary-table-write]]（同系统另一条越权链，需登录）、[[web-generic-auth-fe-controllerfilter5-excludepage-prefix-bypass]]（过滤器/鉴权前缀绕过）。
- 边界：若目标版本修复了空 `logincheck`、给 action 增加额外权限校验、或在全局中间件统一鉴权，则本链失效；仅绕过登录不等于拥有管理员权限，具体危害取决于被暴露 action 的能力。

## 检测与防御

- 防御：鉴权方法应集中在一处，避免中间类用空方法覆写；将 `logincheck`/`initProject` 设为 `final` 或抽象方法，禁止子类静默覆盖；白名单使用显式映射而非字符串比较。
- 防御：在路由分发前统一做登录/权限中间件，控制器构造函数只做初始化，不承载安全边界；对每个 action 做功能级与对象级授权。
- 检测/审计：静态扫描继承链中空的鉴权方法（`logincheck`/`initProject`/`initAction` 等）、`$boss`/白名单字符串比较、以及未登录可达的 Action；CI 中对所有路由做“无 Cookie 访问”基线测试。
- 检测：同一 IP 未携带会话却大量访问 login/api 模块 action；响应为业务数据而非登录页；结合 WAF/访问日志识别异常路由枚举。
- 响应：发现绕过立即修复空实现/白名单逻辑，审计该时间段内被访问的 action 与数据，评估是否被进一步注入或越权。
