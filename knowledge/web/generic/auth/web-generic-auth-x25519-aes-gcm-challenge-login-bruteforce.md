---
id: web-generic-auth-x25519-aes-gcm-challenge-login-bruteforce
title: 前端 x25519+AES-GCM 挑战应答登录加密复刻：execjs 加载原 JS，每轮取新 challenge 自动化口令爆破
type: scenario
domain: web
path: web/generic/auth
technique: x25519-aes-gcm-challenge-response-login-bruteforce
aliases:
- x25519 登录加密爆破
- exchange_key challenge 登录逆向
- AES-GCM 口令密文伪造
- jwes.js encryptPassword
- execjs 复刻登录加密
- 挑战应答前端加密
tags:
- auth
- login
- brute-force
- x25519
- aes-gcm
- node-forge
- execjs
- javascript
- frontend-encryption
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V492
  verified_at: '2026-11-10T23:48:30+08:00'
  notes: 已对照原文与8张图片核对：start/finish 两段式、x25519 临时会话+node-forge AES-GCM(12字节IV,128bit tag)、${challenge}.${password} 明文、execjs 复刻与每轮取新 challenge 均与截图代码一致；原文无组件版本，已--clear。dedup 与 hybrid-rsa-aes 卡为 related 非同链，force 理由（协议/PoC/执行方式不同）成立。未验证点：本机未复现爆破；原文未展示命中结果。
---

## 一句话结论

登录接口先由 `start` 接口下发一次性 `challenge` 与会话级 `exchange_key`，前端用 x25519 临时密钥协商出会话密钥、以 AES-GCM 加密 `${challenge}.${password}` 后提交 `finish`；加密逻辑全部在公开 JS 中，攻击者用 execjs 加载原 JS、每轮实时取新 challenge 并在本地生成密文，即可把"前端加密登录"降级为普通口令爆破。

## 原理

- 两段式登录：点击登录 → `doStart()` 发 `GET api/source/<id>/start?login_name=<用户名>`，响应里取 `challenge` 与 `exchange_key`；无验证码时进入 `passwordLogin(curItem, challenge, exchange_key)`。
- `passwordLogin` 调 `encryptPassword(exchange_key, challenge, password)`，把返回值放进 `password` 字段 POST `api/source/<id>/finish`，与 `login_name` 一起提交。
- `encryptPassword(passwordKey, challenge, password)` 的流程：
  1. `startEphemeralSession(passwordKey)`：生成 x25519 临时密钥对，与服务器下发的 `exchange_key`（公钥）做 ECDH，派生 `masterKey`，返回客户端临时公钥。
  2. `packedAesEncrypt(masterKey, `${challenge}.${password}`)`：node-forge 的 AES-GCM，随机 12 字节 IV、128 bit tag，输出 `urlsafe_b64(iv).urlsafe_b64(ciphertext).urlsafe_b64(tag)`。
  3. 最终返回 `客户端临时公钥.密文三元组`。
- 为什么可复刻：`exchange_key` 对同一用户/会话保持稳定，`challenge` 每次由 `start` 实时下发；密钥协商与加密算法完全在客户端 JS 里，服务端只校验密文格式与解密后的口令。攻击者拿到公开 JS 后，可以在本地对任意候选口令生成服务端能解开的合法密文。
- challenge 的"实时性"只要求每次尝试先取一次新挑战，属于多一次 GET 的成本，不构成防爆破；前端加密只防明文抓包和简单重放，不增加任何认证强度。真正的门槛只剩服务端是否做速率限制、锁定与验证码。

## 触发条件

- 登录页加载包含 x25519/AES-GCM 实现的 JS（如 `jwes.js` + `x25519.js`，依赖 node-forge），加密函数可被静态提取。
- `start` 接口未鉴权，按 `login_name` 返回 `challenge`/`exchange_key`（用户名已知或可从错误码枚举）。
- `finish` 接受 `login_name` 与密文 `password`，服务端解密后校验口令。
- 登录接口缺乏有效速率限制、账号锁定、验证码或设备风控（本案例走的是无验证码分支）。

## 利用步骤

1. DevTools Network 提交一次登录，打开请求的 Initiator 调用栈：`FinishLogin → doStart → passwordLogin → encryptPassword`，据此定位 `@/util/jwes` 模块。
2. 抓 `start` 请求与响应，确认 `challenge`、`exchange_key` 字段名和用户名字段（`login_name`）。
3. 保存 `jwes.js`、`x25519.js`；`npm install node-forge`；处理 Node 运行环境差异：把 `window.crypto` 取随机数的函数改为 `globalThis.crypto.getRandomValues`（或 Node `crypto.randomBytes`），合并 import、去掉 export。
4. 用 Python `execjs`（`EXECJS_RUNTIME=NodeJS`，`cwd` 指向 `node_modules`）调用 `encryptPassword(exchange_key, challenge, candidate)`。
5. 每次尝试前 GET `start` 取新 `challenge`（`exchange_key` 可复用），本地生成密文后 POST `finish`；按响应 `status`/`code` 判断成功，遇到 `UNKNOWN_ACCOUNT` 停止该用户名的枚举。
6. 命中后保存返回的会话凭据。

## PoC

原文给出了完整脚本结构，这里最小化重写（目标/密钥占位，未执行）：

```python
import json, os, execjs, requests
os.environ["EXECJS_RUNTIME"] = "NodeJS"

js = open("jwes.js", encoding="utf-8").read()
base = "http://target"

def enc(exchange_key, challenge, password):
    return execjs.compile(js, cwd="node_modules").call(
        "encryptPassword", exchange_key, challenge, password)

def start(user):
    d = requests.get(f"{base}/api/source/<id>/start",
                     params={"login_name": user}).json()["data"]
    return d["challenge"], d["exchange_key"]

for pw in open("passwd.txt", encoding="utf-8"):
    pw = pw.strip()
    if not pw:
        continue
    challenge, exchange_key = start("admin")   # 每轮刷新 challenge
    body = {"login_name": "admin", "password": enc(exchange_key, challenge, pw)}
    resp = requests.post(f"{base}/api/source/<id>/finish", json=body).json()
    if resp.get("status") != "error":
        print("hit:", pw, resp); break
    if resp.get("code") == "UNKNOWN_ACCOUNT":
        break
```

说明：`exchange_key` 来自 `start` 响应；原文脚本把 challenge 的获取封装为每次加密前请求，`UNKNOWN_ACCOUNT` 用于识别用户名不存在。原文未展示最终命中结果，本卡未复现。

## 变体与关联

- [[web-generic-auth-hybrid-rsa-aes-login-bruteforce]]：同为"前端加密登录复刻 + 自动化口令爆破"，但那张是硬编码 RSA 公钥包裹随机 AES key、单次 POST，可在 Python 内直接重写算法；本卡是 x25519 临时密钥协商 + AES-GCM + 每轮服务端 challenge，必须执行原 JS（execjs/node-forge），协议与 PoC 均不同。
- [[web-generic-auth-cas-aes-cbc-login-encryption-reverse]]、[[web-generic-auth-bastion-frontend-3des-login-forgery]]：其它单层前端登录加密逆向案例。
- [[code-analysis-reverse-frontend-request-response-encryption-automation]]：通用的断点定位 → 扣 JS → PyExecJS 自动化流程。
- [[code-analysis-reverse-obfuscation-js-sign-execjs-dependency-patch]]：execjs 运行原 JS 时的依赖/环境补齐思路（本卡的 `window` 缺失同类问题）。
- 变体：不扣 JS，直接用 Playwright/Selenium 打开登录页调用页面自身的 `encryptPassword` 生成密文；`exchange_key` 若按会话轮换则每轮重新 `start`；有验证码时需先处理验证码分支。

## 检测与防御

- 速率限制：按账号 + IP + 设备指纹限制 `start`/`finish` 频率、失败计数、指数退避与临时锁定；`start` 接口也应做频率控制，避免被当作 challenge 生成器批量调用。
- 挑战绑定：challenge 单次有效、短 TTL，并与客户端会话/指纹绑定；但不要把它当作认证强度——客户端加密可被完整复刻。
- 检测特征：同一 IP/用户名在短时间内大量"先 start 再 finish"的成对请求；finish 的密文结构（IV/密文/tag 长度）高度一致；失败响应高度规律、无验证码介入。
- 防御：强口令策略、MFA、验证码与设备风控；成功/失败响应尽量一致，避免通过错误码枚举用户名；HTTPS 保证传输安全，而不是依赖前端加密。
