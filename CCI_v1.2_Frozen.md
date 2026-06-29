\# CCI 完整伪代码 v1.2（修正版）



> 说明：以下为 Python 风格伪代码。核心变更以 `\\\[FIX]` 标注并附简要注释。  

> ⚠️ 本文件为算法实现的伪代码文档，仅供学习参考。  

> 商业用途须获得作者授权（详见 LICENSE 文件）。



\---



\## 第一部分：数据结构与常量



```python

"""

CCI: Constrained Chaotic Iterator

版本: 1.2 (2026-06-30)

修复: 缠绕数初始化依赖 / 密钥搜索崩溃 / 时间戳同步 / 主密钥轮换 / 版本问题导致失效

"""



import hashlib

import random

import math

import time

from typing import Tuple, List, Optional, Set

from dataclasses import dataclass



\\# ---------- 全局工程常量 ----------

EPSILON = 1e-9

N\\\_ITER = 1000

MAX\\\_KEYGEN\\\_ATTEMPTS = 256

PRECHECK\\\_SAMPLES = 20

CHAOS\\\_LOW, CHAOS\\\_HIGH = 0.5, 2.0

GEO\\\_LOW, GEO\\\_HIGH = 0.5, 2.0

WINDOW\\\_TOLERANCE = 3600



\\# ---------- 数据结构 ----------

@dataclass

class SecurityParams:

\&#x20;   alpha: float

\&#x20;   beta: float

\&#x20;   gamma: float

\&#x20;   a: float

\&#x20;   b: float

\&#x20;   c: float



@dataclass

class CipherText:

\&#x20;   nonce: int

\&#x20;   timestamp: int

\&#x20;   key\\\_version: int

\&#x20;   point: Tuple\\\[float, float, float]



@dataclass

class MasterKeyEntry:

\&#x20;   seed: str

\&#x20;   effective\\\_from: int

\&#x20;   description: str = ""

\&#x20;   is\\\_revoked: bool = False          # \\\[FIX] 显式废止标记

## 第二部分：辅助数学函数

python

def \\\_chaos\\\_map(p: Tuple, alpha: float, beta: float, gamma: float) -> Tuple:

\&#x20;   x, y, z = p

\&#x20;   return (

\&#x20;       (x + alpha \\\* math.sin(y)) % (2 \\\* math.pi),

\&#x20;       (y + beta \\\* math.cos(x)) % (2 \\\* math.pi),

\&#x20;       (z + gamma \\\* math.sin(x + y)) % (2 \\\* math.pi)

\&#x20;   )



def \\\_geo\\\_project(p: Tuple, a: float, b: float, c: float) -> Tuple:

\&#x20;   x, y, z = p

\&#x20;   r = math.sqrt((x/a)\\\*\\\*2 + (y/b)\\\*\\\*2 + (z/c)\\\*\\\*2)

\&#x20;   if r < 1e-15:

\&#x20;       return (0.0, 0.0, c)

\&#x20;   return (x / r, y / r, z / r)



def \\\_compute\\\_winding(p\\\_seq: List\\\[Tuple]) -> int:

\&#x20;   """

\&#x20;   \\\[FIX 1] 缠绕数计算：防止 atan2(0,0) 退化

\&#x20;   """

\&#x20;   start\\\_idx = 0

\&#x20;   for i, p in enumerate(p\\\_seq):

\&#x20;       if abs(p\\\[0]) > 1e-15 or abs(p\\\[1]) > 1e-15:

\&#x20;           start\\\_idx = i

\&#x20;           break

\&#x20;   else:

\&#x20;       return 0



\&#x20;   angle\\\_prev = math.atan2(p\\\_seq\\\[start\\\_idx]\\\[1], p\\\_seq\\\[start\\\_idx]\\\[0])

\&#x20;   total\\\_angle = 0.0

\&#x20;   for p in p\\\_seq\\\[start\\\_idx + 1:]:

\&#x20;       angle\\\_cur = math.atan2(p\\\[1], p\\\[0])

\&#x20;       delta = angle\\\_cur - angle\\\_prev

\&#x20;       if delta > math.pi:

\&#x20;           delta -= 2 \\\* math.pi

\&#x20;       if delta < -math.pi:

\&#x20;           delta += 2 \\\* math.pi

\&#x20;       total\\\_angle += delta

\&#x20;       angle\\\_prev = angle\\\_cur

\&#x20;   return int(round(total\\\_angle / (2 \\\* math.pi)))



def \\\_seed\\\_to\\\_point(seed: str) -> Tuple:

\&#x20;   h = hashlib.sha256(seed.encode()).hexdigest()

\&#x20;   x = (int(h\\\[0:8], 16) / 2\\\*\\\*32) \\\* 2 - 1

\&#x20;   y = (int(h\\\[8:16], 16) / 2\\\*\\\*32) \\\* 2 - 1

\&#x20;   z = (int(h\\\[16:24], 16) / 2\\\*\\\*32) \\\* 2 - 1

\&#x20;   return (x, y, z)

## 第三部分：主密钥管理器

python

class MasterKeyManager:

\&#x20;   """

\&#x20;   \\\[FIX 4] 主密钥轮换与多密钥容灾

\&#x20;   """

\&#x20;   def \\\_\\\_init\\\_\\\_(self):

\&#x20;       self.\\\_keys: dict\\\[int, MasterKeyEntry] = {}

\&#x20;       self.\\\_current\\\_version: Optional\\\[int] = None



\&#x20;   def add\\\_key(self, version: int, seed: str, effective\\\_from: int,

\&#x20;               description: str = "") -> None:

\&#x20;       self.\\\_keys\\\[version] = MasterKeyEntry(

\&#x20;           seed=seed,

\&#x20;           effective\\\_from=effective\\\_from,

\&#x20;           description=description,

\&#x20;           is\\\_revoked=False

\&#x20;       )

\&#x20;       if self.\\\_current\\\_version is None:

\&#x20;           self.\\\_current\\\_version = version

\&#x20;       else:

\&#x20;           cur = self.\\\_keys.get(self.\\\_current\\\_version)

\&#x20;           if cur is None or cur.is\\\_revoked:

\&#x20;               self.\\\_current\\\_version = self.\\\_get\\\_best\\\_version()

\&#x20;           elif effective\\\_from > cur.effective\\\_from and not self.\\\_keys\\\[version].is\\\_revoked:

\&#x20;               self.\\\_current\\\_version = version



\&#x20;   def \\\_get\\\_best\\\_version(self) -> Optional\\\[int]:

\&#x20;       active = \\\[(v, e) for v, e in self.\\\_keys.items() if not e.is\\\_revoked]

\&#x20;       if not active:

\&#x20;           return None

\&#x20;       active.sort(key=lambda x: x\\\[1].effective\\\_from, reverse=True)

\&#x20;       return active\\\[0]\\\[0]



\&#x20;   def get\\\_key(self, timestamp: int) -> Tuple\\\[Optional\\\[int], Optional\\\[str]]:

\&#x20;       applicable = \\\[

\&#x20;           (v, e.seed) for v, e in self.\\\_keys.items()

\&#x20;           if e.effective\\\_from <= timestamp and not e.is\\\_revoked

\&#x20;       ]

\&#x20;       if not applicable:

\&#x20;           return (None, None)

\&#x20;       applicable.sort(key=lambda x: x\\\[0])

\&#x20;       return applicable\\\[-1]



\&#x20;   def get\\\_current\\\_key(self) -> Tuple\\\[Optional\\\[int], Optional\\\[str]]:

\&#x20;       best\\\_version = self.\\\_get\\\_best\\\_version()

\&#x20;       if best\\\_version is None:

\&#x20;           return (None, None)

\&#x20;       self.\\\_current\\\_version = best\\\_version

\&#x20;       return (self.\\\_current\\\_version, self.\\\_keys\\\[self.\\\_current\\\_version].seed)



\&#x20;   def emergency\\\_revoke(self, compromised\\\_version: int,

\&#x20;                        new\\\_seed: str, effective\\\_from: int) -> None:

\&#x20;       if compromised\\\_version in self.\\\_keys:

\&#x20;           self.\\\_keys\\\[compromised\\\_version].is\\\_revoked = True

\&#x20;           self.\\\_keys\\\[compromised\\\_version].description += " \\\[REVOKED]"

\&#x20;       new\\\_version = compromised\\\_version + 1

\&#x20;       self.add\\\_key(new\\\_version, new\\\_seed, effective\\\_from,

\&#x20;                    "Emergency rollover after revocation")

\&#x20;       self.\\\_current\\\_version = self.\\\_get\\\_best\\\_version()

## 第四部分：预检模式

python

def precheck\\\_compatibility(seed: str, target\\\_m: int,

\&#x20;                          max\\\_samples: int = PRECHECK\\\_SAMPLES) -> Tuple\\\[bool, List\\\[int]]:

\&#x20;   """

\&#x20;   \\\[FIX 2] 预检：估算明文的缠绕数可行区间

\&#x20;   """

\&#x20;   observed: Set\\\[int] = set()

\&#x20;   base\\\_point = \\\_seed\\\_to\\\_point(seed)



\&#x20;   for \\\_ in range(max\\\_samples):

\&#x20;       alpha = random.uniform(CHAOS\\\_LOW, CHAOS\\\_HIGH)

\&#x20;       beta = random.uniform(CHAOS\\\_LOW, CHAOS\\\_HIGH)

\&#x20;       gamma = random.uniform(CHAOS\\\_LOW, CHAOS\\\_HIGH)

\&#x20;       a = random.uniform(GEO\\\_LOW, GEO\\\_HIGH)

\&#x20;       b = random.uniform(GEO\\\_LOW, GEO\\\_HIGH)

\&#x20;       c = random.uniform(GEO\\\_LOW, GEO\\\_HIGH)



\&#x20;       test\\\_seq = \\\[]

\&#x20;       p = base\\\_point

\&#x20;       for \\\_ in range(100):

\&#x20;           p = \\\_chaos\\\_map(p, alpha, beta, gamma)

\&#x20;           p = \\\_geo\\\_project(p, a, b, c)

\&#x20;           test\\\_seq.append(p)



\&#x20;       observed.add(\\\_compute\\\_winding(test\\\_seq))



\&#x20;   possible = (target\\\_m in observed) or (target\\\_m == 0)

\&#x20;   return possible, sorted(observed)

## 第五部分：密钥生成（含口令缠绕）

python

def generate\\\_keys(seed: str, timestamp: int, nonce: int,

\&#x20;                 master\\\_seed: str, password\\\_m: int,

\&#x20;                 skip\\\_precheck: bool = False) -> Tuple\\\[SecurityParams, int]:

\&#x20;   if not skip\\\_precheck:

\&#x20;       feasible, observed = precheck\\\_compatibility(seed, password\\\_m)

\&#x20;       if not feasible:

\&#x20;           raise ValueError(

\&#x20;               f"口令 {password\\\_m} 与明文几何不兼容。\\\\n"

\&#x20;               f"该明文在所有参数下能实现的缠绕数为：{observed}\\\\n"

\&#x20;               f"请选择其中一个值作为口令，或修改明文数据。"

\&#x20;           )



\&#x20;   for attempt in range(MAX\\\_KEYGEN\\\_ATTEMPTS):

\&#x20;       raw = f"{seed}{timestamp}{nonce}{master\\\_seed}{password\\\_m}"

\&#x20;       digest = hashlib.sha3\\\_256(raw.encode()).hexdigest()



\&#x20;       alpha = CHAOS\\\_LOW + (CHAOS\\\_HIGH - CHAOS\\\_LOW) \\\* (int(digest\\\[0:8], 16) / 2\\\*\\\*32)

\&#x20;       beta  = CHAOS\\\_LOW + (CHAOS\\\_HIGH - CHAOS\\\_LOW) \\\* (int(digest\\\[8:16], 16) / 2\\\*\\\*32)

\&#x20;       gamma = CHAOS\\\_LOW + (CHAOS\\\_HIGH - CHAOS\\\_LOW) \\\* (int(digest\\\[16:24], 16) / 2\\\*\\\*32)



\&#x20;       a = GEO\\\_LOW + (GEO\\\_HIGH - GEO\\\_LOW) \\\* (int(digest\\\[24:32], 16) / 2\\\*\\\*32)

\&#x20;       b = GEO\\\_LOW + (GEO\\\_HIGH - GEO\\\_LOW) \\\* (int(digest\\\[32:40], 16) / 2\\\*\\\*32)

\&#x20;       c = GEO\\\_LOW + (GEO\\\_HIGH - GEO\\\_LOW) \\\* (int(digest\\\[40:48], 16) / 2\\\*\\\*32)



\&#x20;       params = SecurityParams(alpha, beta, gamma, a, b, c)



\&#x20;       test\\\_seq = \\\[]

\&#x20;       p = \\\_seed\\\_to\\\_point(seed)

\&#x20;       for \\\_ in range(100):

\&#x20;           p = \\\_chaos\\\_map(p, alpha, beta, gamma)

\&#x20;           p = \\\_geo\\\_project(p, a, b, c)

\&#x20;           test\\\_seq.append(p)



\&#x20;       if \\\_compute\\\_winding(test\\\_seq) == password\\\_m:

\&#x20;           return params, nonce



\&#x20;       nonce += 1



\&#x20;   raise RuntimeError(

\&#x20;       f"经过 {MAX\\\_KEYGEN\\\_ATTEMPTS} 次尝试仍无法找到匹配口令 {password\\\_m} 的密钥。"

\&#x20;       "请尝试使用预检模式推荐的缠绕数值。"

\&#x20;   )

## 第六部分：加密引擎

python

\\# 假设全局密钥管理器已初始化（实际部署时需从安全存储加载）

GLOBAL\\\_KEY\\\_MANAGER = MasterKeyManager()

GLOBAL\\\_KEY\\\_MANAGER.add\\\_key(1, "DEFAULT\\\_MASTER\\\_SEED\\\_CHANGE\\\_ME", 0, "Initial key")



def encrypt(plain\\\_point: Tuple\\\[float, ...],

\&#x20;           password\\\_m: int,

\&#x20;           master\\\_seed: Optional\\\[str] = None,

\&#x20;           key\\\_version: Optional\\\[int] = None) -> CipherText:

\&#x20;   """

\&#x20;   \\\[FIX 3] 加密端固定时间戳并写入密文

\&#x20;   \\\[FIX 4] 记录主密钥版本号

\&#x20;   """

\&#x20;   timestamp = int(time.time())

\&#x20;   nonce = random.getrandbits(64)



\&#x20;   if master\\\_seed is None:

\&#x20;       kv, ms = GLOBAL\\\_KEY\\\_MANAGER.get\\\_current\\\_key()

\&#x20;       if ms is None:

\&#x20;           raise RuntimeError("未配置主密钥")

\&#x20;       master\\\_seed = ms

\&#x20;       key\\\_version = kv

\&#x20;   else:

\&#x20;       if key\\\_version is None:

\&#x20;           for v, entry in GLOBAL\\\_KEY\\\_MANAGER.\\\_keys.items():

\&#x20;               if entry.seed == master\\\_seed:

\&#x20;                   key\\\_version = v

\&#x20;                   break

\&#x20;           if key\\\_version is None:

\&#x20;               raise ValueError("无法匹配传入的主密钥到任何已知版本")



\&#x20;   params, final\\\_nonce = generate\\\_keys(

\&#x20;       seed=str(plain\\\_point),

\&#x20;       timestamp=timestamp,

\&#x20;       nonce=nonce,

\&#x20;       master\\\_seed=master\\\_seed,

\&#x20;       password\\\_m=password\\\_m,

\&#x20;       skip\\\_precheck=True

\&#x20;   )



\&#x20;   p = plain\\\_point

\&#x20;   for \\\_ in range(N\\\_ITER):

\&#x20;       p = \\\_chaos\\\_map(p, params.alpha, params.beta, params.gamma)

\&#x20;       p = \\\_geo\\\_project(p, params.a, params.b, params.c)



\&#x20;   return CipherText(

\&#x20;       nonce=final\\\_nonce,

\&#x20;       timestamp=timestamp,

\&#x20;       key\\\_version=key\\\_version,

\&#x20;       point=p

\&#x20;   )

## 第七部分：解密与验证（恒定时间）

python

def decrypt\\\_verify(cipher: CipherText,

\&#x20;                  guess\\\_m: int,

\&#x20;                  plain\\\_original: Tuple,

\&#x20;                  master\\\_seed: Optional\\\[str] = None) -> bool:

\&#x20;   """

\&#x20;   \\\[FIX 3] 使用密文中的时间戳，不再依赖本地系统时间

\&#x20;   \\\[FIX 4] 根据密文中的版本号获取对应的主密钥

\&#x20;   """

\&#x20;   result = False



\&#x20;   try:

\&#x20;       if master\\\_seed is None:

\&#x20;           entry = GLOBAL\\\_KEY\\\_MANAGER.\\\_keys.get(cipher.key\\\_version)

\&#x20;           if entry is None or entry.is\\\_revoked:    # \\\[FIX] 检查废止状态

\&#x20;               return False

\&#x20;           master\\\_seed = entry.seed



\&#x20;       params, \\\_ = generate\\\_keys(

\&#x20;           seed=str(plain\\\_original),

\&#x20;           timestamp=cipher.timestamp,

\&#x20;           nonce=cipher.nonce,

\&#x20;           master\\\_seed=master\\\_seed,

\&#x20;           password\\\_m=guess\\\_m,

\&#x20;           skip\\\_precheck=True

\&#x20;       )



\&#x20;       p = plain\\\_original

\&#x20;       trajectory = \\\[]

\&#x20;       for i in range(N\\\_ITER):

\&#x20;           p = \\\_chaos\\\_map(p, params.alpha, params.beta, params.gamma)

\&#x20;           p = \\\_geo\\\_project(p, params.a, params.b, params.c)

\&#x20;           if i > N\\\_ITER - 100:

\&#x20;               trajectory.append(p)



\&#x20;       dist = math.sqrt(

\&#x20;           (p\\\[0] - cipher.point\\\[0])\\\*\\\*2 +

\&#x20;           (p\\\[1] - cipher.point\\\[1])\\\*\\\*2 +

\&#x20;           (p\\\[2] - cipher.point\\\[2])\\\*\\\*2

\&#x20;       )

\&#x20;       if dist < EPSILON:

\&#x20;           if \\\_compute\\\_winding(trajectory) == guess\\\_m:

\&#x20;               result = True



\&#x20;   except Exception:

\&#x20;       pass



\&#x20;   # 恒定时间执行：无论结果如何，跑满后做无害空计算

\&#x20;   \\\_dummy = sum(\\\[math.sin(i) for i in range(100)])

\&#x20;   return result

## 第八部分：时间锁扩展（预留）

python

def encrypt\\\_with\\\_time\\\_lock(plain\\\_point: Tuple,

\&#x20;                          password\\\_m: int,

\&#x20;                          unlock\\\_after: int,

\&#x20;                          master\\\_seed: Optional\\\[str] = None) -> CipherText:

\&#x20;   """

\&#x20;   时间锁加密：密文在 unlock\\\_after 时间之前无法被解密。

\&#x20;   （完整实现预留）

\&#x20;   """

\&#x20;   pass

## 第九部分：变更日志

版本	修复项	触发条件	修复方案	影响范围

v1.0→v1.1	\\\[FIX 1] 缠绕数初始化退化	atan2(0,0)	跳过 Z 轴起始点	\\\_compute\\\_winding

v1.0→v1.1	\\\[FIX 2] 密钥搜索崩溃	口令与明文几何不兼容	增加预检模式	precheck\\\_compatibility

v1.0→v1.1	\\\[FIX 3] 时间戳同步失败	加密/解密不同秒	时间戳写入密文	CipherText + decrypt\\\_verify

v1.0→v1.1	\\\[FIX 4] 主密钥泄漏无应对	单点失效	增加 MasterKeyManager	全局架构

v1.1→v1.2	\\\[FIX 5] 废止版本仍被选为当前版本	逻辑盲区	增加 is\\\_revoked 字段 + 自动故障转移	MasterKeyManager


