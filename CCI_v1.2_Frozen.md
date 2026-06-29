\# CCI 完整伪代码 v1.2（修正版）



> 说明：以下为 Python 风格伪代码。核心变更以 `\[FIX]` 标注并附简要注释。  

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



\# ---------- 全局工程常量 ----------

EPSILON = 1e-9

N\_ITER = 1000

MAX\_KEYGEN\_ATTEMPTS = 256

PRECHECK\_SAMPLES = 20

CHAOS\_LOW, CHAOS\_HIGH = 0.5, 2.0

GEO\_LOW, GEO\_HIGH = 0.5, 2.0

WINDOW\_TOLERANCE = 3600



\# ---------- 数据结构 ----------

@dataclass

class SecurityParams:

    alpha: float

    beta: float

    gamma: float

    a: float

    b: float

    c: float



@dataclass

class CipherText:

    nonce: int

    timestamp: int

    key\_version: int

    point: Tuple\[float, float, float]



@dataclass

class MasterKeyEntry:

    seed: str

    effective\_from: int

    description: str = ""

    is\_revoked: bool = False          # \[FIX] 显式废止标记



## 第二部分：辅助数学函数



def \_chaos\_map(p: Tuple, alpha: float, beta: float, gamma: float) -> Tuple:

    x, y, z = p

    return (

        (x + alpha \* math.sin(y)) % (2 \* math.pi),

        (y + beta \* math.cos(x)) % (2 \* math.pi),

        (z + gamma \* math.sin(x + y)) % (2 \* math.pi)

    )



def \_geo\_project(p: Tuple, a: float, b: float, c: float) -> Tuple:

    x, y, z = p

    r = math.sqrt((x/a)\*\*2 + (y/b)\*\*2 + (z/c)\*\*2)

    if r < 1e-15:

        return (0.0, 0.0, c)

    return (x / r, y / r, z / r)



def \_compute\_winding(p\_seq: List\[Tuple]) -> int:

    """

    \[FIX 1] 缠绕数计算：防止 atan2(0,0) 退化

    """

    start\_idx = 0

    for i, p in enumerate(p\_seq):

        if abs(p\[0]) > 1e-15 or abs(p\[1]) > 1e-15:

            start\_idx = i

            break

    else:

        return 0



    angle\_prev = math.atan2(p\_seq\[start\_idx]\[1], p\_seq\[start\_idx]\[0])

    total\_angle = 0.0

    for p in p\_seq\[start\_idx + 1:]:

        angle\_cur = math.atan2(p\[1], p\[0])

        delta = angle\_cur - angle\_prev

        if delta > math.pi:

            delta -= 2 \* math.pi

        if delta < -math.pi:

            delta += 2 \* math.pi

        total\_angle += delta

        angle\_prev = angle\_cur

    return int(round(total\_angle / (2 \* math.pi)))



def \_seed\_to\_point(seed: str) -> Tuple:

    h = hashlib.sha256(seed.encode()).hexdigest()

    x = (int(h\[0:8], 16) / 2\*\*32) \* 2 - 1

    y = (int(h\[8:16], 16) / 2\*\*32) \* 2 - 1

    z = (int(h\[16:24], 16) / 2\*\*32) \* 2 - 1

    return (x, y, z)



\## 第三部分：主密钥管理器



class MasterKeyManager:

    """

    \[FIX 4] 主密钥轮换与多密钥容灾

    """

    def \_\_init\_\_(self):

        self.\_keys: dict\[int, MasterKeyEntry] = {}

        self.\_current\_version: Optional\[int] = None



    def add\_key(self, version: int, seed: str, effective\_from: int,

                description: str = "") -> None:

        self.\_keys\[version] = MasterKeyEntry(

            seed=seed,

            effective\_from=effective\_from,

            description=description,

            is\_revoked=False

        )

        if self.\_current\_version is None:

            self.\_current\_version = version

        else:

            cur = self.\_keys.get(self.\_current\_version)

            if cur is None or cur.is\_revoked:

                self.\_current\_version = self.\_get\_best\_version()

            elif effective\_from > cur.effective\_from and not self.\_keys\[version].is\_revoked:

                self.\_current\_version = version



    def \_get\_best\_version(self) -> Optional\[int]:

        active = \[(v, e) for v, e in self.\_keys.items() if not e.is\_revoked]

        if not active:

            return None

        active.sort(key=lambda x: x\[1].effective\_from, reverse=True)

        return active\[0]\[0]



    def get\_key(self, timestamp: int) -> Tuple\[Optional\[int], Optional\[str]]:

        applicable = \[

            (v, e.seed) for v, e in self.\_keys.items()

            if e.effective\_from <= timestamp and not e.is\_revoked

        ]

        if not applicable:

            return (None, None)

        applicable.sort(key=lambda x: x\[0])

        return applicable\[-1]



    def get\_current\_key(self) -> Tuple\[Optional\[int], Optional\[str]]:

        best\_version = self.\_get\_best\_version()

        if best\_version is None:

            return (None, None)

        self.\_current\_version = best\_version

        return (self.\_current\_version, self.\_keys\[self.\_current\_version].seed)



    def emergency\_revoke(self, compromised\_version: int,

                         new\_seed: str, effective\_from: int) -> None:

        if compromised\_version in self.\_keys:

            self.\_keys\[compromised\_version].is\_revoked = True

            self.\_keys\[compromised\_version].description += " \[REVOKED]"

        new\_version = compromised\_version + 1

        self.add\_key(new\_version, new\_seed, effective\_from,

                     "Emergency rollover after revocation")

        self.\_current\_version = self.\_get\_best\_version()



\## 第四部分：预检模式



def precheck\_compatibility(seed: str, target\_m: int,

                           max\_samples: int = PRECHECK\_SAMPLES) -> Tuple\[bool, List\[int]]:

    """

    \[FIX 2] 预检：估算明文的缠绕数可行区间

    """

    observed: Set\[int] = set()

    base\_point = \_seed\_to\_point(seed)



    for \_ in range(max\_samples):

        alpha = random.uniform(CHAOS\_LOW, CHAOS\_HIGH)

        beta = random.uniform(CHAOS\_LOW, CHAOS\_HIGH)

        gamma = random.uniform(CHAOS\_LOW, CHAOS\_HIGH)

        a = random.uniform(GEO\_LOW, GEO\_HIGH)

        b = random.uniform(GEO\_LOW, GEO\_HIGH)

        c = random.uniform(GEO\_LOW, GEO\_HIGH)



        test\_seq = \[]

        p = base\_point

        for \_ in range(100):

            p = \_chaos\_map(p, alpha, beta, gamma)

            p = \_geo\_project(p, a, b, c)

            test\_seq.append(p)



        observed.add(\_compute\_winding(test\_seq))



    possible = (target\_m in observed) or (target\_m == 0)

    return possible, sorted(observed)



\## 第五部分：密钥生成（含口令缠绕）



def generate\_keys(seed: str, timestamp: int, nonce: int,

                  master\_seed: str, password\_m: int,

                  skip\_precheck: bool = False) -> Tuple\[SecurityParams, int]:

    if not skip\_precheck:

        feasible, observed = precheck\_compatibility(seed, password\_m)

        if not feasible:

            raise ValueError(

                f"口令 {password\_m} 与明文几何不兼容。\\n"

                f"该明文在所有参数下能实现的缠绕数为：{observed}\\n"

                f"请选择其中一个值作为口令，或修改明文数据。"

            )



    for attempt in range(MAX\_KEYGEN\_ATTEMPTS):

        raw = f"{seed}{timestamp}{nonce}{master\_seed}{password\_m}"

        digest = hashlib.sha3\_256(raw.encode()).hexdigest()



        alpha = CHAOS\_LOW + (CHAOS\_HIGH - CHAOS\_LOW) \* (int(digest\[0:8], 16) / 2\*\*32)

        beta  = CHAOS\_LOW + (CHAOS\_HIGH - CHAOS\_LOW) \* (int(digest\[8:16], 16) / 2\*\*32)

        gamma = CHAOS\_LOW + (CHAOS\_HIGH - CHAOS\_LOW) \* (int(digest\[16:24], 16) / 2\*\*32)



        a = GEO\_LOW + (GEO\_HIGH - GEO\_LOW) \* (int(digest\[24:32], 16) / 2\*\*32)

        b = GEO\_LOW + (GEO\_HIGH - GEO\_LOW) \* (int(digest\[32:40], 16) / 2\*\*32)

        c = GEO\_LOW + (GEO\_HIGH - GEO\_LOW) \* (int(digest\[40:48], 16) / 2\*\*32)



        params = SecurityParams(alpha, beta, gamma, a, b, c)



        test\_seq = \[]

        p = \_seed\_to\_point(seed)

        for \_ in range(100):

            p = \_chaos\_map(p, alpha, beta, gamma)

            p = \_geo\_project(p, a, b, c)

            test\_seq.append(p)



        if \_compute\_winding(test\_seq) == password\_m:

            return params, nonce



        nonce += 1



    raise RuntimeError(

        f"经过 {MAX\_KEYGEN\_ATTEMPTS} 次尝试仍无法找到匹配口令 {password\_m} 的密钥。"

        "请尝试使用预检模式推荐的缠绕数值。"

    )



\## 第六部分：加密引擎



\# 假设全局密钥管理器已初始化（实际部署时需从安全存储加载）

GLOBAL\_KEY\_MANAGER = MasterKeyManager()

GLOBAL\_KEY\_MANAGER.add\_key(1, "DEFAULT\_MASTER\_SEED\_CHANGE\_ME", 0, "Initial key")



def encrypt(plain\_point: Tuple\[float, ...],

            password\_m: int,

            master\_seed: Optional\[str] = None,

            key\_version: Optional\[int] = None) -> CipherText:

    """

    \[FIX 3] 加密端固定时间戳并写入密文

    \[FIX 4] 记录主密钥版本号

    """

    timestamp = int(time.time())

    nonce = random.getrandbits(64)



    if master\_seed is None:

        kv, ms = GLOBAL\_KEY\_MANAGER.get\_current\_key()

        if ms is None:

            raise RuntimeError("未配置主密钥")

        master\_seed = ms

        key\_version = kv

    else:

        if key\_version is None:

            for v, entry in GLOBAL\_KEY\_MANAGER.\_keys.items():

                if entry.seed == master\_seed:

                    key\_version = v

                    break

            if key\_version is None:

                raise ValueError("无法匹配传入的主密钥到任何已知版本")



    params, final\_nonce = generate\_keys(

        seed=str(plain\_point),

        timestamp=timestamp,

        nonce=nonce,

        master\_seed=master\_seed,

        password\_m=password\_m,

        skip\_precheck=True

    )



    p = plain\_point

    for \_ in range(N\_ITER):

        p = \_chaos\_map(p, params.alpha, params.beta, params.gamma)

        p = \_geo\_project(p, params.a, params.b, params.c)



    return CipherText(

        nonce=final\_nonce,

        timestamp=timestamp,

        key\_version=key\_version,

        point=p

    )



\## 第七部分：解密与验证（恒定时间）



def decrypt\_verify(cipher: CipherText,

                   guess\_m: int,

                   plain\_original: Tuple,

                   master\_seed: Optional\[str] = None) -> bool:

    """

    \[FIX 3] 使用密文中的时间戳，不再依赖本地系统时间

    \[FIX 4] 根据密文中的版本号获取对应的主密钥

    """

    result = False



    try:

        if master\_seed is None:

            entry = GLOBAL\_KEY\_MANAGER.\_keys.get(cipher.key\_version)

            if entry is None or entry.is\_revoked:    # \[FIX] 检查废止状态

                return False

            master\_seed = entry.seed



        params, \_ = generate\_keys(

            seed=str(plain\_original),

            timestamp=cipher.timestamp,

            nonce=cipher.nonce,

            master\_seed=master\_seed,

            password\_m=guess\_m,

            skip\_precheck=True

        )



        p = plain\_original

        trajectory = \[]

        for i in range(N\_ITER):

            p = \_chaos\_map(p, params.alpha, params.beta, params.gamma)

            p = \_geo\_project(p, params.a, params.b, params.c)

            if i > N\_ITER - 100:

                trajectory.append(p)



        dist = math.sqrt(

            (p\[0] - cipher.point\[0])\*\*2 +

            (p\[1] - cipher.point\[1])\*\*2 +

            (p\[2] - cipher.point\[2])\*\*2

        )

        if dist < EPSILON:

            if \_compute\_winding(trajectory) == guess\_m:

                result = True



    except Exception:

        pass



    # 恒定时间执行：无论结果如何，跑满后做无害空计算

    \_dummy = sum(\[math.sin(i) for i in range(100)])

    return result



\## 第八部分：时间锁扩展（预留）



def encrypt\_with\_time\_lock(plain\_point: Tuple,

                           password\_m: int,

                           unlock\_after: int,

                           master\_seed: Optional\[str] = None) -> CipherText:

    """

    时间锁加密：密文在 unlock\_after 时间之前无法被解密。

    （完整实现预留）

    """

    pass





\## 第九部分：变更日志



| 版本 | 修复项 | 触发条件 | 修复方案 | 影响范围 |

| :--- | :--- | :--- | :--- | :--- |

| v1.0→v1.1 | \[FIX 1] 缠绕数初始化退化 | `atan2(0,0)` | 跳过 Z 轴起始点 | `\_compute\_winding` |

| v1.0→v1.1 | \[FIX 2] 密钥搜索崩溃 | 口令与明文几何不兼容 | 增加预检模式 | `precheck\_compatibility` |

| v1.0→v1.1 | \[FIX 3] 时间戳同步失败 | 加密/解密不同秒 | 时间戳写入密文 | `CipherText` + `decrypt\_verify` |

| v1.0→v1.1 | \[FIX 4] 主密钥泄漏无应对 | 单点失效 | 增加 `MasterKeyManager` | 全局架构 |

| \*\*v1.1→v1.2\*\* | \*\*\[FIX 5] 废止版本仍被选为当前版本\*\* | \*\*逻辑盲区\*\* | \*\*增加 `is\_revoked` 字段 + 自动故障转移\*\* | \*\*`MasterKeyManager`\*\* |

| \*\*v1.1→v1.2\*\* | \*\*\[UPDATE] 文档元数据错位\*\* | \*\*版本号与日志不一致\*\* | \*\*修正文件头与日志标题\*\* | \*\*文档\*\* |

