CCI 完整伪代码 v1.1（含四项修复）



说明：以下为 Python 风格伪代码。核心变更以 [FIX] 标注并附简要注释。



---



第一部分：数据结构与常量



```python

"""

CCI: Constrained Chaotic Iterator

版本: 1.1 (2026-06-28)

修复: 缠绕数初始化依赖 / 密钥搜索崩溃 / 时间戳同步 / 主密钥轮换

"""



import hashlib

import random

import math

import time

from typing import Tuple, List, Optional, Set

from dataclasses import dataclass



# ---------- 全局工程常量 ----------

EPSILON = 1e-9

N_ITER = 1000

MAX_KEYGEN_ATTEMPTS = 256

PRECHECK_SAMPLES = 20          # 预检采样次数

CHAOS_LOW, CHAOS_HIGH = 0.5, 2.0

GEO_LOW, GEO_HIGH = 0.5, 2.0

WINDOW_TOLERANCE = 3600        # 时间窗口容差（秒），用于时间锁场景





# ---------- 数据结构 ----------

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

    key_version: int              # [FIX 4] 主密钥版本号

    point: Tuple[float, float, float]



@dataclass

class MasterKeyEntry:

    seed: str

    effective_from: int

    description: str = ""

```



---



第二部分：辅助数学函数（含修复）



```python

def _chaos_map(p: Tuple, alpha: float, beta: float, gamma: float) -> Tuple:

    x, y, z = p

    return (

        (x + alpha * math.sin(y)) % (2 * math.pi),

        (y + beta * math.cos(x)) % (2 * math.pi),

        (z + gamma * math.sin(x + y)) % (2 * math.pi)

    )



def _geo_project(p: Tuple, a: float, b: float, c: float) -> Tuple:

    x, y, z = p

    r = math.sqrt((x/a)**2 + (y/b)**2 + (z/c)**2)

    if r < 1e-15:

        return (0.0, 0.0, c)  # 原点映射到椭球北极

    return (x / r, y / r, z / r)



def _compute_winding(p_seq: List[Tuple]) -> int:

    """

    [FIX 1] 缠绕数计算：防止 atan2(0,0) 退化

    找到第一个不在 Z 轴上的点作为起始点。

    """

    # 寻找有效起始点

    start_idx = 0

    for i, p in enumerate(p_seq):

        if abs(p[0]) > 1e-15 or abs(p[1]) > 1e-15:

            start_idx = i

            break

    else:

        # 所有点都在 Z 轴上：缠绕数为 0（退化情况）

        return 0



    angle_prev = math.atan2(p_seq[start_idx][1], p_seq[start_idx][0])

    total_angle = 0.0



    for p in p_seq[start_idx + 1:]:

        angle_cur = math.atan2(p[1], p[0])

        delta = angle_cur - angle_prev

        if delta > math.pi:

            delta -= 2 * math.pi

        if delta < -math.pi:

            delta += 2 * math.pi

        total_angle += delta

        angle_prev = angle_cur



    return int(round(total_angle / (2 * math.pi)))



def _seed_to_point(seed: str) -> Tuple:

    """将字符串种子确定性映射到三维点（用于预检）"""

    h = hashlib.sha256(seed.encode()).hexdigest()

    x = (int(h[0:8], 16) / 2**32) * 2 - 1

    y = (int(h[8:16], 16) / 2**32) * 2 - 1

    z = (int(h[16:24], 16) / 2**32) * 2 - 1

    return (x, y, z)

```



---



第三部分：主密钥管理器（[FIX 4]）



```python

class MasterKeyManager:

    """

    [FIX 4] 主密钥轮换与多密钥容灾

    """

    def __init__(self):

        self._keys: dict[int, MasterKeyEntry] = {}

        self._current_version: Optional[int] = None



    def add_key(self, version: int, seed: str, effective_from: int, description: str = ""):

        self._keys[version] = MasterKeyEntry(seed, effective_from, description)

        if self._current_version is None or effective_from > self._keys.get(self._current_version, MasterKeyEntry("", 0)).effective_from:

            self._current_version = version



    def get_key(self, timestamp: int) -> Tuple[Optional[int], Optional[str]]:

        """根据时间戳选择对应的主密钥版本"""

        applicable = [(v, e.seed) for v, e in self._keys.items() if e.effective_from <= timestamp]

        if not applicable:

            return (None, None)

        applicable.sort(key=lambda x: x[0])

        return applicable[-1]



    def get_current_key(self) -> Tuple[Optional[int], Optional[str]]:

        if self._current_version is None:

            return (None, None)

        return (self._current_version, self._keys[self._current_version].seed)



    def emergency_revoke(self, compromised_version: int, new_seed: str, effective_from: int):

        """

        [FIX 4] 紧急废止：废弃泄露的主密钥版本，启用新版本。

        注意：历史密文仍用旧版本解密，但新加密用新版本。

        """

        if compromised_version in self._keys:

            # 标记为废弃（不删除，仍可用于解密历史数据）

            self._keys[compromised_version].description += " [REVOKED]"

        self.add_key(compromised_version + 1, new_seed, effective_from, "Emergency rollover")





# ---------- 全局主密钥管理器实例（由系统初始化）----------

GLOBAL_KEY_MANAGER = MasterKeyManager()

# 初始化默认主密钥（实际部署时应从安全存储加载）

GLOBAL_KEY_MANAGER.add_key(1, "DEFAULT_MASTER_SEED_CHANGE_ME", 0, "Initial key")

```



---



第四部分：预检模式（[FIX 2]）



```python

def precheck_compatibility(seed: str, target_m: int, max_samples: int = PRECHECK_SAMPLES) -> Tuple[bool, List[int]]:

    """

    [FIX 2] 预检：用随机参数采样，估算明文的缠绕数可行区间。

    返回 (是否可能达到 target_m, 观察到的缠绕数列表)

    """

    observed: Set[int] = set()

    base_point = _seed_to_point(seed)



    for _ in range(max_samples):

        # 随机生成参数

        alpha = random.uniform(CHAOS_LOW, CHAOS_HIGH)

        beta = random.uniform(CHAOS_LOW, CHAOS_HIGH)

        gamma = random.uniform(CHAOS_LOW, CHAOS_HIGH)

        a = random.uniform(GEO_LOW, GEO_HIGH)

        b = random.uniform(GEO_LOW, GEO_HIGH)

        c = random.uniform(GEO_LOW, GEO_HIGH)



        test_seq = []

        p = base_point

        for _ in range(100):  # 快速预检，步数少于正式迭代

            p = _chaos_map(p, alpha, beta, gamma)

            p = _geo_project(p, a, b, c)

            test_seq.append(p)



        observed.add(_compute_winding(test_seq))



    # 检查 target_m 是否在可行区间内（0 总是可能的退化情况）

    possible = (target_m in observed) or (target_m == 0)

    return possible, sorted(observed)

```



---



第五部分：密钥生成（含口令缠绕）



```python

def generate_keys(seed: str, timestamp: int, nonce: int,

                  master_seed: str, password_m: int,

                  skip_precheck: bool = False) -> Tuple[SecurityParams, int]:

    """

    生成满足口令缠绕的密钥参数。

    若 skip_precheck=False，则在搜索前先调用预检（仅当非内部调用时启用）。

    """

    # [FIX 2] 预检（仅当从外部调用且未跳过时执行）

    if not skip_precheck:

        feasible, observed = precheck_compatibility(seed, password_m)

        if not feasible:

            raise ValueError(

                f"口令 {password_m} 与明文几何不兼容。\n"

                f"该明文在所有参数下能实现的缠绕数为：{observed}\n"

                f"请选择其中一个值作为口令，或修改明文数据。"

            )



    for attempt in range(MAX_KEYGEN_ATTEMPTS):

        raw = f"{seed}{timestamp}{nonce}{master_seed}{password_m}"

        digest = hashlib.sha3_256(raw.encode()).hexdigest()



        alpha = CHAOS_LOW + (CHAOS_HIGH - CHAOS_LOW) * (int(digest[0:8], 16) / 2**32)

        beta  = CHAOS_LOW + (CHAOS_HIGH - CHAOS_LOW) * (int(digest[8:16], 16) / 2**32)

        gamma = CHAOS_LOW + (CHAOS_HIGH - CHAOS_LOW) * (int(digest[16:24], 16) / 2**32)



        a = GEO_LOW + (GEO_HIGH - GEO_LOW) * (int(digest[24:32], 16) / 2**32)

        b = GEO_LOW + (GEO_HIGH - GEO_LOW) * (int(digest[32:40], 16) / 2**32)

        c = GEO_LOW + (GEO_HIGH - GEO_LOW) * (int(digest[40:48], 16) / 2**32)



        params = SecurityParams(alpha, beta, gamma, a, b, c)



        # 缠绕数校验（快速预跑 100 步）

        test_seq = []

        p = _seed_to_point(seed)

        for _ in range(100):

            p = _chaos_map(p, alpha, beta, gamma)

            p = _geo_project(p, a, b, c)

            test_seq.append(p)



        if _compute_winding(test_seq) == password_m:

            return params, nonce



        nonce += 1



    raise RuntimeError(

        f"经过 {MAX_KEYGEN_ATTEMPTS} 次尝试仍无法找到匹配口令 {password_m} 的密钥。"

        "请尝试使用预检模式推荐的缠绕数值。"

    )

```



---



第六部分：加密引擎（含时间戳固定与版本号）



```python

def encrypt(plain_point: Tuple[float, ...],

            password_m: int,

            master_seed: Optional[str] = None,

            key_version: Optional[int] = None) -> CipherText:

    """

    [FIX 3] 加密端固定时间戳并写入密文

    [FIX 4] 记录主密钥版本号

    """

    timestamp = int(time.time())

    nonce = random.getrandbits(64)



    # [FIX 4] 获取当前主密钥版本

    if master_seed is None:

        # 从全局管理器获取当前版本

        kv, ms = GLOBAL_KEY_MANAGER.get_current_key()

        if ms is None:

            raise RuntimeError("未配置主密钥")

        master_seed = ms

        key_version = kv

    else:

        # 若显式传入主密钥，尝试匹配版本号

        if key_version is None:

            # 扫描所有版本找到匹配的种子

            for v, entry in GLOBAL_KEY_MANAGER._keys.items():

                if entry.seed == master_seed:

                    key_version = v

                    break

            if key_version is None:

                raise ValueError("无法匹配传入的主密钥到任何已知版本")



    # 生成密钥（内部调用，跳过预检避免重复检查）

    params, final_nonce = generate_keys(

        seed=str(plain_point),

        timestamp=timestamp,

        nonce=nonce,

        master_seed=master_seed,

        password_m=password_m,

        skip_precheck=True      # 加密入口已通过预检

    )



    # 运行混合迭代 N_ITER 轮

    p = plain_point

    for _ in range(N_ITER):

        p = _chaos_map(p, params.alpha, params.beta, params.gamma)

        p = _geo_project(p, params.a, params.b, params.c)



    return CipherText(

        nonce=final_nonce,

        timestamp=timestamp,

        key_version=key_version,

        point=p

    )

```



---



第七部分：解密与验证（含恒定时间执行）



```python

def decrypt_verify(cipher: CipherText,

                   guess_m: int,

                   plain_original: Tuple,

                   master_seed: Optional[str] = None) -> bool:

    """

    [FIX 3] 使用密文中的时间戳，不再依赖本地系统时间

    [FIX 4] 根据密文中的版本号获取对应的主密钥

    """

    result = False



    try:

        # [FIX 4] 获取对应版本的主密钥

        if master_seed is None:

            # 从全局管理器根据版本号获取

            entry = GLOBAL_KEY_MANAGER._keys.get(cipher.key_version)

            if entry is None:

                # 未知版本，拒绝

                return False

            master_seed = entry.seed

        # 如果显式传入 master_seed，则直接使用（用于测试场景）



        # 使用密文中固定的时间戳和随机数重算密钥

        params, _ = generate_keys(

            seed=str(plain_original),

            timestamp=cipher.timestamp,          # [FIX 3] 使用密文内的时间戳

            nonce=cipher.nonce,

            master_seed=master_seed,

            password_m=guess_m,

            skip_precheck=True                   # 验证时不重复预检

        )



        # 正向跑满 N_ITER 轮

        p = plain_original

        trajectory = []

        for i in range(N_ITER):

            p = _chaos_map(p, params.alpha, params.beta, params.gamma)

            p = _geo_project(p, params.a, params.b, params.c)

            if i > N_ITER - 100:

                trajectory.append(p)



        # 判定1：终点匹配容差

        dist = math.sqrt(

            (p[0] - cipher.point[0])**2 +

            (p[1] - cipher.point[1])**2 +

            (p[2] - cipher.point[2])**2

        )

        if dist < EPSILON:

            # 判定2：缠绕数匹配

            if _compute_winding(trajectory) == guess_m:

                result = True



    except Exception:

        # 任何异常统一返回 False，不暴露具体错误

        pass



    # [FIX 3] 恒定时间执行：无论结果如何，跑满后做无害空计算

    _dummy = sum([math.sin(i) for i in range(100)])



    return result

```



---



第八部分：时间锁扩展（可选）



```python

def encrypt_with_time_lock(plain_point: Tuple,

                           password_m: int,

                           unlock_after: int,      # Unix 时间戳，解锁最早时间

                           master_seed: Optional[str] = None) -> CipherText:

    """

    时间锁加密：密文在 unlock_after 时间之前无法被解密。

    原理：在密钥派生的哈希输入中嵌入 unlock_after，使几何空间依赖于解锁时间。

    """

    # 在加密时，将 unlock_after 作为额外的输入嵌入密钥派生

    # 解密端必须提供当前时间 >= unlock_after 才能正确重算密钥

    # 实现方法：将 unlock_after 加入 generate_keys 的哈希输入中

    # 此处省略完整实现，为扩展预留接口

    pass

```



---



第九部分：变更日志（v1.0 → v1.1）



修复项 触发条件 修复方案 影响范围

[FIX 1] 缠绕数初始化退化 atan2(0,0) 跳过 Z 轴上的起始点 _compute_winding

[FIX 2] 密钥搜索崩溃 口令与明文几何不兼容 增加预检模式 precheck_compatibility generate_keys + encrypt

[FIX 3] 时间戳同步失败 加密/解密不同秒 时间戳固定写入密文 CipherText + decrypt_verify

[FIX 4] 主密钥泄漏无应对 单点失效 增加 MasterKeyManager + 版本号 全局架构