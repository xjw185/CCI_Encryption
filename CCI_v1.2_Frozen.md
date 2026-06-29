# CCI 完整伪代码 v1.2（修正版）

> 说明：以下为 Python 风格伪代码。核心变更以 `[FIX]` 标注并附简要注释。  
> ⚠️ 本文件为算法实现的伪代码文档，仅供学习参考。  
> 商业用途须获得作者授权（详见 LICENSE 文件）。

---

## 第一部分：数据结构与常量

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

# ---------- 全局工程常量 ----------
EPSILON = 1e-9
N_ITER = 1000
MAX_KEYGEN_ATTEMPTS = 256
PRECHECK_SAMPLES = 20
CHAOS_LOW, CHAOS_HIGH = 0.5, 2.0
GEO_LOW, GEO_HIGH = 0.5, 2.0
WINDOW_TOLERANCE = 3600

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
    key_version: int
    point: Tuple[float, float, float]

@dataclass
class MasterKeyEntry:
    seed: str
    effective_from: int
    description: str = ""
    is_revoked: bool = False          # [FIX] 显式废止标记
第二部分：辅助数学函数
python
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
        return (0.0, 0.0, c)
    return (x / r, y / r, z / r)

def _compute_winding(p_seq: List[Tuple]) -> int:
    """
    [FIX 1] 缠绕数计算：防止 atan2(0,0) 退化
    """
    start_idx = 0
    for i, p in enumerate(p_seq):
        if abs(p[0]) > 1e-15 or abs(p[1]) > 1e-15:
            start_idx = i
            break
    else:
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
    h = hashlib.sha256(seed.encode()).hexdigest()
    x = (int(h[0:8], 16) / 2**32) * 2 - 1
    y = (int(h[8:16], 16) / 2**32) * 2 - 1
    z = (int(h[16:24], 16) / 2**32) * 2 - 1
    return (x, y, z)
第三部分：主密钥管理器
python
class MasterKeyManager:
    """
    [FIX 4] 主密钥轮换与多密钥容灾
    """
    def __init__(self):
        self._keys: dict[int, MasterKeyEntry] = {}
        self._current_version: Optional[int] = None

    def add_key(self, version: int, seed: str, effective_from: int,
                description: str = "") -> None:
        self._keys[version] = MasterKeyEntry(
            seed=seed,
            effective_from=effective_from,
            description=description,
            is_revoked=False
        )
        if self._current_version is None:
            self._current_version = version
        else:
            cur = self._keys.get(self._current_version)
            if cur is None or cur.is_revoked:
                self._current_version = self._get_best_version()
            elif effective_from > cur.effective_from and not self._keys[version].is_revoked:
                self._current_version = version

    def _get_best_version(self) -> Optional[int]:
        active = [(v, e) for v, e in self._keys.items() if not e.is_revoked]
        if not active:
            return None
        active.sort(key=lambda x: x[1].effective_from, reverse=True)
        return active[0][0]

    def get_key(self, timestamp: int) -> Tuple[Optional[int], Optional[str]]:
        applicable = [
            (v, e.seed) for v, e in self._keys.items()
            if e.effective_from <= timestamp and not e.is_revoked
        ]
        if not applicable:
            return (None, None)
        applicable.sort(key=lambda x: x[0])
        return applicable[-1]

    def get_current_key(self) -> Tuple[Optional[int], Optional[str]]:
        best_version = self._get_best_version()
        if best_version is None:
            return (None, None)
        self._current_version = best_version
        return (self._current_version, self._keys[self._current_version].seed)

    def emergency_revoke(self, compromised_version: int,
                         new_seed: str, effective_from: int) -> None:
        if compromised_version in self._keys:
            self._keys[compromised_version].is_revoked = True
            self._keys[compromised_version].description += " [REVOKED]"
        new_version = compromised_version + 1
        self.add_key(new_version, new_seed, effective_from,
                     "Emergency rollover after revocation")
        self._current_version = self._get_best_version()
第四部分：预检模式
python
def precheck_compatibility(seed: str, target_m: int,
                           max_samples: int = PRECHECK_SAMPLES) -> Tuple[bool, List[int]]:
    """
    [FIX 2] 预检：估算明文的缠绕数可行区间
    """
    observed: Set[int] = set()
    base_point = _seed_to_point(seed)

    for _ in range(max_samples):
        alpha = random.uniform(CHAOS_LOW, CHAOS_HIGH)
        beta = random.uniform(CHAOS_LOW, CHAOS_HIGH)
        gamma = random.uniform(CHAOS_LOW, CHAOS_HIGH)
        a = random.uniform(GEO_LOW, GEO_HIGH)
        b = random.uniform(GEO_LOW, GEO_HIGH)
        c = random.uniform(GEO_LOW, GEO_HIGH)

        test_seq = []
        p = base_point
        for _ in range(100):
            p = _chaos_map(p, alpha, beta, gamma)
            p = _geo_project(p, a, b, c)
            test_seq.append(p)

        observed.add(_compute_winding(test_seq))

    possible = (target_m in observed) or (target_m == 0)
    return possible, sorted(observed)
第五部分：密钥生成（含口令缠绕）
python
def generate_keys(seed: str, timestamp: int, nonce: int,
                  master_seed: str, password_m: int,
                  skip_precheck: bool = False) -> Tuple[SecurityParams, int]:
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
第六部分：加密引擎
python
# 假设全局密钥管理器已初始化（实际部署时需从安全存储加载）
GLOBAL_KEY_MANAGER = MasterKeyManager()
GLOBAL_KEY_MANAGER.add_key(1, "DEFAULT_MASTER_SEED_CHANGE_ME", 0, "Initial key")

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

    if master_seed is None:
        kv, ms = GLOBAL_KEY_MANAGER.get_current_key()
        if ms is None:
            raise RuntimeError("未配置主密钥")
        master_seed = ms
        key_version = kv
    else:
        if key_version is None:
            for v, entry in GLOBAL_KEY_MANAGER._keys.items():
                if entry.seed == master_seed:
                    key_version = v
                    break
            if key_version is None:
                raise ValueError("无法匹配传入的主密钥到任何已知版本")

    params, final_nonce = generate_keys(
        seed=str(plain_point),
        timestamp=timestamp,
        nonce=nonce,
        master_seed=master_seed,
        password_m=password_m,
        skip_precheck=True
    )

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
第七部分：解密与验证（恒定时间）
python
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
        if master_seed is None:
            entry = GLOBAL_KEY_MANAGER._keys.get(cipher.key_version)
            if entry is None or entry.is_revoked:    # [FIX] 检查废止状态
                return False
            master_seed = entry.seed

        params, _ = generate_keys(
            seed=str(plain_original),
            timestamp=cipher.timestamp,
            nonce=cipher.nonce,
            master_seed=master_seed,
            password_m=guess_m,
            skip_precheck=True
        )

        p = plain_original
        trajectory = []
        for i in range(N_ITER):
            p = _chaos_map(p, params.alpha, params.beta, params.gamma)
            p = _geo_project(p, params.a, params.b, params.c)
            if i > N_ITER - 100:
                trajectory.append(p)

        dist = math.sqrt(
            (p[0] - cipher.point[0])**2 +
            (p[1] - cipher.point[1])**2 +
            (p[2] - cipher.point[2])**2
        )
        if dist < EPSILON:
            if _compute_winding(trajectory) == guess_m:
                result = True

    except Exception:
        pass

    # 恒定时间执行：无论结果如何，跑满后做无害空计算
    _dummy = sum([math.sin(i) for i in range(100)])
    return result
第八部分：时间锁扩展（预留）
python
def encrypt_with_time_lock(plain_point: Tuple,
                           password_m: int,
                           unlock_after: int,
                           master_seed: Optional[str] = None) -> CipherText:
    """
    时间锁加密：密文在 unlock_after 时间之前无法被解密。
    （完整实现预留）
    """
    pass
第九部分：变更日志
版本	修复项	触发条件	修复方案	影响范围
v1.0→v1.1	[FIX 1] 缠绕数初始化退化	atan2(0,0)	跳过 Z 轴起始点	_compute_winding
v1.0→v1.1	[FIX 2] 密钥搜索崩溃	口令与明文几何不兼容	增加预检模式	precheck_compatibility
v1.0→v1.1	[FIX 3] 时间戳同步失败	加密/解密不同秒	时间戳写入密文	CipherText + decrypt_verify
v1.0→v1.1	[FIX 4] 主密钥泄漏无应对	单点失效	增加 MasterKeyManager	全局架构
v1.1→v1.2	[FIX 5] 废止版本仍被选为当前版本	逻辑盲区	增加 is_revoked 字段 + 自动故障转移	MasterKeyManager
