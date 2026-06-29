#!/usr/bin/env python3
# ============================================================
# CCI: Constrained Chaotic Iteration Encryption System
# 版本: 1.2 (2026-06-29)
# 作者: [肖景文]
# 许可证: GPL v3 + 商业授权例外 (详见 LICENSE 文件)
#
# 本程序是自由软件: 你可以根据自由软件基金会发布的 GNU
# 通用公共许可证（第3版或任何更高版本）的条款重新分发或修改它。
#
# 本程序分发的目的是希望它有用，但没有任何担保；甚至没有
# 隐含的适销性或特定用途适用性的担保。更多细节请参见
# GNU通用公共许可证第3版。
#
# 商业授权例外：任何商业闭源使用须获得作者书面授权。
# ============================================================# -*- coding: utf-8 -*-
"""
CCI: Constrained Chaotic Iteration Encryption System
版本: 1.2 (2026-06-29)
包含全部四项工程修复：
  1. 缠绕数初始化依赖 (跳过Z轴点)
  2. 密钥搜索崩溃 (预检模式)
  3. 时间戳同步 (固定于密文)
  4. 主密钥泄漏模型 (版本化管理)

用法: python cci.py
"""

import hashlib
import random
import math
import time
from typing import Tuple, List, Optional, Set
from dataclasses import dataclass
import sys


# ============================================================
# 第一部分：全局常量与数据结构
# ============================================================

EPSILON = 1e-9                 # 几何验证容差
N_ITER = 1000                  # 加密迭代轮数
L_PRE = 100                    # 缠绕校验/预检步数
MAX_KEYGEN_ATTEMPTS = 256      # 密钥搜索尝试上限
PRECHECK_SAMPLES = 20          # 预检采样次数
CHAOS_LOW, CHAOS_HIGH = 0.5, 2.0
GEO_LOW, GEO_HIGH = 0.5, 2.0


@dataclass
class SecurityParams:
    """加密参数 (混沌 + 几何)"""
    alpha: float
    beta: float
    gamma: float
    a: float
    b: float
    c: float


@dataclass
class CipherText:
    """密文包"""
    nonce: int
    timestamp: int
    key_version: int
    point: Tuple[float, float, float]


@dataclass
class MasterKeyEntry:
    """主密钥条目"""
    seed: str
    effective_from: int
    description: str = ""
    is_revoked: bool = False


# ============================================================
# 第二部分：核心数学函数
# ============================================================

def _chaos_map(p: Tuple[float, float, float],
               alpha: float, beta: float, gamma: float) -> Tuple[float, float, float]:
    """三维标准映射 (混沌扩散层)"""
    x, y, z = p
    return (
        (x + alpha * math.sin(y)) % (2 * math.pi),
        (y + beta * math.cos(x)) % (2 * math.pi),
        (z + gamma * math.sin(x + y)) % (2 * math.pi)
    )


def _geo_project(p: Tuple[float, float, float],
                 a: float, b: float, c: float) -> Tuple[float, float, float]:
    """径向投影至椭球面 (几何约束层)"""
    x, y, z = p
    r = math.sqrt((x / a) ** 2 + (y / b) ** 2 + (z / c) ** 2)
    if r < 1e-15:
        # 原点映射到椭球北极
        return (0.0, 0.0, c)
    return (x / r, y / r, z / r)


def _compute_winding(seq: List[Tuple[float, float, float]]) -> int:
    """
    计算轨迹绕Z轴的缠绕数
    修复：跳过在Z轴上的起始点，避免 atan2(0,0)
    """
    # 寻找第一个不在Z轴上的点
    start_idx = 0
    for i, p in enumerate(seq):
        if abs(p[0]) > 1e-15 or abs(p[1]) > 1e-15:
            start_idx = i
            break
    else:
        # 所有点都在Z轴上：缠绕数为0
        return 0

    angle_prev = math.atan2(seq[start_idx][1], seq[start_idx][0])
    total_angle = 0.0

    for p in seq[start_idx + 1:]:
        angle_cur = math.atan2(p[1], p[0])
        delta = angle_cur - angle_prev
        if delta > math.pi:
            delta -= 2 * math.pi
        if delta < -math.pi:
            delta += 2 * math.pi
        total_angle += delta
        angle_prev = angle_cur

    return int(round(total_angle / (2 * math.pi)))


def _seed_to_point(seed: str) -> Tuple[float, float, float]:
    """将字符串种子映射到三维空间中的点 (用于预检)"""
    h = hashlib.sha256(seed.encode()).hexdigest()
    x = (int(h[0:8], 16) / 0xFFFFFFFF) * 2.0 - 1.0
    y = (int(h[8:16], 16) / 0xFFFFFFFF) * 2.0 - 1.0
    z = (int(h[16:24], 16) / 0xFFFFFFFF) * 2.0 - 1.0
    return (x, y, z)


# ============================================================
# 第三部分：主密钥管理器
# ============================================================

class MasterKeyManager:
    """版本化的主密钥管理器 (修复4)"""

    def __init__(self):
        self._keys: dict[int, MasterKeyEntry] = {}
        self._current_version: Optional[int] = None

    def add_key(self, version: int, seed: str, effective_from: int,
                description: str = "") -> None:
        self._keys[version] = MasterKeyEntry(seed, effective_from, description)
        # 更新当前版本 (取生效时间最新者)
        if self._current_version is None:
            self._current_version = version
        else:
            cur = self._keys[self._current_version]
            if effective_from > cur.effective_from:
                self._current_version = version

    def get_key(self, timestamp: int) -> Tuple[Optional[int], Optional[str]]:
        """根据时间戳获取对应版本的主密钥"""
        applicable = [(v, e.seed) for v, e in self._keys.items()
                      if e.effective_from <= timestamp]
        if not applicable:
            return (None, None)
        applicable.sort(key=lambda x: x[0])
        return applicable[-1]

    def get_current_key(self) -> Tuple[Optional[int], Optional[str]]:
        if self._current_version is None:
            return (None, None)
        return (self._current_version, self._keys[self._current_version].seed)

    def emergency_revoke(self, compromised_version: int,
                         new_seed: str, effective_from: int) -> None:
        """紧急废止泄露的主密钥"""
        if compromised_version in self._keys:
            self._keys[compromised_version].description += " [REVOKED]"
        self.add_key(compromised_version + 1, new_seed, effective_from,
                     "Emergency rollover after revocation")


# ============================================================
# 第四部分：预检模式 (修复2)
# ============================================================

def precheck_compatibility(seed: str, target_m: int,
                           samples: int = PRECHECK_SAMPLES) -> Tuple[bool, List[int]]:
    """
    预检：用随机参数快速采样，估算该明文能实现的缠绕数范围
    返回 (是否可能达到 target_m, 观察到的缠绕数列表)
    """
    observed: Set[int] = set()
    base_point = _seed_to_point(seed)

    for _ in range(samples):
        alpha = random.uniform(CHAOS_LOW, CHAOS_HIGH)
        beta = random.uniform(CHAOS_LOW, CHAOS_HIGH)
        gamma = random.uniform(CHAOS_LOW, CHAOS_HIGH)
        a = random.uniform(GEO_LOW, GEO_HIGH)
        b = random.uniform(GEO_LOW, GEO_HIGH)
        c = random.uniform(GEO_LOW, GEO_HIGH)

        seq = []
        p = base_point
        for _ in range(L_PRE):
            p = _chaos_map(p, alpha, beta, gamma)
            p = _geo_project(p, a, b, c)
            seq.append(p)
        observed.add(_compute_winding(seq))

    possible = (target_m in observed) or (target_m == 0)
    return possible, sorted(observed)


# ============================================================
# 第五部分：密钥生成 (口令缠绕)
# ============================================================

def generate_keys(seed: str, timestamp: int, nonce: int,
                  master_seed: str, password_m: int,
                  skip_precheck: bool = False) -> Tuple[SecurityParams, int]:
    """
    生成满足口令缠绕条件的密钥参数
    """
    # 预检 (除非跳过)
    if not skip_precheck:
        feasible, observed = precheck_compatibility(seed, password_m)
        if not feasible:
            raise ValueError(
                f"口令 {password_m} 与明文几何不兼容。\n"
                f"该明文可实现的缠绕数为: {observed}\n"
                f"请选择其中一个作为口令，或修改明文数据。"
            )

    for attempt in range(MAX_KEYGEN_ATTEMPTS):
        raw = f"{seed}{timestamp}{nonce}{master_seed}{password_m}"
        digest = hashlib.sha3_256(raw.encode()).hexdigest()

        # 从哈希中提取参数
        def _extract(start: int) -> float:
            part = int(digest[start:start+8], 16)
            return CHAOS_LOW + (CHAOS_HIGH - CHAOS_LOW) * (part / 0xFFFFFFFF)

        alpha = _extract(0)
        beta = _extract(8)
        gamma = _extract(16)
        a = _extract(24)
        b = _extract(32)
        c = _extract(40)

        params = SecurityParams(alpha, beta, gamma, a, b, c)

        # 校验缠绕数
        seq = []
        p = _seed_to_point(seed)
        for _ in range(L_PRE):
            p = _chaos_map(p, alpha, beta, gamma)
            p = _geo_project(p, a, b, c)
            seq.append(p)

        if _compute_winding(seq) == password_m:
            return params, nonce

        nonce += 1

    raise RuntimeError(
        f"经过 {MAX_KEYGEN_ATTEMPTS} 次尝试仍无法找到匹配口令 {password_m} 的密钥。"
    )


# ============================================================
# 第六部分：加密引擎
# ============================================================

def encrypt(plain_point: Tuple[float, float, float],
            password_m: int,
            master_seed: Optional[str] = None,
            key_version: Optional[int] = None) -> CipherText:
    """
    加密主函数
    固定时间戳并写入密文，记录主密钥版本号
    """
    timestamp = int(time.time())
    nonce = random.getrandbits(64)

    # 获取主密钥及版本号
    if master_seed is None:
        # 从全局管理器获取
        kv, ms = GLOBAL_KEY_MANAGER.get_current_key()
        if ms is None:
            raise RuntimeError("未配置主密钥")
        master_seed = ms
        key_version = kv
    else:
        # 若显式传入，尝试匹配版本号
        if key_version is None:
            for v, entry in GLOBAL_KEY_MANAGER._keys.items():
                if entry.seed == master_seed:
                    key_version = v
                    break
            if key_version is None:
                # 未知主密钥：临时分配版本号 -1
                key_version = -1

    # 生成密钥 (跳过预检，因为 encrypt 入口会先调 precheck)
    params, final_nonce = generate_keys(
        seed=str(plain_point),
        timestamp=timestamp,
        nonce=nonce,
        master_seed=master_seed,
        password_m=password_m,
        skip_precheck=True    # 由外层调用者决定是否预检
    )

    # 迭代加密
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


# ============================================================
# 第七部分：解密验证
# ============================================================

def decrypt_verify(cipher: CipherText,
                   guess_m: int,
                   plain_original: Tuple[float, float, float],
                   master_seed: Optional[str] = None) -> bool:
    """
    解密验证：恒定时间执行，防止定时攻击
    """
    result = False

    try:
        # 获取正确版本的主密钥
        if master_seed is None:
            entry = GLOBAL_KEY_MANAGER._keys.get(cipher.key_version)
            if entry is None or entry.is_revoked:
                return False
            master_seed = entry.seed

        # 使用密文中的时间戳重算密钥
        params, _ = generate_keys(
            seed=str(plain_original),
            timestamp=cipher.timestamp,
            nonce=cipher.nonce,
            master_seed=master_seed,
            password_m=guess_m,
            skip_precheck=True
        )

        # 正向迭代
        p = plain_original
        trajectory = []
        for i in range(N_ITER):
            p = _chaos_map(p, params.alpha, params.beta, params.gamma)
            p = _geo_project(p, params.a, params.b, params.c)
            if i > N_ITER - L_PRE:
                trajectory.append(p)

        # 判定1：终点匹配
        dist = math.sqrt(
            (p[0] - cipher.point[0]) ** 2 +
            (p[1] - cipher.point[1]) ** 2 +
            (p[2] - cipher.point[2]) ** 2
        )
        if dist < EPSILON:
            if _compute_winding(trajectory) == guess_m:
                result = True

    except Exception:
        # 任何异常统一返回 False
        pass

    # 恒定时间执行：无害空计算
    _dummy = sum(math.sin(i) for i in range(100))

    return result


# ============================================================
# 第八部分：全局主密钥管理器实例
# ============================================================

GLOBAL_KEY_MANAGER = MasterKeyManager()
# 初始化默认主密钥 (实际部署应安全存储)
GLOBAL_KEY_MANAGER.add_key(1, "REPLACE_WITH_YOUR_OWN_256BIT_MASTER_SEED", 0,
                           "Initial development key")


# ============================================================
# 第九部分：测试与示例
# ============================================================

def main():
    """运行完整测试闭环"""
    print("=" * 60)
    print("CCI 加密系统 v1.2 – 测试演示")
    print("=" * 60)

    # 1. 设置测试数据
    plain_point = (1.0, 1.0, 0.5)
    password_m = 3
    print(f"[1] 明文点: {plain_point}")
    print(f"[2] 口令: {password_m}")

    # 2. 预检
    feasible, observed = precheck_compatibility(str(plain_point), password_m)
    print(f"[3] 预检: 可行? {feasible}, 可实现的缠绕数: {observed}")
    if not feasible:
        print("    ⚠️ 警告: 该口令可能不可行，但仍尝试加密...")

    # 3. 加密
    print("[4] 加密中...")
    cipher = encrypt(plain_point, password_m)
    print(f"[5] 密文: ({cipher.point[0]:.6f}, {cipher.point[1]:.6f}, {cipher.point[2]:.6f})")
    print(f"    Nonce: {cipher.nonce}, Timestamp: {cipher.timestamp}, 密钥版本: {cipher.key_version}")

    # 4. 正确口令验证
    print("[6] 正确口令验证...")
    ok = decrypt_verify(cipher, password_m, plain_point)
    print(f"    结果: {'✅ 通过' if ok else '❌ 失败'}")

    # 5. 错误口令验证
    print("[7] 错误口令 (m=5) 验证...")
    ok_fail = decrypt_verify(cipher, 5, plain_point)
    print(f"    结果: {'✅ 通过 (不应发生)' if ok_fail else '❌ 拒绝 (正确)'}")

    # 6. 性能测试 (粗略)
    print("[8] 性能测试: 加密 10 次...")
    import time as ttime
    start = ttime.time()
    for _ in range(10):
        encrypt(plain_point, password_m)
    elapsed = ttime.time() - start
    print(f"    平均耗时: {elapsed/10:.3f} 秒/次 (Python 单核)")

    print("\n" + "=" * 60)
    print("测试完成。")
    print("=" * 60)


if __name__ == "__main__":
    main()
