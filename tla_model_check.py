#!/usr/bin/env python3
"""
tla_model_check.py - Model Checker Python xác minh EngramRevoke.tla
===================================================================
Phần 1: Duyệt exhaustive (BFS) toàn bộ không gian trạng thái của mô hình
        TLA+ (cùng hằng số với EngramRevoke.cfg) và kiểm chứng 7 invariant:
          TypeOK, I1TerminalStable, I2EpochMonotonic, I3StaleRejected,
          I4FailClosed, I5NoLeak, RevokeLatched
        + Chạy kiểm tra ĐỐI CHIẾU (mutant): vô hiệu hóa Terminal State
          Invariant -> model checker phải BẮT được vi phạm I1/I5.

Phần 2: Đối chiếu mô hình với cài đặt Python thật:
          signedandapend_events.py, anchorroot.py,
          freshnesswindowandlatesttrustedroot.py,
          test_adversarial_suite.py

Chạy:  python3 tla_model_check.py
"""
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass, replace

# =============================================================================
# HẰNG SỐ - Khớp EngramRevoke.cfg
# =============================================================================
MAX_EPOCH = 5           # MaxEpoch = 5
FRESHNESS_WINDOW = 2    # FreshnessWindow = 2

POLICY_STATES = {"NONE", "ACTIVE", "SUSPENDED", "REVOKED", "EXPIRED"}
TERMINAL_STATES = {"REVOKED", "EXPIRED"}
VALID_TRANSITIONS = {
    ("ACTIVE", "SUSPENDED"),
    ("SUSPENDED", "ACTIVE"),
    ("ACTIVE", "EXPIRED"),
    ("ACTIVE", "REVOKED"),
    ("SUSPENDED", "REVOKED"),
}
OUTCOMES = {"none", "granted", "stale", "failclosed", "blocked"}
ROOT_VIEWS = range(0, MAX_EPOCH + 1)


# =============================================================================
# TRẠNG THÁI MÔ HÌNH (khớp biến trong EngramRevoke.tla)
# =============================================================================
@dataclass(frozen=True)
class State:
    pstate: str = "NONE"
    pepoch: int = 1
    aepoch: int = 0
    netUp: bool = True
    kEpoch: int = 0
    kFresh: bool = False
    partitionAge: int = 0
    revokeDone: bool = False
    outcome: str = "none"
    presented: int = 0
    # 3 flag an toàn - ghi nhận tại thời điểm cấp khóa
    staleGrant: bool = False    # I3
    unfreshGrant: bool = False  # I4
    leak: bool = False          # I5
    # biến lịch sử/phái sinh
    maxKE: int = 0
    terminalSeen: bool = False


INIT_STATE = State()


def derive(s: State) -> State:
    r"""maxKE' = Max(maxKE, kEpoch');  terminalSeen' = terminalSeen \/
    (pstate' \in TerminalStates) - 2 conjunct cuối của Next trong TLA+."""
    max_ke = max(s.maxKE, s.kEpoch)
    term = s.terminalSeen or (s.pstate in TERMINAL_STATES)
    if max_ke == s.maxKE and term == s.terminalSeen:
        return s
    return replace(s, maxKE=max_ke, terminalSeen=term)


def successors(s: State, mutant: bool = False):
    """Sinh tất cả trạng thái kế tiếp - bám sát từng Action trong EngramRevoke.tla.

    mutant=True: mô phỏng CHỦ ĐÍCH gỡ bỏ Terminal State Invariant
    (cho phép REVOKED -> ACTIVE) - model checker phải bắt được vi phạm.
    """
    out = []

    # --- Action 1: InitPolicy (NONE -> ACTIVE, neo epoch 1) ---
    if s.pstate == "NONE":
        if s.netUp:
            out.append(("InitPolicy(sync ep1)",
                        replace(s, pstate="ACTIVE", aepoch=1, kEpoch=1,
                                kFresh=True, partitionAge=0)))
        else:
            out.append(("InitPolicy(partition->failclosed)",
                        replace(s, pstate="ACTIVE", aepoch=1)))

    # --- Action 2: Transition (State Machine + Terminal Invariant I1) ---
    allowed = set(VALID_TRANSITIONS)
    if mutant:
        allowed = allowed | {("REVOKED", "ACTIVE")}  # MUTANT: gỡ terminal inv.
    for new_st in {"SUSPENDED", "ACTIVE", "REVOKED", "EXPIRED"}:
        if (s.pstate, new_st) not in allowed:
            continue
        # Guard: pstate \in {ACTIVE,_SUSPENDED}  (mutant bỏ guard này)
        if not mutant and s.pstate not in {"ACTIVE", "SUSPENDED"}:
            continue
        if new_st in TERMINAL_STATES and s.pepoch >= MAX_EPOCH:
            continue  # (newSt terminal) => pepoch < MaxEpoch
        ns = replace(s, pstate=new_st)
        if new_st in TERMINAL_STATES:
            ns = replace(ns, pepoch=s.pepoch + 1)
        if new_st == "REVOKED":
            ns = replace(ns, revokeDone=True)
        out.append((f"Transition({s.pstate}->{new_st})", ns))

    # --- Action 3: Anchor (yêu cầu sau InitPolicy -> bảo toàn I2) ---
    if s.pstate != "NONE" and s.netUp and s.aepoch < MAX_EPOCH:
        out.append(("Anchor", replace(s, aepoch=s.aepoch + 1)))

    # --- Action 4: Sync ---
    if s.pstate != "NONE" and s.netUp and s.aepoch > s.kEpoch:
        out.append(("Sync", replace(s, kEpoch=s.aepoch, kFresh=True,
                                    partitionAge=0)))

    # --- Action 5: Refresh ---
    if (s.pstate != "NONE" and s.netUp and not s.kFresh
            and s.aepoch > 0 and s.aepoch >= s.kEpoch):
        out.append(("Refresh", replace(s, kFresh=True, partitionAge=0)))

    # --- Action 6: StartPartition ---
    if s.netUp:
        out.append(("StartPartition", replace(s, netUp=False, partitionAge=0)))

    # --- Action 7: AgePartition ---
    if not s.netUp and s.partitionAge < FRESHNESS_WINDOW:
        new_age = s.partitionAge + 1
        out.append(("AgePartition", replace(
            s, partitionAge=new_age,
            kFresh=s.kFresh and new_age < FRESHNESS_WINDOW)))

    # --- Action 8: EndPartition ---
    if not s.netUp:
        out.append(("EndPartition", replace(s, netUp=True, partitionAge=0)))

    # --- Action 9: RequestAccess(p) - 3 flag ghi nhận tại thời điểm grant ---
    for p in ROOT_VIEWS:
        if not s.kFresh:
            outcome = "failclosed"
        elif p != s.kEpoch:
            outcome = "stale"
        elif s.pstate != "ACTIVE":
            outcome = "blocked"
        else:
            outcome = "granted"
        ns = replace(s, presented=p, outcome=outcome,
                     staleGrant=s.staleGrant or (outcome == "granted"
                                                 and p != s.kEpoch),
                     unfreshGrant=s.unfreshGrant or (outcome == "granted"
                                                     and not s.kFresh),
                     leak=s.leak or (outcome == "granted" and s.revokeDone))
        out.append((f"RequestAccess(p={p})", ns))

    return [(act, derive(ns)) for act, ns in out]


# =============================================================================
# INVARIANTS (khớp EngramRevoke.tla)
# =============================================================================
def check_invariants(s: State):
    violations = []
    # TypeOK
    if not (s.pstate in POLICY_STATES
            and 1 <= s.pepoch <= MAX_EPOCH
            and 0 <= s.aepoch <= MAX_EPOCH
            and 0 <= s.kEpoch <= MAX_EPOCH
            and 0 <= s.partitionAge <= FRESHNESS_WINDOW
            and s.outcome in OUTCOMES
            and s.presented in ROOT_VIEWS
            and 0 <= s.maxKE <= MAX_EPOCH):
        violations.append(("TypeOK", s))
    # I1
    if s.terminalSeen and s.pstate not in TERMINAL_STATES:
        violations.append(("I1TerminalStable", s))
    # I2
    if s.kEpoch != s.maxKE:
        violations.append(("I2EpochMonotonic", s))
    # I3
    if s.staleGrant:
        violations.append(("I3StaleRejected", s))
    # I4
    if s.unfreshGrant:
        violations.append(("I4FailClosed", s))
    # I5
    if s.leak:
        violations.append(("I5NoLeak", s))
    # RevokeLatched
    if s.revokeDone and s.pstate != "REVOKED":
        violations.append(("RevokeLatched", s))
    return violations


# =============================================================================
# BFS EXHAUSTIVE
# =============================================================================
def model_check(mutant: bool = False):
    start = time.perf_counter()
    queue = deque([INIT_STATE])                 # BFS queue
    parent = {INIT_STATE: (None, None)}          # state -> (parent, action)
    visited = {INIT_STATE}
    violations = {}
    edges = 0

    while queue:
        state = queue.popleft()
        for act, ns in successors(state, mutant=mutant):
            edges += 1
            for name, bad_state in check_invariants(ns):
                if name not in violations:
                    violations[name] = (ns, act, state)
            if ns not in visited:
                visited.add(ns)
                parent[ns] = (state, act)
                queue.append(ns)

    elapsed = time.perf_counter() - start
    return visited, edges, violations, parent, elapsed


def print_counterexample(violations, parent):
    for name, (bad_state, action, _) in violations.items():
        # Truy ngược về Init
        trace = []
        cur = bad_state
        while parent[cur][0] is not None:
            prev, act = parent[cur]
            trace.append((act, cur))
            cur = prev
        trace.append(("Init", cur))
        trace.reverse()
        print(f"\n  [COUNTEREXAMPLE] {name}:")
        print(f"    Action vi phạm cuối: {action}")
        print(f"    Số bước từ Init    : {len(trace) - 1}")
        print("    Trace (rút gọn):")
        for act, st in trace:
            print(f"      {act:<28} pstate={st.pstate:<9} kEpoch={st.kEpoch} "
                  f"kFresh={int(st.kFresh)} outcome={st.outcome:<10} "
                  f"staleGrant={int(st.staleGrant)} "
                  f"unfreshGrant={int(st.unfreshGrant)} "
                  f"leak={int(st.leak)} revokeDone={int(st.revokeDone)}")


# =============================================================================
# ĐỐI CHIẾU VỚI CÀI ĐẶT PYTHON THẬT
# =============================================================================
def cross_check_implementation() -> bool:
    print("=" * 78)
    print("PHẦN 2: ĐỐI CHIẾU MÔ HÌNH VỚI CÀI ĐẶT PYTHON THẬT")
    print("=" * 78)
    ok = True

    from cryptography.hazmat.primitives.asymmetric import ed25519
    from signedandapend_events import PolicyLogService
    from anchorroot import EngramAnchorBridge, EpochAnchor
    from freshnesswindowandlatesttrustedroot import (
        KeyNodeTrustedRootOracle, StaleRootError, FailClosedFreshnessError,
        EquivocationError,
    )
    import time as _time

    auth_sk = ed25519.Ed25519PrivateKey.generate()
    bridge_sk = ed25519.Ed25519PrivateKey.generate()

    def report(tag, passed, detail=""):
        nonlocal ok
        ok = ok and passed
        print(f"  {'PASS' if passed else 'FAIL'} | {tag}" +
              (f" | {detail}" if detail else ""))

    # --- I1: Terminal State Invariant (signedandapend_events.py) ---
    svc = PolicyLogService(auth_sk)
    svc.init_policy("OBJ-MC")
    svc.transition_policy("OBJ-MC", "REVOKED")
    try:
        svc.transition_policy("OBJ-MC", "ACTIVE")
        report("I1 Terminal invariant (REVOKED->ACTIVE phải bị chặn)", False)
    except ValueError as e:
        report("I1 Terminal invariant (REVOKED->ACTIVE phải bị chặn)",
               "Terminal State Invariant" in str(e), str(e)[:70])

    # --- I3/I4: Stale root & Fail-closed (freshnesswindow...py) ---
    oracle = KeyNodeTrustedRootOracle(bridge_sk.public_key())
    try:
        oracle.resolve_fresh_policy("OBJ-MC", "00" * 32, svc.policy_records)
        report("I4 Fail-closed khi chưa sync root nào", False)
    except FailClosedFreshnessError:
        report("I4 Fail-closed khi chưa sync root nào", True)

    bridge = EngramAnchorBridge(bridge_sk)
    svc2 = PolicyLogService(auth_sk)
    svc2.init_policy("OBJ-MC2")
    a1 = bridge.anchor_epoch(1, svc2.mmr)
    oracle2 = KeyNodeTrustedRootOracle(bridge_sk.public_key())
    oracle2.sync_latest_trusted_root(a1)
    svc2.transition_policy("OBJ-MC2", "SUSPENDED")
    a2 = bridge.anchor_epoch(2, svc2.mmr)
    pr = bridge.get_consistency_proof(1, 2)
    oracle2.sync_latest_trusted_root(a2, pr)
    try:
        oracle2.resolve_fresh_policy("OBJ-MC2", a1.mmr_root, svc2.policy_records)
        report("I3 Stale root (root ep1 khi đã ep2) bị từ chối", False)
    except StaleRootError:
        report("I3 Stale root (root ep1 khi đã ep2) bị từ chối", True)

    # --- I2/Equivocation: 2 roots cùng epoch (attack corpus) ---
    fake = EpochAnchor(epoch=1, mmr_root="bb" * 32, tree_size=a1.tree_size,
                       peak_hashes=["bb" * 32], timestamp=a1.timestamp,
                       prev_anchor_hash="0" * 64, bridge_signature="")
    fake.bridge_signature = bridge_sk.sign(fake.canonical_bytes_for_signing()).hex()
    try:
        oracle2.sync_latest_trusted_root(fake)
        report("Equivocation (2 roots cùng epoch) bị phát hiện", False)
    except EquivocationError:
        report("Equivocation (2 roots cùng epoch) bị phát hiện", True)

    # --- I5: Concurrent access/revoke (test_adversarial_suite.py) ---
    proc = subprocess.run([sys.executable, "test_adversarial_suite.py"],
                          capture_output=True, text=True, timeout=60)
    passed = proc.returncode == 0 and "illegal_leak_after_revoke': 0" in proc.stdout
    detail = ""
    if not passed:
        detail = (proc.stdout + proc.stderr)[-200:]
    report("I5 Concurrent revoke: 7/7 tests, illegal_leak=0", passed, detail)

    return ok


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    print("=" * 78)
    print("PHẦN 1: MODEL CHECKER EXHAUSTIVE CHO EngramRevoke.tla")
    print(f"  MaxEpoch={MAX_EPOCH}, FreshnessWindow={FRESHNESS_WINDOW}")
    print("=" * 78)

    # --- (A) Mô hình đúng ---
    visited, edges, violations, parent, elapsed = model_check(mutant=False)
    print(f"\n[A] MÔ HÌNH ĐÚNG (Spec trong EngramRevoke.tla)")
    print(f"    Trạng thái duyệt được : {len(visited):,}")
    print(f"    Cạnh trạng thái        : {edges:,}")
    print(f"    Thời gian BFS          : {elapsed:.3f}s")
    inv_names = ["TypeOK", "I1TerminalStable", "I2EpochMonotonic",
                 "I3StaleRejected", "I4FailClosed", "I5NoLeak",
                 "RevokeLatched"]
    if violations:
        print(f"    KẾT QUẢ: FAIL - {len(violations)} invariant bị vi phạm!")
        print_counterexample(violations, parent)
        spec_ok = False
    else:
        print(f"    KẾT QUẢ: PASS - tất cả {len(inv_names)} invariant được giữ "
              f"trên TOÀN BỘ {len(visited):,} trạng thái khả thi.")
        print(f"      + {', '.join(inv_names)}")
        spec_ok = True

    # --- (B) Mutant: gỡ bỏ Terminal State Invariant (phải BẮT được lỗi) ---
    m_visited, m_edges, m_viol, m_parent, m_time = model_check(mutant=True)
    caught = {"I1TerminalStable", "I5NoLeak"} <= set(m_viol)
    print(f"\n[B] MUTANT TEST (gỡ bỏ Terminal State Invariant -> REVOKED->ACTIVE)")
    print(f"    Trạng thái duyệt được : {len(m_visited):,} ({m_time:.3f}s)")
    if m_viol:
        print(f"    KẾT QUẢ: model checker BẮT được vi phạm: "
              f"{', '.join(sorted(m_viol))}")
        print_counterexample(m_viol, m_parent)
    else:
        print("    KẾT QUẢ: FAIL - checker không bắt được lỗi (mô hình trống trơn)!")
    mut_ok = bool(m_viol) and caught

    # --- (C) Đối chiếu với code thật ---
    impl_ok = cross_check_implementation()

    # --- Tổng hợp ---
    print("\n" + "=" * 78)
    print("KẾT LUẬN")
    print("=" * 78)
    print(f"  Spec TLA+ giữ toàn bộ invariant        : {'PASS' if spec_ok else 'FAIL'}")
    print(f"  Mutant được phát hiện (I1/I5)          : {'PASS' if mut_ok else 'FAIL'}")
    print(f"  Đối chiếu với cài đặt Python           : {'PASS' if impl_ok else 'FAIL'}")
    all_ok = spec_ok and mut_ok and impl_ok
    print(f"  => TỔNG: {'PASS - MÔ HÌNH HỢP LỆ VÀ KHỚP VỚI CODE' if all_ok else 'FAIL'}")
    sys.exit(0 if all_ok else 1)
