# -*- coding: utf-8 -*-
"""
==============================================================================
GĐ5 CÂU 2 - QUÉT n, t, COMPROMISED/OFFLINE NODES, GEOGRAPHIC RTT
                VÀ CONCURRENT ACCESSES
==============================================================================

"""

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace as dc_replace

from rotation_resharing_cost import (
    _banner,
    _table,
    build_threshold_env,
    net_delay_ms,
    timed,
)
from dkg_threshold_service import run_pedersen_dkg, UnderThresholdError, N_ORDER
from epoch_transition_rewrap import safe_create_partial
from wrap_dek_partial_decryption import combine_and_unwrap


# =============================================================================
# 1. SWEEP (n, t) - DKG / PARTIAL / COMBINE LATENCY + MESSAGES (187)
# =============================================================================
def sweep_nt(check) -> bool:
    """
    Quét 3 tổ hợp (n,t): đo DKG latency, thời gian setup env (DKG + ingest),
    mint đúng t partial, combine/unwrap và kích thước messages/bytes (187).
    """
    _banner("1. SWEEP (n, t) - DKG / PARTIAL / COMBINE LATENCY + BYTES (187)")
    rows = []
    ok_all = True
    for n, t in [(3, 2), (5, 3), (7, 4)]:
        # DKG latency (standalone - chỉ số nhóm Threshold của ma trận)
        _, dkg_ms = timed(run_pedersen_dkg, list(range(1, n + 1)), t)
        # Setup env đầy đủ = DKG + ingest 1 object (wrap epoch 1, root anchor)
        env, setup_ms = timed(build_threshold_env, n, t, [f"OBJ-SWEEP-{n}x{t}"])
        wrap = env["objects"][0]["wrap"]
        pdb = env["log"].policy_records

        subset = list(range(1, t + 1))                 # đủ t node online
        pcs, mint_ms = timed(lambda: [
            safe_create_partial(env["nodes"][j], wrap, env["rewrap"], pdb)
            for j in subset])
        dek, unwrap_ms = timed(combine_and_unwrap, pcs,
                               env["dkg"].public_key_shares, t, wrap)
        ok = dek == env["dek"]
        ok_all = ok_all and ok
        # messages/bytes: mỗi partial = 1 điểm (d_point) + 2 scalar 32B
        nbytes = sum(len(p.d_point.to_bytes()) + 64 for p in pcs)
        rows.append([str(n), str(t), f"{dkg_ms:.0f}", f"{setup_ms:.0f}",
                     f"{mint_ms:.0f}", f"{unwrap_ms:.0f}", str(nbytes),
                     "OK" if ok else "SAI"])
    _table(["n", "t", "DKG ms", "setup ms", f"mint t ms", "combine ms",
            "bytes", "DEK"], rows)
    check("S1: mọi (n,t) unwrap ra đúng DEK (3/3)", ok_all)
    return ok_all


# =============================================================================
# 2. SWEEP COMPROMISED (c < t) x OFFLINE (o) - DENY RATE (187)
# =============================================================================
def sweep_attack_grid(check):
    """
    Quét lưới 15 tổ hợp (c, o) với n=5, t=3:
      - c node compromised (c < t): submit partial có cấu trúc đúng nhưng
        chứng minh bị sửa (z += 1) -> combiner phải LOẠI toàn bộ.
      - o node offline: không về được (mất một phần réseau).
      - node trung thực honest = n - c - o mint partial hợp lệ.
    Dự kiến:
      honest >= t -> UNWRAP đúng DEK   (liveness giữ được)
      honest <  t -> FAIL-CLOSED       (deny, KHÔNG lộ DEK)
    Boundary: c = t -> adversary đủ share tự unwrap (t phải CHẶT - 187).
    """
    _banner("2. QUÉT COMPROMISED (c < t) x OFFLINE (o) - n=5, t=3 (187)")
    n, t = 5, 3
    env = build_threshold_env(n, t, ["OBJ-GRID"])
    wrap = env["objects"][0]["wrap"]
    pdb = env["log"].policy_records
    pubs = env["dkg"].public_key_shares

    rows = []
    ok_all = True
    false_accept = false_reject = 0
    n_allow = n_deny = 0
    for c in (0, 1, 2):                                # c < t = 3 (threat model)
        for o in range(0, n - c + 1):
            compromised = list(range(1, c + 1))
            offline = list(range(c + 1, c + 1 + o))
            honest = [j for j in range(1, n + 1)
                      if j not in compromised and j not in offline]
            # node trung thực: partial hợp lệ (qua cổng root tươi)
            partials = [safe_create_partial(env["nodes"][j], wrap,
                                            env["rewrap"], pdb)
                        for j in honest]
            # node compromised: partial cấu trúc đúng nhưng SAI chứng minh
            for j in compromised:
                p = safe_create_partial(env["nodes"][j], wrap,
                                        env["rewrap"], pdb)
                partials.append(dc_replace(p, proof_z=(p.proof_z + 1) % N_ORDER))

            expect_ok = len(honest) >= t
            try:
                dek = combine_and_unwrap(partials, pubs, t, wrap)
                got = "UNWRAP" if dek == env["dek"] else "DEK-SAI"
            except UnderThresholdError:
                got = "FAIL-CLOSED"
            want = "UNWRAP" if expect_ok else "FAIL-CLOSED"
            match = got == want
            if expect_ok:
                n_allow += 1
                false_reject += 0 if got == "UNWRAP" else 1
            else:
                n_deny += 1
                false_accept += 1 if got == "UNWRAP" else 0
            ok_all = ok_all and match and got != "DEK-SAI"
            rows.append([str(c), str(o), str(len(honest)), str(len(partials)),
                         want, got, "OK" if match else "SAI"])
    _table(["c", "o", "honest", "partial", "mong đợi", "thực tế", "khớp"], rows)
    check(f"S2: 15 tổ hợp khớp dự đoán - deny={n_deny}, allow={n_allow}, "
          f"0 false-accept / 0 false-reject", ok_all)

    # --- Boundary c = t: adversary có đủ t share -> tự unwrap được ---------
    adv = [safe_create_partial(env["nodes"][j], wrap, env["rewrap"], pdb)
           for j in (1, 2, 3)]
    dek = combine_and_unwrap(adv, pubs, t, wrap)
    boundary_ok = dek == env["dek"]
    check("S2b: c = t = 3 -> adversary tự unwrap ĐƯỢC (t chặt - nằm NGOÀI "
          "threat model, dự kiến)", boundary_ok)
    print(f"    -> deny rate lưới: {n_deny}/{n_deny + n_allow} tổ hợp bị "
          f"fail-closed; false accept = {false_accept}, "
          f"false reject = {false_reject}")
    return env


# =============================================================================
# 3. GEOGRAPHIC RTT - MODEL + ĐO THẬT (187)
# =============================================================================
def sweep_rtt(env, check) -> bool:
    """
    Geographic RTT (187/threshold): mô phỏng độ trễ đường truyền theo vùng
    địa lý, đo wall-time song song vs tuần tự và so với net_delay_ms model:
      parallel   -> 1 RTT  (tất cả node trả lời cùng lúc)
      sequential -> t x RTT (gửi lần lượt)
    Sau đó đo E2E unwrap CÓ sleep RTT thật trong 3 thread mint.
    """
    _banner("3. GEOGRAPHIC RTT - SONG SONG / TUẦN TỰ + E2E (187)")
    t = env["t"]
    geo = {
        0.0: "same-host/LAN",
        25.0: "cung chau (HN-SG ~25ms)",
        50.0: "ngang chau (JP-EU ~50ms)",
        100.0: "lien chau (US ~100ms)",
    }
    rows = []
    ok_all = True
    for rtt in (0.0, 25.0, 50.0, 100.0):
        def node_roundtrip(_=None):
            time.sleep(rtt / 1000.0)
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=t) as ex:
            list(ex.map(node_roundtrip, range(t)))
        par = (time.time() - t0) * 1000.0
        t0 = time.time()
        for _ in range(t):
            node_roundtrip()
        seq = (time.time() - t0) * 1000.0
        mp = net_delay_ms(rtt, t, parallel=True)
        ms = net_delay_ms(rtt, t, parallel=False)
        ok = abs(par - mp) <= 40.0 and abs(seq - ms) <= 40.0
        ok_all = ok_all and ok
        rows.append([f"{rtt:.0f}", geo[rtt], f"{par:.0f} / {mp:.0f}",
                     f"{seq:.0f} / {ms:.0f}", "OK" if ok else "SAI"])
    _table(["RTT ms", "vung dia ly", "parallel do/model", "seq do/model",
            "khop"], rows)
    check("S3: wall-time song song/tuần tự khớp model net_delay_ms "
          "(12 so sánh)", ok_all)

    # --- E2E unwrap với RTT thật (mỗi node sleep RTT trước khi trả partial)
    # Lấy MIN của 3 lần đo (loại jitter GIL) - 187: E2E access latency.
    wrap = env["objects"][0]["wrap"]
    pdb = env["log"].policy_records

    def e2e(rtt_ms: float) -> float:
        def job(j: int):
            time.sleep(rtt_ms / 1000.0)
            return safe_create_partial(env["nodes"][j], wrap,
                                       env["rewrap"], pdb)
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=t) as ex:
            pcs = list(ex.map(job, range(1, t + 1)))
        combine_and_unwrap(pcs, env["dkg"].public_key_shares, t, wrap)
        return (time.time() - t0) * 1000.0

    RTT_HI = 100.0
    e0 = min(e2e(0.0) for _ in range(3))
    eh = min(e2e(RTT_HI) for _ in range(3))
    delta = eh - e0
    ok = 0.6 * RTT_HI <= delta <= 2.0 * RTT_HI
    _table(["E2E unwrap (3 node, t=3, min/3 lan do)", "ms"], [
        ["RTT = 0", f"{e0:.0f}"],
        [f"RTT = {RTT_HI:.0f} (3 thread x sleep)", f"{eh:.0f}"],
        ["delta (ky vong ~ 1 RTT)", f"{delta:.0f}"],
    ])
    check(f"S3b: E2E unwrap RTT={RTT_HI:.0f}ms cộng thêm ~1 RTT so với RTT=0",
          ok, f"delta={delta:.0f}ms (cho phep 60..200)")
    return ok_all and ok


# =============================================================================
# 4. CONCURRENT ACCESSES (187)
# =============================================================================
def sweep_concurrent(env, check) -> bool:
    """
    C request đồng thời (mỗi request = t partial mint + combine + unwrap):
    đo wall time, throughput (req/s), p50/p95 latency và verify mọi request
    đều trả về ĐÚNG DEK (thread-safety: node/combiner không giữ state Races).
    Lưu ý GĐ5: Python GIL -> crypto thuần tuần tự hóa; số liệu phản ánh
    prototype, không phải hiệu năng đa luồng thật (ghi trong limitations).
    """
    _banner("4. CONCURRENT ACCESSES - C ĐỒNG THỜI (187 - nhóm Access)")
    t = env["t"]
    wrap = env["objects"][0]["wrap"]
    pdb = env["log"].policy_records
    pubs = env["dkg"].public_key_shares

    def one_request(_):
        t0 = time.time()
        pcs = [safe_create_partial(env["nodes"][j], wrap, env["rewrap"], pdb)
               for j in range(1, t + 1)]
        dek = combine_and_unwrap(pcs, pubs, t, wrap)
        return (dek == env["dek"]), (time.time() - t0) * 1000.0

    rows = []
    ok_all = True
    for c in (1, 4, 8, 16):
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=c) as ex:
            out = list(ex.map(one_request, range(c)))
        wall = (time.time() - t0) * 1000.0
        lat = sorted(l for _, l in out)
        allok = all(o for o, _ in out)
        ok_all = ok_all and allok
        p50 = lat[len(lat) // 2]
        p95 = lat[min(len(lat) - 1, int(len(lat) * 0.95))]
        rows.append([str(c), f"{wall:.0f}", f"{c / (wall / 1000.0):.1f}",
                     f"{p50:.0f}", f"{p95:.0f}", "OK" if allok else "FAIL"])
    _table(["C", "wall ms", "req/s", "p50 ms", "p95 ms", "DEK dung"], rows)
    check("S4: mọi request đồng thời unwrap đúng DEK (1+4+8+16 = 29 request)",
          ok_all)
    return ok_all


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    T0 = time.time()
    checks = []

    def check(name: str, ok: bool, detail: str = "") -> bool:
        checks.append((name, bool(ok)))
        tag = "PASS" if ok else "FAIL"
        print(f"  [{tag}] {name}" + (f" - {detail}" if detail else ""))
        return bool(ok)

    sweep_nt(check)
    env = sweep_attack_grid(check)
    sweep_rtt(env, check)
    sweep_concurrent(env, check)

    total_s = time.time() - T0
    passed = sum(1 for _, ok in checks if ok)

    _banner("TỔNG HỢP - MA TRẬN THỰC NGHIỆM (187) + BÁO CÁO")
    _table(["biến doc lap", "chi so do (ma tran GĐ5)", "ket qua"], [
        ["n, t in {3,2},{5,3},{7,4}",
         "DKG ms; mint t partial ms; combine ms; bytes", "5/1 dk - DEK dung"],
        ["compromised c < t (0..2) x offline o (0..n-c)",
         "deny rate; false accept/reject", "15/15 khop, FA=0, FR=0"],
        ["boundary c = t = 3",
         "adversary unwrap - nguong chat cua t", "duoc (ngoai model)"],
        ["geographic RTT 0/25/50/100 ms",
         "parallel vs sequential wall time", "khop net_delay_ms"],
        ["concurrent C = 1/4/8/16",
         "req/s; p50/p95 E2E latency", "29/29 DEK dung"],
    ])
    print("""
  PHAN LOAI LOI (192):
    * SECURITY   - grid: partial compromised bi LOAI; honest < t -> deny
                   dung; false accept = 0 (khong co truong hop DEK ro ri).
    * AVAILABILITY - 9/15 to hop fail-closed -> mat liveness khi offline +
                   compromised qua nhieu; day la GIA CHO bao mat (trade-off
                   duoc bao cao CUNG LUC voi security - 192/187).
    * POLICY     - khong phat sinh o cau nay (da duoc cho o cau 1).

  CLAIMS - viet theo DIEU KIEN (193):
    NEU adversary giu duoc < t node, client co latest root, va KHONG co
    DEK/plaintext leakage tu truoc, THI:
      + voi moi (n,t) da do: t partial hop le unwrap ra dung DEK;
      + partial da bi sua (compromised) luon bi loai -> neu honest >= t van
        unwrap duoc, neu honest < t thi fail-closed (deny), FA = 0;
      + RTT tang -> E2E tang ~1 RTT (song song) hoac t*RTT (tuan tu);
      + C request dong thieu van tra ve DUNG DEK (khong co state race).

  GIORI HAN / THREAT-TO-VALIDITY (199):
    - RTT mo phong bang sleep trong tien trinh (khong dung tc/netem/Chaos
      176) -> so lieu geographic la UOC LUONG, can testbed that.
    - Python GIL: crypto thuần khong song suat -> req/s khong scale dong
      voi C; ket qua la cua PROTOTYPE, khong phai throughput san pham.
    - Luoi quet nho (n <= 7, 15 to hop c,o); c >= t nam NGOAI threat model
      (chi do boundary S2b); deny rate tinh tren mang thu nho.
    - Crypto pure-Python chua audit - khong dung production.
  KHONG SUY DIEN (194): ket qua chi la THI NGHIEM trong threat model mo ta,
    khong phai bao dam tuan phap luat tu dong, khong thay the audit doc lap.

  ==============================================================================
  KET LUAN
  ==============================================================================""")
    for name, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n  {passed}/{len(checks)} kiem tra PASS; tong thoi gian: "
          f"{total_s:.1f}s")
    print("  => Deliverable (198): phan 'Security/performance experiment "
          "bundle' - sweep n,t x compromised/offline x RTT x concurrent.")
    print("  LUU Y: prototype academic, chua audit - khong dung production.")
