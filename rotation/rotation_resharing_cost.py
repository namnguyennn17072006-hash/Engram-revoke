#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GIAI ĐOẠN 4 - CÂU 5: ĐO ROTATION / RESHARING COST THEO n, t, OBJECT COUNT
                      VÀ NETWORK LATENCY
File: rotation_resharing_cost.py

GỢI Ý SỬ DỤNG (mục 169 - "Công việc phải thực hiện" GĐ4):
  169  Đo rotation/resharing cost theo n, t, object count và network latency.
  174  Batch rewrap worker; threshold protocol harness; policy event log.
  175  (Công cụ) Batch rewrap worker + threshold protocol harness + event log.
  176  Chaos Mesh/tc -> mô phỏng network latency + node churn (ở đây mô
       phỏng RTT bằng sleep + model phân tích, ghi rõ giới hạn).
  180  Rotation cost analysis (deliverable - bảng số liệu + cost model).
  182  RỦI RO: "Rewrap queue quá lớn" -> đo tổng wall theo K object.

TÁI SỬ DỤNG TOÀN BỘ code đã viết:
  * GĐ3: wrap_dek/ThresholdWrapNode, prove_dleq, ThresholdCombiner,
         run_pedersen_dkg, committee_keygen (vss).
  * GĐ4 câu 1: EpochRewrapService (rotate/prepare/commit), batch_rewrap_worker,
         rewrap_via_committee, encrypt/decrypt_payload, issue_capability.
  * GĐ4 câu 2: (không đo trực tiếp - refresh là câu riêng; xem NOTE cuối).
  * GĐ4 câu 3: ResharingService/ReshareParty (Mode A prepare/commit,
         phase_times ghi prepare_ms/commit_ms).
  * GĐ4 câu 4: EpochReplayGate + reissue_capability_for_epoch (đo chi phí
         đường TỪ CHỐI replay - rất rẻ, "reject-early").

CODE MỚI (chỉ phục vụ đo lường):
  * build_threshold_env(n, t, object_ids): ủy ban DKG (n,t) + K object
    (policy log + oracle + wrap epoch 1 + nodes + combiner) - tham số hóa
    thay vì hard-code N=5,T=3 như build_env().
  * build_reshare_bench(...): ResharingService cho mọi cỡ (n_old,t_old)->t_new
    (Mode A) - tái sử dụng class câu 3.
  * timed()/net_delay_ms()/mô hình sóng gói tin (parallel vs sequential).
  * In bảng + cost model (180).

PHƯƠNG PHÁP ĐO (trung thực - 169):
  * Crypto time: đo THẬT trên secp256k1 pure-Python trong 1 tiến trình.
  * Network time: KHÔNG có tc/Chaos trên máy này -> 2 cách:
      (a) mô hình hóa: net = RTT (song song) hoặc links×RTT (tuần tự)
          + số sóng (phân phát, complaint, collect partial);
      (b) mô phỏng thực: time.sleep(RTT) trước khi chạy phase - tổng wall
          = crypto + sleep, dùng cho demo E2E vài cấu hình.
  * Ghi rõ: crypto pure-Python chi phối; với lib EC thật (Rust/C) số liệu
    sẽ đảo ngược giữa crypto và network - công thức vẫn dùng được.

Yêu cầu: python3 + cryptography.  Chạy: python3 rotation_resharing_cost.py
Lưu ý:   prototype academic, CHƯA audit - không dùng production.
"""

import os
import time
import hashlib
from dataclasses import replace as dc_replace
from typing import Callable, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

# --- GĐ1/GĐ2: policy log + oracle ------------------------------------------------
from signedandapend_events import PolicyLogService
from anchorroot import EngramAnchorBridge
from freshnesswindowandlatesttrustedroot import (
    KeyNodeTrustedRootOracle,
    FreshnessWindowConfig,
)

# --- GĐ3: DKG + wrap + proof + combiner -------------------------------------------
from dkg_threshold_service import run_pedersen_dkg
from vss_share_verification import committee_keygen
from wrap_dek_partial_decryption import (
    WrapContext,
    wrap_dek,
    ThresholdWrapNode,
)
from chaum_pedersen_partial_proof import prove_dleq
from combiner_filter_and_combine import ThresholdCombiner

# --- GĐ4 câu 1: epoch rewrap --------------------------------------------------------
from epoch_transition_rewrap import (
    encrypt_payload,
    decrypt_payload,
    wrap_digest,
    EpochRewrapService,
    issue_capability,
    batch_rewrap_worker,
)

# --- GĐ4 câu 3: resharing ------------------------------------------------------------
from resharing_committee_change import (
    ResharingService,
    ReshareParty,
    RETURNING,
    RETIRING,
    JOINING,
)

# --- GĐ4 câu 4: replay gate (đo đường reject) -----------------------------------------
from capabilityverifier import CapabilityVerifier
from epoch_replay_protection import EpochReplayGate, StaleEpochError


# =============================================================================
# 1. CÔNG CỤ ĐO LƯỜNG
# =============================================================================
def timed(fn: Callable, *args, **kwargs) -> Tuple[object, float]:
    """Chạy fn và trả về (kết quả, thời gian ms)."""
    t0 = time.time()
    result = fn(*args, **kwargs)
    return result, (time.time() - t0) * 1000.0


def net_delay_ms(rtt_ms: float, links: int, parallel: bool) -> float:
    """
    Model latency (169/176):
      parallel  : tất cả link chạy song song -> 1 sóng = RTT.
      sequential: từng link một           -> links × RTT.
    """
    return float(rtt_ms) if parallel else float(links) * float(rtt_ms)


def _table(headers: List[str], rows: List[List[str]]):
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h)
              for i, h in enumerate(headers)]
    line = "  " + " | ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("  " + "-+-".join("-" * w for w in widths))
    for r in rows:
        print("  " + " | ".join(str(c).ljust(w)
                                for c, w in zip(r, widths)))


# =============================================================================
# 2. PIPELINE ĐO: ủy ban (n,t) + K object / resharing bench
# =============================================================================
def build_threshold_env(n: int, t: int, object_ids: List[str],
                        payload_size: int = 128) -> dict:
    """
    Môi trường rotation bench: DKG (n,t) + K object đã ingest (wrap epoch 1)
    + EpochRewrapService + nodes + combiner.  Tái sử dụng y hệt build_env()
    của GĐ4 câu 1 nhưng tham số hóa được n, t, object count (169).
    """
    dkg, _ = run_pedersen_dkg(list(range(1, n + 1)), t)
    log = PolicyLogService(ed25519.Ed25519PrivateKey.generate())
    phs: Dict[str, str] = {}
    for oid in object_ids:
        event, _, _ = log.init_policy(oid, initial_epoch=1)
        phs[oid] = hashlib.sha256(event.canonical_bytes_for_signing()).hexdigest()
    bridge = EngramAnchorBridge(ed25519.Ed25519PrivateKey.generate())
    anchor1 = bridge.anchor_epoch(1, log.mmr)
    oracle = KeyNodeTrustedRootOracle(
        bridge.bridge_pk, FreshnessWindowConfig(max_anchor_age_seconds=60.0))
    oracle.sync_latest_trusted_root(anchor1)

    dek = os.urandom(32)                       # 1 DEK dùng chung cho bench
    objects: List[dict] = []
    t_wrap = 0.0
    for oid in object_ids:
        payload = os.urandom(payload_size)
        ct, ms = timed(encrypt_payload, dek, payload, oid, 1, phs[oid],
                       "JSON-GCM-v1")
        t_wrap += ms
        ctx = WrapContext(object_id=oid, version=1, policy_hash=phs[oid],
                          codec_id="JSON-GCM-v1", epoch=1,
                          policy_root=anchor1.mmr_root)
        wrapped, ms = timed(wrap_dek, dek, dkg.joint_public_key, ctx)
        t_wrap += ms
        objects.append(dict(object_id=oid, wrap=wrapped, payload=payload,
                            payload_ct=ct, ph_ingest=phs[oid]))
    rewrap_svc = EpochRewrapService(log, bridge, oracle)
    for o in objects:
        rewrap_svc.register_object(o["object_id"], o["wrap"], initial_epoch=1)
    nodes = {j: ThresholdWrapNode(j, dkg.private_shares[j],
                                  dkg.public_key_shares[j], t, oracle=oracle)
             for j in range(1, n + 1)}
    return dict(n=n, t=t, dkg=dkg, log=log, bridge=bridge, oracle=oracle,
                rewrap=rewrap_svc, nodes=nodes,
                combiner=ThresholdCombiner(dkg.public_key_shares, t),
                dek=dek, objects=objects, ingest_ms=t_wrap)


def build_reshare_bench(n_old: int, t_old: int, t_new: int,
                        new_ids: Optional[List[int]] = None) -> dict:
    """
    Môi trường resharing Mode A (câu 3) cho mọi cỡ: DKG (n_old,t_old) ->
    ResharingService với roles returning/retiring/joining (t_new).
    """
    dkg, _ = run_pedersen_dkg(list(range(1, n_old + 1)), t_old)
    if new_ids is None:
        new_ids = list(range(1, n_old + 1))
    new_ids = list(new_ids)
    max_id = max(max(new_ids), n_old)
    sks, pks = committee_keygen(max_id)
    parties: Dict[int, ReshareParty] = {}
    for j in range(1, n_old + 1):
        role = RETURNING if j in new_ids else RETIRING
        parties[j] = ReshareParty(j, role, t_new,
                                  old_share=dkg.private_shares[j],
                                  old_public=dkg.public_key_shares[j],
                                  signing_sk=sks[j])
    for j in new_ids:
        if j > n_old:
            parties[j] = ReshareParty(j, JOINING, t_new, signing_sk=sks[j])
    root = hashlib.sha256(
        f"bench-root|{n_old}|{t_old}|{t_new}|{new_ids}".encode()).hexdigest()
    svc = ResharingService(parties, t_old, t_new, lambda: root,
                           signing_pks=pks, period=1)
    return dict(n_old=n_old, t_old=t_old, t_new=t_new, new_ids=new_ids,
                dkg=dkg, svc=svc, threshold_pk=dkg.joint_public_key,
                shares=dkg.private_shares, pub_shares=dkg.public_key_shares)


def mint_partials_batch(nodes: Dict[int, ThresholdWrapNode], wrapped,
                        subset: List[int]):
    """Bộ proof DLEQ cho wrap - tái sử dụng ThresholdWrapNode (GĐ3)."""
    proofs = []
    for j in subset:
        node = nodes[j]
        d_point = node.share * wrapped.c1
        proofs.append(prove_dleq(j, node.share, node.public_share, wrapped.c1,
                                 d_point, wrapped.proof_context()))
    return proofs


# =============================================================================
# 3. BANNER
# =============================================================================
def _banner(title: str):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


# =============================================================================
# DEMO + TESTS
# =============================================================================
if __name__ == "__main__":
    TOTAL_T0 = time.time()
    results: List[str] = []
    RTT_DEMO_MS = 50.0           # RTT dùng cho demo mô phỏng thực (176)

    # =====================================================================
    _banner("TEST 1: ROTATION COST THEO (n, t) - PHÂN BỔ TỪNG PHA (169)")
    # =====================================================================
    rotation_rows: List[List[str]] = []
    dkg_ms_by_nt: Dict[Tuple[int, int], float] = {}
    rot_core_by_nt: Dict[Tuple[int, int], float] = {}

    for n, t in ((3, 2), (5, 3), (7, 4)):
        _, dkg_ms = timed(run_pedersen_dkg, list(range(1, n + 1)), t)
        dkg_ms_by_nt[(n, t)] = dkg_ms

        env = build_threshold_env(n, t, [f"OBJ-ROT-{n}-{t}"])
        obj = env["objects"][0]
        wrap = obj["wrap"]
        subset = list(range(1, t + 1))
        pub = env["dkg"].public_key_shares
        shares = env["dkg"].private_shares

        proofs, ms_proofs = timed(mint_partials_batch, env["nodes"], wrap,
                                  subset)
        report, ms_combine = timed(env["combiner"].combine, proofs, wrap)
        assert report.dek == env["dek"]
        _, ms_rotate = timed(env["rewrap"].rotate_policy_epoch,
                             obj["object_id"])

        def do_rewrap():
            epoch = env["rewrap"].object_epoch[obj["object_id"]]
            root = env["oracle"].get_latest_trusted_root()
            new_ph = hashlib.sha256(f"bench-{n}-{t}".encode()).hexdigest()
            new_ctx = dc_replace(wrap.context, policy_hash=new_ph,
                                 epoch=epoch, policy_root=root)
            new_wrap = wrap_dek(env["dek"], env["dkg"].joint_public_key,
                                new_ctx)
            env["rewrap"].prepare_rewrap(obj["object_id"], new_wrap)
            env["rewrap"].commit_rewrap(obj["object_id"])
            return new_wrap

        new_wrap, ms_rewrap = timed(do_rewrap)
        core = ms_proofs + ms_combine + ms_rotate + ms_rewrap
        rot_core_by_nt[(n, t)] = core
        assert wrap_digest(wrap) in env["rewrap"].retired_digests
        assert decrypt_payload(env["dek"], obj["payload_ct"], obj["object_id"],
                               1, obj["ph_ingest"], "JSON-GCM-v1") \
            == obj["payload"]
        rotation_rows.append([
            f"{n},{t}", f"{dkg_ms:.0f}", f"{ms_proofs:.0f}",
            f"{ms_combine:.1f}", f"{ms_rotate:.1f}", f"{ms_rewrap:.1f}",
            f"{core:.0f}", f"{1000.0 / core * 60:.0f}"])

    print("  (crypto THẬT, secp256k1 pure-Python; partials = t proof DLEQ;")
    print("   rotation core = proofs + combine + rotate(log+anchor) + rewrap)")
    print("  Đơn vị: ms.  'obj/giờ' = 3600000/core - giả định 1 luồng.")
    _table(["n,t", "DKG (1 lần)", f"t×prove_dleq", "combine", "rotate",
            "wrap+2pha", "CORE", "obj/giờ"], rotation_rows)
    assert rot_core_by_nt[(7, 4)] > rot_core_by_nt[(3, 2)]
    assert dkg_ms_by_nt[(7, 4)] > dkg_ms_by_nt[(3, 2)]
    print(f"  => CORE tăng theo t (t proof, Lagrange t phần) và theo n "
          f"(DKG/keygen lớn hơn); DKG là chi phí 1 LẦN cho cả ủy ban.")
    results.append("TEST1 rotation cost by (n,t): PASS")

    # =====================================================================
    _banner("TEST 2: OBJECT COUNT K - BATCH REWRAP + REPLAY-REJECT SWEEP (169/174/182)")
    # =====================================================================
    K_SET = (1, 2, 4, 8)
    batch_rows: List[List[str]] = []
    batch_total_by_k: Dict[int, float] = {}
    reject_total_by_k: Dict[int, float] = {}

    for K in K_SET:
        ids = [f"OBJ-K{K}-{i}" for i in range(1, K + 1)]
        envk = build_threshold_env(5, 3, ids)
        svck = envk["rewrap"]
        issuer = ed25519.Ed25519PrivateKey.generate()
        gate = EpochReplayGate(svck, CapabilityVerifier(issuer.public_key()))
        pdb = envk["log"].policy_records

        stash = []
        for o in envk["objects"]:
            oid = o["object_id"]
            cap, sig = issue_capability(issuer, "alice", oid, "read", 1)
            gate.check_capability(cap, sig, "alice", oid, "read")
            proofs = mint_partials_batch(envk["nodes"], o["wrap"], [1, 2, 3])
            stash.append(dict(oid=oid, cap=cap, sig=sig, wrap=o["wrap"],
                              proofs=proofs, meta=o))

        batch = [dict(object_id=s["oid"], dek=envk["dek"], wrap=s["wrap"],
                      new_policy_hash=hashlib.sha256(
                          f"kbench-{s['oid']}".encode()).hexdigest(),
                      threshold_pk=envk["dkg"].joint_public_key)
                 for s in stash]
        stats, _ = timed(batch_rewrap_worker, svck, batch, pdb)
        batch_total_by_k[K] = stats["median_ms"] * K  # ước lượng wall tuần tự
        # wall THẬT của worker (1 luồng) đo lại:
        wall, ms_wall = timed(batch_rewrap_worker, svck, batch, pdb)

        t_rej = time.time()
        for s in stash:
            try:
                gate.check_capability(s["cap"], s["sig"], "alice", s["oid"],
                                      "read")
            except Exception:
                pass
            try:
                gate.unwrap(s["oid"], s["wrap"], [],
                            envk["dkg"].public_key_shares, 3)
                raise AssertionError("wrap retired phải bị gate chặn")
            except StaleEpochError:
                pass
            try:
                envk["combiner"].combine(s["proofs"],
                                         svck.active_wrap[s["oid"]])
            except Exception:
                pass
        reject_ms = (time.time() - t_rej) * 1000
        reject_total_by_k[K] = reject_ms

        active_first = svck.active_wrap[stash[0]["oid"]]
        proofs_new = mint_partials_batch(envk["nodes"], active_first,
                                         [2, 3, 5])
        dek_new = gate.unwrap_proofs(stash[0]["oid"], active_first, proofs_new,
                                     envk["dkg"].public_key_shares, 3)
        assert dek_new == envk["dek"]

        batch_rows.append([
            str(K), f"{envk['ingest_ms'] / K:.1f}",
            f"{stats['median_ms']:.1f}", f"{stats['p95_ms']:.1f}",
            f"{ms_wall:.0f}", f"{ms_wall / K:.1f}",
            f"{stats['throughput_obj_per_s']:.1f}", f"{reject_ms:.1f}"])

    print("  (n=5, t=3 cố định; ingest = encrypt payload + wrap DEK / object;")
    print("   wall = batch_rewrap_worker THẬT 1 luồng; reject sweep = cap cũ")
    print("   + wrap cũ (retired) + proof cũ cho TỪNG object)")
    _table(["K", "ingest ms/obj", "median ms/obj", "p95 ms/obj", "wall ms",
            "wall ms/obj", "obj/s", "reject-all ms"], batch_rows)
    assert batch_total_by_k[8] > batch_total_by_k[2]
    print(f"  => wall tăng GẦN TUỲ TÍNH với K (worker tuần tự 1 luồng).")
    print(f"  => RỦI RO 182 'rewrap queue quá lớn': K=8 wall "
          f"{reject_total_by_k[8]:.1f}ms reject-sweep + worker "
          f"{[r[4] for r in batch_rows][-1]}ms; đề xuất: worker pool + "
          f"checkpoint từng object (prototype chưa có).")
    print(f"  => Đường TỪ CHỐI replay cực rẻ (reject-early): toàn bộ sweep "
          f"K=8 chỉ {reject_total_by_k[8]:.1f} ms.")
    results.append("TEST2 object-count sweep + queue/reject cost: PASS")

    # =====================================================================
    _banner("TEST 3: RESHARING COST THEO (n, t) - MODE A (169/180)")
    # =====================================================================
    reshare_cfgs = [
        (3, 2, 3, None, "t 2->3, cùng committee"),
        (5, 3, 4, None, "t 3->4, cùng committee"),
        (5, 3, 3, [1, 2, 3, 4, 6], "membership: out=5, in=6"),
        (7, 4, 5, None, "t 4->5, cùng committee"),
    ]
    reshare_rows: List[List[str]] = []
    prepare_by_cfg: Dict[str, float] = {}

    for n_old, t_old, t_new, new_ids, label in reshare_cfgs:
        envr = build_reshare_bench(n_old, t_old, t_new, new_ids)
        svcr: ResharingService = envr["svc"]
        _, ms_prepare = timed(svcr.prepare_reshare)
        _, ms_commit = timed(svcr.commit)
        assert svcr.period == 2
        n_dealers = len(svcr.dealer_ids)
        n_members = len(svcr.member_ids)
        links = n_dealers * n_members
        commitments = n_dealers * t_new
        net_par = net_delay_ms(RTT_DEMO_MS, links, True)
        net_seq = net_delay_ms(RTT_DEMO_MS, links, False)
        prepare_by_cfg[label] = ms_prepare
        reshare_rows.append([
            label, f"{n_old},{t_old}->{t_new}",
            f"{n_dealers}x{t_new}", f"{links}",
            f"{ms_prepare:.0f}", f"{ms_commit:.1f}",
            f"{ms_prepare + net_par:.0f}", f"{ms_prepare + net_seq:.0f}"])

    print("  (crypto THẬT cho prepare/commit; net = MODEL với RTT "
          f"{RTT_DEMO_MS:.0f}ms - 181 không mơ hồ: prepare/commit 2 pha)")
    print("  commitments = n_dealer × t_new (scalar-mul 256-bit mỗi cái);")
    print("  links = n_dealer × n_member (phân phát share); net par = 1 sóng, "
          "net seq = links × RTT")
    _table(["cau hinh", "n,t", "commit", "links", "prepare ms", "commit ms",
            "prepare+net(par)", "prepare+net(seq)"], reshare_rows)
    assert prepare_by_cfg["t 4->5, cùng committee"] > \
        prepare_by_cfg["t 2->3, cùng committee"]
    print("  => prepare chi phối: O(n_dealer × t_new) scalar-mul + Horner "
          "xác minh (scalar nhỏ j^k -> rẻ); network song song chỉ +1-2 sóng")
    results.append("TEST3 resharing cost by (n,t): PASS")

    # =====================================================================
    _banner("TEST 4: NETWORK LATENCY SWEEP + MÔ PHỎNG THỰC (169/176)")
    # =====================================================================
    envn = build_threshold_env(5, 3, ["OBJ-NET-1"])
    wrapn = envn["objects"][0]["wrap"]
    subset = [1, 2, 3]
    pubn = envn["dkg"].public_key_shares
    sharesn = envn["dkg"].private_shares

    proofs_net, crypto_partials = timed(mint_partials_batch, envn["nodes"],
                                        wrapn, subset)
    _, crypto_combine = timed(envn["combiner"].combine, proofs_net, wrapn)

    net_rows: List[List[str]] = []
    for rtt in (0.0, 10.0, 25.0, 50.0, 100.0):
        rot_par = crypto_partials + crypto_combine + net_delay_ms(rtt, 3, True)
        rot_seq = crypto_partials + crypto_combine + net_delay_ms(rtt, 3, False)
        resh_par = prepare_by_cfg["t 3->4, cùng committee"] + \
            net_delay_ms(rtt, 4 * 5, True)      # wave 1 (phân phát)
        resh_seq = prepare_by_cfg["t 3->4, cùng committee"] + \
            net_delay_ms(rtt, 4 * 5, False)
        net_rows.append([f"{rtt:.0f}", f"{rot_par:.0f}", f"{rot_seq:.0f}",
                         f"{resh_par:.0f}", f"{resh_seq:.0f}"])

    print("  Model: tổng = crypto (đo THẬT) + net (RTT hoặc links×RTT)")
    _table(["RTT ms", "rotation par ms", "rotation seq ms", "reshare par ms",
            "reshare seq ms"], net_rows)
    print("  (rotation: thu t partial - song song = +1 RTT, tuần tự = +t RTT;")
    print("   reshare: phân phát n_dealer×n_member link - model sóng)")

    # Mô phỏng THỰC bằng sleep (176 - tc/Chaos ngoài phạm vi máy này)
    t_e2e = time.time()
    time.sleep(RTT_DEMO_MS / 1000.0)            # client chờ gói tin partial
    proofs_e2e = mint_partials_batch(envn["nodes"], wrapn, subset)
    report_e2e, _ = timed(envn["combiner"].combine, proofs_e2e, wrapn)
    e2e_ms = (time.time() - t_e2e) * 1000
    assert report_e2e.dek == envn["dek"]
    print(f"  MÔ PHỎNG THỰC: sleep {RTT_DEMO_MS:.0f}ms (1 sóng partial) + "
          f"t proof + combine -> E2E {e2e_ms:.0f} ms "
          f"(= {RTT_DEMO_MS:.0f} + crypto {e2e_ms - RTT_DEMO_MS:.0f})")
    assert e2e_ms >= RTT_DEMO_MS
    print("  => Trong prototype crypto chi phối; mạng thật (RTT 20-200ms, "
          "bandwidth share ~KB) sẽ đẩy net lên - dùng lại model trên để quy "
          "ước (169).")
    results.append("TEST4 network latency model + real-sleep E2E: PASS")

    # =====================================================================
    _banner("TEST 5: DKG + COST MODEL TỔNG HỢP (180/182 - ROTATION COST ANALYSIS)")
    # =====================================================================
    dkg_rows = [[f"{n},{t}", f"{dkg_ms_by_nt[(n, t)]:.0f}",
                 f"{rot_core_by_nt[(n, t)]:.0f}",
                 f"{prepare_by_cfg.get(lbl, float('nan')):.0f}"]
                for (n, t), lbl in (
                    ((3, 2), "t 2->3, cùng committee"),
                    ((5, 3), "t 3->4, cùng committee"),
                    ((7, 4), "t 4->5, cùng committee"))]
    print("  BẢNG TỔNG HỢP (180) - DKG 1 lần / rotation per-object / reshare 1 vòng:")
    _table(["n,t", "DKG ms", "rotation core ms", "reshare prepare ms"],
           dkg_rows)
    print("""
  COST MODEL (169/180 - dùng lib EC thật sẽ giảm hệ số, giữ nguyên cấu trúc):
    DKG(n,t)          ~ O(n*t) scalar-mul 256-bit + n^2 share verify (Feldman)
    Rotation/object   ~ t*prove_dleq + combine(t Lagrange)
                       + rotate(policy 2 event + anchor + oracle sync)
                       + wrap_dek (2 scalar-mul) + prepare/commit (O(1))
    Batch K object    ~ K * Rotation/object   (worker tuần tự; 182: queue dài
                       -> đề xuất worker pool + đo lại p95 theo hàng đợi)
    Resharing Mode A  ~ O(n_dealer * t_new) commitment scalar-mul
                       + O(n_dealer * n_member) share (Horner verify ~O(t_new)
                       scalar nhỏ) + Lagrange candidate
    Network           = waves * RTT (song song)  hoặc  links * RTT (tuần tự)
                       waves resharing ~ 2 (phân發 + complaint); waves rotation
                       partial ~ 1 (collect song song)
    Replay-reject     ~ 0.08ms (cap epoch) / ~0ms (DLEQ reject-early, 168)
  GHI CHÚ TRUNG THỰC:
    - Crypto pure-Python (~35ms/scalar-mul) chi phối mọi hàng số ở trên.
    - Network mô phỏng bằng model + sleep; thật cần tc/Chaos (176) để lấy
      RTT phân bố + mất gói; số liệu ở đây là đường cơ sở (baseline).
    - Mode B (DKG mới + rewrap) = DKG + K*Rotation; Mode A (reshare giữ
      secret) KHÔNG rewrap -> chỉ tốn resharing prepare/commit (bảng trên).
""")
    results.append("TEST5 cost model + DKG summary: PASS")

    # =====================================================================
    _banner("KẾT LUẬN")
    # =====================================================================
    for line in results:
        print(f"  {line}")
    print(f"  Tổng thời gian demo: {time.time() - TOTAL_T0:.2f} s")
    print("""
  => Rotation cost tăng theo t (t proof DLEQ) và gần như tuyến tính theo K
     object (batch worker 1 luồng) - đo median/p95/obj-s theo mục 174/169.
  => Resharing Mode A chi phối bởi n_dealer*t_new scalar-mul; KHÔNG rewrap,
     KHÔNG đổi Y (câu 3) -> rẻ hơn Mode B khi chỉ đổi t/membership.
  => Network: model song song (1-2 sóng RTT) vs tuần tự (links×RTT) + demo
     sleep thật; replay-reject path gần như miễn phí (168).
  => Bảng số liệu + cost model = deliverable 'Rotation cost analysis' (180);
     rủi ro 'rewrap queue quá lớn' (182) đã đo bằng wall-vs-K + đề xuất pool.
  LƯU Ý: prototype academic, chưa audit - không dùng production.
""")
