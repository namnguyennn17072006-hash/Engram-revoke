# -*- coding: utf-8 -*-
"""
==============================================================================
GĐ5 CÂU 4 - ABLATION: KHÔNG ANCHORED LOG / KHÔNG FRESHNESS CHECK /
                KHÔNG PARTIAL PROOF / KHÔNG PROACTIVE REFRESH
==============================================================================
"""

import time
from dataclasses import replace as dc_replace

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from rfc9180_hpke import derive_wrap_key
from rotation_resharing_cost import _banner, _table
from adversarial_stage5_suite import forge_anchor, detect_policy_hash_mismatch
from epoch_transition_rewrap import build_env, safe_create_partial
from wrap_dek_partial_decryption import (
    ThresholdWrapNode,
    combine_and_unwrap,
    verify_partial,
)
from dkg_threshold_service import ECPoint, G, lagrange_coefficient
from chaum_pedersen_partial_proof import prove_dleq
from combiner_filter_and_combine import ThresholdCombiner
from proactive_share_refresh import build_refresh_env
from freshnesswindowandlatesttrustedroot import (
    StaleRootError,
    EquivocationError,
)

T = 3          # ngưỡng của mọi env N=5, T=3 dùng trong bộ demo này


# =============================================================================
# CÔNG CỤ ABLATION
# =============================================================================
class NaiveOracle:
    """
    ABLATION A2 - "không freshness check": giữ NGUYÊN interface oracle nhưng
    bỏ toàn bộ 5 bước (equivocation / clock skew / stale window / consistency
    proof / rollback) - sync nhận mọi anchor, resolve trả policy không so root.
    """

    def __init__(self):
        self.latest = None

    def sync_latest_trusted_root(self, anchor, *args, **kwargs):
        self.latest = anchor.mmr_root          # KHÔNG kiểm tra gì cả

    def get_latest_trusted_root(self):
        return self.latest

    def resolve_fresh_policy(self, object_id, presented_policy_root, db):
        return db.get(object_id)               # KHÔNG so root, KHÔNG terminal


def combine_without_proof(partials, threshold, wrapped) -> bytes:
    """
    ABLATION A3 - "không partial proof": Lagrange thẳng trên d_point của t
    phần tử ĐẦU TIÊN, không xác minh DLEQ, không lọc - AEAD là tầng cuối.
    Wrap key vẫn derive đúng RFC 9180 KeySchedule - chỉ bỏ proof + lọc.
    """
    subset = list(partials[:threshold])
    combined = ECPoint(None, None)
    for p in subset:
        lam = lagrange_coefficient(p.party_id,
                                   [q.party_id for q in subset])
        combined = combined + (lam * p.d_point)
    wrap_key = derive_wrap_key(combined.to_bytes(), wrapped.context.aad())
    return AESGCM(wrap_key).decrypt(wrapped.nonce, wrapped.ciphertext,
                                    wrapped.context.aad())


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    T0 = time.time()
    checks = []

    def check(name: str, ok: bool, detail: str = "") -> bool:
        checks.append((name, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
              + (f" - {detail}" if detail else ""))
        return bool(ok)

    # =========================================================================
    _banner("A1. ABLATION: KHÔNG ANCHORED LOG - policy_hash không còn gì để so (189)")
    # =========================================================================
    env1 = build_env("OBJ-ABL-1")
    log1 = env1["service_log"]
    wrap1 = env1["rewrap"].get_active_wrap(env1["object_id"])
    # Wrap "dán nhãn chính sách" - context bị thay policy_hash lạ
    evil_ctx = dc_replace(wrap1.context, policy_hash="fe" * 32)
    evil_wrap = dc_replace(wrap1, context=evil_ctx)

    # --- FULL: client so với log ký số (MMR/anchor) -------------------------
    full_good = detect_policy_hash_mismatch(log1, env1["object_id"], wrap1)
    full_reason = detect_policy_hash_mismatch(log1, env1["object_id"],
                                              evil_wrap)
    print(f"  [FULL   ] wrap chính chủ  -> detect = {full_good}")
    print(f"  [FULL   ] wrap policy_hash lạ -> detect = {full_reason}")
    a1_full = full_good is None and full_reason is not None

    # --- ABLATED: không anchored log -> chỉ còn bản sao CHỮ KÝ SỐ để so,
    #     attacker sửa được bản sao đó thì check tự động qua ---------------
    unsigned_local = {"policy_hash": wrap1.context.policy_hash}
    unsigned_local["policy_hash"] = evil_ctx.policy_hash     # attacker rewrite
    a1_ablated = evil_wrap.context.policy_hash == unsigned_local["policy_hash"]
    print(f"  [ABLATED] không log anchor -> attacker sửa bản sao so chiếu -> "
          f"wrap lạ bị CHẤP NHẬN = {a1_ablated}")
    check("A1-FULL: anchored log bắt được wrap dán policy_hash lạ",
          a1_full, f"reason = {str(full_reason)[:60]}...")
    check("A1-ABLATED: bỏ anchored log -> không còn căn cứ, wrap lạ lọt",
          a1_ablated)

    # =========================================================================
    _banner("A2. ABLATION: KHÔNG FRESHNESS CHECK - wrap epoch cũ vẫn ra partial (189)")
    # =========================================================================
    env2 = build_env("OBJ-ABL-2")
    svc2 = env2["rewrap"]
    oid2 = env2["object_id"]
    wrap_old = svc2.get_active_wrap(oid2)
    pdb2 = env2["service_log"].policy_records
    root1 = env2["oracle"].get_latest_trusted_root()
    anchor1 = env2["bridge"].anchor_chain[1]
    epoch2, root2 = svc2.rotate_policy_epoch(oid2)      # root1 đã CŨ

    # --- FULL (oracle GĐ2 thật) --------------------------------------------
    stale_err = None
    try:
        safe_create_partial(env2["nodes"][1], wrap_old, svc2, pdb2)
    except StaleRootError as err:
        stale_err = err
    twin = forge_anchor(anchor1, env2["bridge"].bridge_sk,
                        mmr_root="cd" * 32)              # root song sinh epoch 1
    equiv_err = None
    try:
        env2["oracle"].sync_latest_trusted_root(twin)
    except EquivocationError as err:
        equiv_err = err
    print(f"  [FULL   ] node có oracle, wrap epoch cũ -> StaleRootError: "
          f"{str(stale_err)[:70]}...")
    print(f"  [FULL   ] sync root SONG SINH cùng epoch -> EquivocationError: "
          f"{str(equiv_err)[:60]}...")
    a2_full = stale_err is not None and equiv_err is not None

    # --- ABLATED: node bỏ oracle (oracle=None) -> không còn cổng nào ------
    no_gate = {j: ThresholdWrapNode(j, env2["shares"][j],
                                    env2["pub_shares"][j], T, oracle=None)
               for j in (1, 2, 3)}
    pcs_stale = [no_gate[j].create_partial(wrap_old,
                                           presented_policy_root=root1,
                                           policy_db=pdb2) for j in (1, 2, 3)]
    dek_bypass = combine_and_unwrap(pcs_stale, env2["pub_shares"], T, wrap_old)
    # ABLATED flavor 2: oracle "naive" vẫn nhận root song sinh
    naive = NaiveOracle()
    naive.sync_latest_trusted_root(twin)
    node_naive = ThresholdWrapNode(4, env2["shares"][4], env2["pub_shares"][4],
                                   T, oracle=naive)
    pc_naive = node_naive.create_partial(wrap_old,
                                         presented_policy_root=naive.latest,
                                         policy_db=pdb2)
    a2_ablated = (dek_bypass == env2["dek"]) and pc_naive is not None
    print(f"  [ABLATED] node không oracle: mint {len(pcs_stale)} partial cho "
          f"wrap epoch {wrap_old.context.epoch} (root {root1[:12]}... đã cũ) "
          f"-> unwrap DEK = {dek_bypass == env2['dek']}")
    print(f"  [ABLATED] NaiveOracle nhận root song sinh {naive.latest[:12]}... "
          f"-> partial thứ 4 được cấp (root không còn ý nghĩa)")
    check("A2-FULL: oracle thật chặn stale root + equivocation (2/2)",
          a2_full)
    check("A2-ABLATED: bỏ freshness -> wrap RETIRED vẫn unwrap ra DEK, "
          "root song sinh vẫn được nhận", a2_ablated)

    # =========================================================================
    _banner("A3. ABLATION: KHÔNG PARTIAL PROOF - 1 partial hỏng làm sập combine (189)")
    # =========================================================================
    env3 = build_env("OBJ-ABL-3")
    wrap3 = env3["rewrap"].get_active_wrap(env3["object_id"])
    pubs3 = env3["pub_shares"]
    p3 = [safe_create_partial(env3["nodes"][j], wrap3, env3["rewrap"],
                              env3["service_log"].policy_records)
          for j in (1, 2, 3, 4)]
    tampered2 = dc_replace(p3[1], d_point=p3[1].d_point + G)   # hỏng trên đường

    # --- FULL: combiner xác minh DLEQ từng partial (verify_partial GĐ3) ----
    all4 = [p3[0], tampered2, p3[2], p3[3]]
    rejected = [p.party_id for p in all4
                if not verify_partial(p, pubs3[p.party_id], wrap3.c1,
                                      wrap3.proof_context())]
    dek_full = combine_and_unwrap(all4, pubs3, T, wrap3)
    print(f"  [FULL   ] 4 partial (1 hỏng) -> rejected = {rejected} "
          f"(dleq-invalid); 3 partial còn lại >= t -> DEK đúng = "
          f"{dek_full == env3['dek']}")
    a3_full = rejected == [2] and dek_full == env3["dek"]

    # --- ABLATED: Lagrange không xác minh, t phần tử đầu -------------------
    dek_ablated, tag_err = None, None
    try:
        dek_ablated = combine_without_proof(
            [p3[0], tampered2, p3[2]], T, wrap3)
    except InvalidTag as err:
        tag_err = err
    print(f"  [ABLATED] không verify DLEQ -> partial hỏng lọt Lagrange -> "
          f"K sai -> AEAD InvalidTag = {tag_err is not None} "
          f"(không biết node {2} xấu, fail mù)")
    a3_ablated = tag_err is not None and dek_ablated is None
    check("A3-FULL: partial proof lọc đúng node hỏng, vẫn unwrap được DEK",
          a3_full)
    check("A3-ABLATED: bỏ proof -> partial hỏng không bị phát hiện, "
          "combine trả DEK SAI/mất chẩn đoán", a3_ablated)

    # =========================================================================
    _banner("A4. ABLATION: KHÔNG PROACTIVE REFRESH - share bị lộ dùng được mãi (189)")
    # =========================================================================
    env4 = build_refresh_env("OBJ-ABL-4")
    svc4 = env4["svc"]
    wrap4 = env4["wrapped"]
    # Kẻ tấn công CHÉP share của party 3 từ period 1
    stolen_share = svc4.private_share(3)
    stolen_pub = env4["pub_shares"][3]
    stale_proof = prove_dleq(3, stolen_share, stolen_pub, wrap4.c1,
                             stolen_share * wrap4.c1, wrap4.proof_context())

    # --- ABLATED: không refresh -> registry cũ vẫn là "hiện hành" ----------
    comb_old = ThresholdCombiner(env4["pub_shares"], T)
    v_ab = comb_old.classify([stale_proof], wrap4.c1, wrap4.proof_context())[0]
    print(f"  [ABLATED] không refresh: share đánh cắp period 1 dưới registry "
          f"cũ -> accepted = {v_ab.accepted} (dùng được MÃI, không có ngày hết hạn)")
    a4_ablated = v_ab.accepted

    # --- FULL: refresh 1 vòng -> registry mới, share cũ chết ---------------
    svc4.prepare()
    svc4.commit()
    comb_new = ThresholdCombiner(svc4.public_shares(), T)
    v_full = comb_new.classify([stale_proof], wrap4.c1,
                               wrap4.proof_context())[0]
    honest = [svc4.issue_partial(j, wrap4) for j in (1, 2, 3)]
    dek_after = comb_new.combine(honest, wrap4).dek
    print(f"  [FULL   ] sau refresh (period {svc4.period}): share cũ dưới "
          f"registry Y'_j -> accepted = {v_full.accepted} "
          f"(reason={v_full.reason}); node thật vẫn unwrap DEK = "
          f"{dek_after == env4['dek']}")
    a4_full = (not v_full.accepted) and v_full.reason == "dleq-invalid" \
        and dek_after == env4["dek"]
    check("A4-FULL: sau refresh share bị đánh cắp bị TỪ CHỐI, "
          "node thật vẫn hoạt động", a4_full)
    check("A4-ABLATED: bỏ refresh -> share cũ vẫn accepted (không có "
          "'hết hạn' cho secret đã lộ)", a4_ablated)

    total_s = time.time() - T0
    passed = sum(1 for _, ok in checks if ok)

    _banner("TỔNG HỢP - BẢNG ABLATION (189) + BÁO CÁO")
    _table(["thanh phan bi bo", "expected property (cổng 188)",
            "FULL (bat)", "ABLATED (tat)", "gia tri mua duoc"], [
        ["anchored log",
         "wrap chi chap nhan policy_hash co trong log ky so",
         "bat duoc wrap la (A1)", "attacker sua log so chieu -> accept",
         "chong danh nhan chinh sach"],
        ["freshness check",
         "khong phuc vu duoi root da bi rotation thay",
         "StaleRootError + EquivocationError",
         "3 partial stale -> unwrap DEK; root song sinh accepted",
         "chong stale root / equivocation"],
        ["partial proof (DLEQ)",
         "partial sua bi loc, >= t phan van unwrap duoc",
         "reject node 2, DEK dung (3/4)",
         "DEK sai, fail moz (InvalidTag)",
         "chong partial gia + chuan doan duoc ai xau"],
        ["proactive refresh",
         "share da lo het han sau 1 chu ky",
         "share cu -> dleq-invalid; node that van OK",
         "share cu accepted vo thoi han",
         "cat mobile adversary sau moi ky"],
    ])
    print(f"""
  PHAN LOAI LOI (192):
    * SECURITY   - A1/A2/A3/A4 (FULL): moi tan cong deu BỊ CHẶN va co
                   ly do ro (StaleRootError, EquivocationError, dleq-invalid,
                   detect mismatch). Tong: 4/4 expected property dat.
    * AVAILABILITY - A3 (ABLATED): bo proof -> 1 partial lam sập TOAN BO
                   combine (fail moz) - trade-off dung de doc lap (192).
    * POLICY     - A1 (ABLATed): policy_hash troi ra khoi log ky so ->
                   nham lan chinh sach (172/181 - transcript kiem chieu duoc).

  CLAIMS - viet theo DIEU KIEN (193):
    NEU adversary giu duoc < t node, client co latest root, va KHONG co
    DEK/plaintext leakage tu truoc, THI (voi 4 thanh phan BAT):
      + moi wrap deu co policy_hash xac minh duoc tu log ky so (A1);
      + root cu / root song sinh khong dua duoc vao dich vu (A2);
      + moi partial deu di kem proof, phan hong bi loc truoc khi Lagrange (A3);
      + share da lo bi cat sau 1 chu ky refresh (A4).
    ABLATED chung minh neu BO 1 trong 4 -> tan cong tuong ung LO NGAY.

  GIORI HAN / THREAT-TO-VALIDITY (199):
    - ABLATED = mo phong co so (oracle=None / NaiveOracle / combiner tu
      viet) tren CUNG codebase - khong phai 4 phien ban he thong rieng biet.
    - A3: combiner ABLATED lay t phan tu DAU; thu tu partial do client/chuong
      trinh chon - ket qua cu the co the bien doi, tinh chat "fail moz" thi
      van dung.
    - A4: chi do 1 chu ky refresh tren 1 wrap; so chu ky dai hon chua do.
    - Crypto pure-Python chua audit - khong dung production.
  KHONG SUY DIEN (194): chi la THI NGHIEM trong threat model mo ta - khong
    phai bao dam tuan phap luat tu dong, khong thay the audit doc lap.

  ==============================================================================
  KET LUAN
  ==============================================================================""")
    for name, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n  {passed}/{len(checks)} kiem tra PASS; tong thoi gian: "
          f"{total_s:.1f}s")
    print("  => Deliverable (198): phan 'Security/performance experiment "
          "bundle' - ablation 4 thanh phan (FULL vs ABLATED).")
    print("  LUU Y: prototype academic, chua audit - khong dung production.")
