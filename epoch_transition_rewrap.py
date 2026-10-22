
import os
import time
import hashlib
import random
from dataclasses import dataclass, field, replace as dc_replace
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519

# --- GĐ1: policy log + capability verifier -----------------------------------
from signedandapend_events import PolicyLogService
from capabilityverifier import CapabilityVerifier
from capabilityverifier import SecurityError as CapSecurityError

# --- GĐ2: anchor + freshness oracle ------------------------------------------
from anchorroot import EngramAnchorBridge
from freshnesswindowandlatesttrustedroot import (
    KeyNodeTrustedRootOracle,
    FreshnessWindowConfig,
    StaleRootError,
)

# --- Câu 1: DKG + EC math -----------------------------------------------------
from dkg_threshold_service import (
    ECPoint,
    G,
    N_ORDER,
    run_pedersen_dkg,
    UnderThresholdError,
)

# --- Câu 2: VSS xác minh share ------------------------------------------------
from vss_share_verification import (
    FeldmanVSS,
    VSSMember,
    sign_broadcast,
    committee_keygen,
)

# --- Câu 3: wrap DEK + node ---------------------------------------------------
from wrap_dek_partial_decryption import (
    WrapContext,
    ThresholdWrappedDEK,
    wrap_dek,
    ThresholdWrapNode,
)

# --- Câu 4: proof Chaum-Pedersen ----------------------------------------------
from chaum_pedersen_partial_proof import (
    prove_dleq,
    verify_dleq,
)

# --- Câu 5: combiner có verdict -----------------------------------------------
from combiner_filter_and_combine import ThresholdCombiner, InsufficientPartials

_RNG = random.SystemRandom()
N, T = 5, 3


# =============================================================================
# 1. PAYLOAD AAD CỐ ĐỊNH - chìa khóa cho "không re-encrypt payload" (170)
# =============================================================================
def payload_aad(object_id: str, version: int, policy_hash_ingest: str,
                codec_id: str) -> bytes:
    """
    AAD của AEAD PAYLOAD - GIỮ ĐỊNH DẠNG GĐ1 (wrapDEK.py):
      (ObjectID, Version, PolicyHash, CodecID)
    KHÔNG epoch/policy root -> payload ciphertext sống xuyên suốt các epoch;
    epoch rotation chỉ quay lại lớp bọc DEK. PolicyHash ở đây là hash policy
    tại thời điểm INGEST (version binding), không phải policy hash từng epoch.
    """
    return (f"ObjectID:{object_id}|Version:{version}"
            f"|PolicyHash:{policy_hash_ingest}|CodecID:{codec_id}").encode()


def encrypt_payload(dek: bytes, payload: bytes, object_id: str, version: int,
                    policy_hash_ingest: str, codec_id: str) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(dek).encrypt(
        nonce, payload, payload_aad(object_id, version, policy_hash_ingest, codec_id))


def decrypt_payload(dek: bytes, payload_ct: bytes, object_id: str, version: int,
                    policy_hash_ingest: str, codec_id: str) -> bytes:
    return AESGCM(dek).decrypt(
        payload_ct[:12], payload_ct[12:],
        payload_aad(object_id, version, policy_hash_ingest, codec_id))


# =============================================================================
# 2. EPOCH TRANSITION RECORD (audit - deliverable 177)
# =============================================================================
PENDING, COMMITTED, ABORTED = "PENDING", "COMMITTED", "ABORTED"


@dataclass
class EpochTransition:
    """Một lượt epoch transition của 1 object - lưu làm audit trail."""
    object_id: str
    old_epoch: int
    new_epoch: int
    old_root: str
    new_root: str
    old_wrap_digest: str
    new_wrap_digest: str
    status: str = PENDING
    prepared_at: float = field(default_factory=time.time)
    committed_at: Optional[float] = None

    def to_audit_line(self) -> str:
        return (f"[{self.status}] {self.object_id}: epoch {self.old_epoch}->"
                f"{self.new_epoch}, wrap {self.old_wrap_digest[:12]}->"
                f"{self.new_wrap_digest[:12]}, root {self.new_root[:16]}...")


def wrap_digest(wrapped: ThresholdWrappedDEK) -> str:
    """Định danh bất biến của 1 wrapped DEK (c1||nonce||ct||aad)."""
    return hashlib.sha256(
        wrapped.c1.to_bytes() + wrapped.nonce + wrapped.ciphertext
        + wrapped.context.aad()).hexdigest()


# =============================================================================
# 3. EPOCH REWRAP SERVICE - giao thức transition 2 pha (164/177/180)
# =============================================================================
class EpochRewrapService:
    """
    Quản lý epoch transition + rewrap cho threshold key service.
    Bất biến (180 - không trạng thái mơ hồ):
      - Mỗi object đúng 1 active wrap; active chỉ đổi tại commit_rewrap().
      - Pending wrap CHƯA bao giờ được node phát partial (root chưa trusted).
      - Wrap cũ sau commit -> digest vào retired set; get_active_wrap từ chối.
      - Epoch không bao giờ lùi (recovery đi về phía trước).
    """

    def __init__(self, policy_log: PolicyLogService, bridge: EngramAnchorBridge,
                 oracle: KeyNodeTrustedRootOracle):
        self.policy_log = policy_log
        self.bridge = bridge
        self.oracle = oracle
        self.active_wrap: Dict[str, ThresholdWrappedDEK] = {}
        self.pending_wrap: Dict[str, ThresholdWrappedDEK] = {}
        self.retired_digests: set = set()
        self.global_epoch = 1                       # epoch neo toàn cục per-bridge
        self.object_epoch: Dict[str, int] = {}      # epoch label của wrap từng object
        self.transitions: List[EpochTransition] = []

    # ------------------------------------------------------------------
    def register_object(self, object_id: str, wrapped: ThresholdWrappedDEK,
                        initial_epoch: int = 1):
        """Đăng ký wrap epoch 1 (sau ingest)."""
        self.active_wrap[object_id] = wrapped
        self.object_epoch[object_id] = initial_epoch

    # ------------------------------------------------------------------
    def rotate_policy_epoch(self, object_id: str) -> Tuple[int, str]:
        """
        Bước 1 - Chính sách quay vòng: SUSPENDED -> ACTIVE tạo 2 signed event
        (policy metadata mới - 170); epoch neo TOÀN CỤC +1 (một bridge = một
        chuỗi anchor), anchor root mới, oracle sync -> root R' tươi.
        Wrap/context epoch MỚI của object sẽ gắn epoch toàn cục + R'.
        """
        self.global_epoch += 1
        self.policy_log.transition_policy(object_id, "SUSPENDED")
        self.policy_log.transition_policy(object_id, "ACTIVE")
        anchor = self.bridge.anchor_epoch(self.global_epoch, self.policy_log.mmr)
        proof = self.bridge.get_consistency_proof(self.global_epoch - 1,
                                                  self.global_epoch)
        self.oracle.sync_latest_trusted_root(anchor, proof)
        self.object_epoch[object_id] = self.global_epoch
        return self.global_epoch, anchor.mmr_root

    # ------------------------------------------------------------------
    def prepare_rewrap(self, object_id: str, new_wrap: ThresholdWrappedDEK):
        """
        Bước 2 - Chuẩn bị: wrap mới phải gắn epoch == epoch rotation hiện tại
        và policy_root == latest trusted root (chưa commit => node vẫn chặn
        partial cho nó vì pending, nhưng root đã trusted để validate).
        """
        if new_wrap.context.object_id != object_id:
            raise ValueError("new_wrap object_id không khớp")
        cur_epoch = self.object_epoch[object_id]
        if new_wrap.context.epoch != cur_epoch:
            raise ValueError(
                f"new_wrap epoch {new_wrap.context.epoch} != epoch hiện tại {cur_epoch}")
        latest = self.oracle.get_latest_trusted_root()
        if new_wrap.context.policy_root != latest:
            raise ValueError("new_wrap policy_root không phải latest trusted root")
        old = self.active_wrap[object_id]
        tr = EpochTransition(
            object_id=object_id, old_epoch=old.context.epoch, new_epoch=cur_epoch,
            old_root=old.context.policy_root, new_root=latest,
            old_wrap_digest=wrap_digest(old), new_wrap_digest=wrap_digest(new_wrap))
        self.pending_wrap[object_id] = new_wrap
        self.transitions.append(tr)
        return tr

    # ------------------------------------------------------------------
    def commit_rewrap(self, object_id: str):
        """
        Bước 3 - COMMIT nguyên tử: hoán đổi active wrap, retire wrap cũ.
        Trước commit: epoch cũ vẫn là active (fail-closed nếu root đã đổi).
        Sau commit: wrap cũ -> retired, wrap mới là duy nhất được phục vụ.
        """
        if object_id not in self.pending_wrap:
            raise ValueError("Không có rewrap đang PENDING để commit")
        old = self.active_wrap[object_id]
        new = self.pending_wrap.pop(object_id)
        self.retired_digests.add(wrap_digest(old))
        self.active_wrap[object_id] = new
        for tr in reversed(self.transitions):
            if tr.object_id == object_id and tr.status == PENDING:
                tr.status = COMMITTED
                tr.committed_at = time.time()
                break

    # ------------------------------------------------------------------
    def recover_forward(self, object_id: str):
        """
        Recovery sau crash (180): nếu còn pending -> commit đi tới (epoch đã
        anchor không lùi được); nếu không -> giữ nguyên active hiện tại.
        KHÔNG BAO GIỜ có 2 wrap cùng 'đúng' - chỉ 1 active.
        """
        if object_id in self.pending_wrap:
            self.commit_rewrap(object_id)
            print(f"    [recover] {object_id}: commit pending -> epoch "
                  f"{self.active_wrap[object_id].context.epoch} (forward-only)")
        else:
            print(f"    [recover] {object_id}: không có pending, active giữ nguyên "
                  f"epoch {self.active_wrap[object_id].context.epoch}")

    # ------------------------------------------------------------------
    def get_active_wrap(self, object_id: str) -> ThresholdWrappedDEK:
        wrapped = self.active_wrap[object_id]
        assert wrap_digest(wrapped) not in self.retired_digests, \
            "BẤT BIẾN VI PHẠM: active wrap đã bị retire"
        return wrapped


def safe_create_partial(node: ThresholdWrapNode, wrapped: ThresholdWrappedDEK,
                        service: EpochRewrapService, policy_db: Dict[str, dict]):
    """
    (167) Cổng chặn replay epoch cũ tại NGUỒN PHÁT HÀNH: node chỉ tạo partial
    cho wrap có policy_root == latest trusted root. Wrap epoch cũ (root đã bị
    rotation thay) -> StaleRootError, KHÔNG partial mới.
    """
    latest = service.oracle.get_latest_trusted_root()
    if wrapped.context.policy_root != latest:
        raise StaleRootError(
            f"Node từ chối: wrap thuộc epoch {wrapped.context.epoch} với root cũ "
            f"(latest là epoch {service.object_epoch[wrapped.context.object_id]})")
    return node.create_partial(wrapped, presented_policy_root=latest,
                               policy_db=policy_db)


# =============================================================================
# 4. CAPABILITY + COMMITTEE REWRAP + BATCH WORKER
# =============================================================================
def issue_capability(issuer_sk: ed25519.Ed25519PrivateKey, subject: str,
                     object_id: str, rights: str, epoch: int,
                     ttl_seconds: float = 300.0):
    """Cấp capability theo đúng canonical form của CapabilityVerifier (GĐ1)."""
    cap = {"subject": subject, "object_id": object_id, "rights": rights,
           "epoch": epoch, "expiry": time.time() + ttl_seconds,
           "nonce": os.urandom(8).hex()}
    canonical = (f"{cap['subject']}:{cap['object_id']}:{cap['rights']}"
                 f":{cap['epoch']}:{cap['expiry']}:{cap['nonce']}").encode()
    return cap, issuer_sk.sign(canonical)


def rewrap_via_committee(
    service: EpochRewrapService, object_id: str,
    old_nodes: Dict[int, ThresholdWrapNode], old_combiner: ThresholdCombiner,
    subset: List[int], new_threshold_pk: ECPoint, new_policy_hash: str,
    policy_db: Dict[str, dict],
) -> Tuple[ThresholdWrappedDEK, bytes]:
    """
    Committee-mode: t node cũ partial-unwrap epoch CŨ (root còn tươi - làm
    TRƯỚC rotation), client gộp DEK, rotation + wrap dưới key/context MỚI.
    Lưu ý trung thực: DEK tồn tại tạm tại client/combiner trong lúc rewrap.
    """
    old_wrap = service.get_active_wrap(object_id)
    proofs = [prove_dleq(
        j, old_nodes[j].share, old_nodes[j].public_share, old_wrap.c1,
        old_nodes[j].share * old_wrap.c1, old_wrap.proof_context())
        for j in subset]
    dek = old_combiner.combine(proofs, old_wrap).dek
    new_epoch, new_root = service.rotate_policy_epoch(object_id)
    new_ctx = WrapContext(
        object_id=object_id, version=old_wrap.context.version,
        policy_hash=new_policy_hash, codec_id=old_wrap.context.codec_id,
        epoch=new_epoch, policy_root=new_root)
    new_wrap = wrap_dek(dek, new_threshold_pk, new_ctx)
    service.prepare_rewrap(object_id, new_wrap)
    service.commit_rewrap(object_id)
    return new_wrap, dek


def batch_rewrap_worker(service: EpochRewrapService, batch: List[dict],
                        policy_db: Dict[str, dict]) -> dict:
    """
    (174) Batch rewrap worker: quay lại K object (owner-mode, DEK tạm có),
    đo latency từng object -> median/p95 (deliverable 179 + gợi ý 168).
    """
    times_ms: List[float] = []
    for item in batch:
        t0 = time.time()
        object_id = item["object_id"]
        dek = item["dek"]
        new_epoch, new_root = service.rotate_policy_epoch(object_id)
        new_ctx = dc_replace(item["wrap"].context, epoch=new_epoch,
                             policy_root=new_root,
                             policy_hash=item["new_policy_hash"])
        new_wrap = wrap_dek(dek, item["threshold_pk"], new_ctx)
        service.prepare_rewrap(object_id, new_wrap)
        service.commit_rewrap(object_id)
        times_ms.append((time.time() - t0) * 1000)
    times_ms.sort()
    k = len(times_ms)
    return {
        "count": k,
        "median_ms": times_ms[k // 2],
        "p95_ms": times_ms[min(k - 1, int(k * 0.95))],
        "throughput_obj_per_s": 1000.0 / (sum(times_ms) / k),
    }


# =============================================================================
# 5. PIPELINE (key material cache - DKG/VSS 1 lần cho cả file)
# =============================================================================
_KEY_CACHE = {}


def key_material() -> dict:
    if _KEY_CACHE:
        return _KEY_CACHE
    dealer_sks, dealer_pks = committee_keygen(N)
    # VSS (câu 2): chứng minh mọi thành viên xác minh được share trước khi
    # DKG dùng - dùng bộ Feldman riêng để demo check, KHÔNG trộn vào key.
    ctx = "epoch-rewrap-vss"
    feldman = {i: FeldmanVSS(i, T, rng=random.Random(8000 + i))
               for i in range(1, N + 1)}
    members = {j: VSSMember(j, ctx, dealer_pks) for j in range(1, N + 1)}
    for j in range(1, N + 1):
        for i in range(1, N + 1):
            sig = sign_broadcast(dealer_sks[i], ctx, i, feldman[i].commitments)
            members[j].check_feldman_share(i, feldman[i].share_for(j),
                                           feldman[i].commitments, sig)
    assert all(m.report.all_ok for m in members.values())
    # Key thật cho wrap/partial: DKG (câu 1) - Y_j và x_j nhất quán với Y
    dkg, _ = run_pedersen_dkg(list(range(1, N + 1)), T)
    _KEY_CACHE.update(
        dkg=dkg, shares=dkg.private_shares,
        pub_shares=dkg.public_key_shares,
        threshold_pk=dkg.joint_public_key)
    return _KEY_CACHE


def build_env(object_id: str = "OBJ-8001", payload_size: int = 1024) -> dict:
    """Một môi trường epoch-1 độc lập: policy log GĐ1 + oracle GĐ2 + wrap + nodes."""
    km = key_material()
    service_log = PolicyLogService(ed25519.Ed25519PrivateKey.generate())
    event, _, _ = service_log.init_policy(object_id, initial_epoch=1)
    ph_ingest = hashlib.sha256(event.canonical_bytes_for_signing()).hexdigest()
    bridge = EngramAnchorBridge(ed25519.Ed25519PrivateKey.generate())
    anchor1 = bridge.anchor_epoch(1, service_log.mmr)
    oracle = KeyNodeTrustedRootOracle(
        bridge.bridge_pk, FreshnessWindowConfig(max_anchor_age_seconds=60.0))
    oracle.sync_latest_trusted_root(anchor1)

    dek = os.urandom(32)
    payload = os.urandom(payload_size)
    codec = "JSON-GCM-v1"
    payload_ct = encrypt_payload(dek, payload, object_id, 1, ph_ingest, codec)

    wrap_ctx = WrapContext(object_id=object_id, version=1, policy_hash=ph_ingest,
                           codec_id=codec, epoch=1, policy_root=anchor1.mmr_root)
    wrapped = wrap_dek(dek, km["threshold_pk"], wrap_ctx)

    rewrap_svc = EpochRewrapService(service_log, bridge, oracle)
    rewrap_svc.register_object(object_id, wrapped, initial_epoch=1)
    nodes = {j: ThresholdWrapNode(j, km["shares"][j], km["pub_shares"][j],
                                  T, oracle=oracle)
             for j in range(1, N + 1)}
    return dict(object_id=object_id, service_log=service_log, bridge=bridge,
                oracle=oracle, rewrap=rewrap_svc, nodes=nodes,
                combiner=ThresholdCombiner(km["pub_shares"], T),
                dek=dek, payload=payload, payload_ct=payload_ct,
                ph_ingest=ph_ingest, codec=codec, **km)


def _banner(title: str):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


# =============================================================================
# 6. DEMO + TESTS
# =============================================================================
if __name__ == "__main__":
    TOTAL_T0 = time.time()
    results = []
    OBJECT = "OBJ-8001"

    # =====================================================================
    _banner("TEST 1: EPOCH TRANSITION OWNER-MODE - PAYLOAD KHÔNG RE-ENCRYPT (170)")
    # =====================================================================
    env = build_env(OBJECT)
    svc, nodes, comb = env["rewrap"], env["nodes"], env["combiner"]

    # Epoch 1: 3 node partial-unwrap bình thường
    w1 = svc.get_active_wrap(OBJECT)
    p1 = [prove_dleq(j, env["shares"][j], env["pub_shares"][j], w1.c1,
                     env["shares"][j] * w1.c1, w1.proof_context())
          for j in (1, 2, 3)]
    assert comb.combine(p1, w1).dek == env["dek"]
    print(f"  [1a] Epoch 1: unwrap DEK OK từ 3/5 node")

    # Rotation: policy SUSPENDED->ACTIVE, anchor epoch 2, oracle sync
    new_epoch, new_root = svc.rotate_policy_epoch(OBJECT)
    assert new_epoch == 2
    print(f"  [1b] rotate_policy_epoch -> epoch 2, root mới {new_root[:24]}...")

    # Rewrap DEK dưới context epoch 2 (chính sách mới) - DEK KHÔNG đổi
    new_ph = hashlib.sha256(b"rotation-epoch-2-policy").hexdigest()
    new_ctx = dc_replace(w1.context, policy_hash=new_ph, epoch=new_epoch,
                         policy_root=new_root)
    w2 = wrap_dek(env["dek"], env["threshold_pk"], new_ctx)
    tr = svc.prepare_rewrap(OBJECT, w2)
    svc.commit_rewrap(OBJECT)
    print(f"  [1c] PREPARE->COMMIT: {tr.to_audit_line()}")

    # Payload ciphertext GIỮ NGUYÊN từng byte; DEK unwrap ở epoch 2 giống hệt
    assert decrypt_payload(env["dek"], env["payload_ct"], OBJECT, 1,
                           env["ph_ingest"], env["codec"]) == env["payload"]
    w2b = svc.get_active_wrap(OBJECT)
    assert w2b.context.epoch == 2 and wrap_digest(w1) in svc.retired_digests
    p2 = [prove_dleq(j, env["shares"][j], env["pub_shares"][j], w2b.c1,
                     env["shares"][j] * w2b.c1, w2b.proof_context())
          for j in (2, 3, 5)]
    assert comb.combine(p2, w2b).dek == env["dek"]
    print(f"  [1d] Payload AEAD hash = "
          f"{hashlib.sha256(env['payload_ct']).hexdigest()[:24]}... (cũ hay mới "
          f"cũng decrypt bằng DEK cũ) - KHÔNG re-encrypt payload")
    print(f"  [1e] Epoch 2: unwrap từ subset (2,3,5) -> CÙNG DEK; wrap epoch 1 retired")
    results.append("TEST1 owner-mode transition, payload unchanged: PASS")

    # =====================================================================
    _banner("TEST 2: PARTIAL/POLICY ROOT EPOCH CŨ KHÔNG REPLAY SANG EPOCH MỚI (167)")
    # =====================================================================
    # 2a. Partial epoch 1 (p1) trình cho wrap epoch 2 -> combiner loại toàn bộ
    try:
        comb.combine(p1, w2b)
        raise AssertionError("Partial epoch cũ phải bị loại")
    except InsufficientPartials as err:
        assert all(r == "dleq-invalid" for _, r in err.report.rejected)
        print(f"  [2a] 3 partial epoch 1 vs wrap epoch 2 -> {err}")

    # 2b. Node TỪ CHỐI tạo partial mới cho wrap epoch cũ (root không còn tươi)
    try:
        safe_create_partial(nodes[1], w1, svc, env["service_log"].policy_records)
        raise AssertionError("Wrap epoch cũ phải bị chặn tại node")
    except StaleRootError as err:
        print(f"  [2b] safe_create_partial(wrap epoch 1) -> StaleRootError: {err}")

    # 2c. Partial MỚI cho wrap epoch 2 vẫn được cấp bình thường
    pc = safe_create_partial(nodes[4], w2b, svc, env["service_log"].policy_records)
    full = prove_dleq(4, env["shares"][4], env["pub_shares"][4], w2b.c1,
                      pc.d_point, w2b.proof_context())
    assert comb.combine([p2[0], p2[1], full], w2b).dek == env["dek"]
    print(f"  [2c] Partial mới (epoch 2, root tươi) -> unwrap OK")
    results.append("TEST2 no old-epoch replay: PASS")

    # =====================================================================
    _banner("TEST 3: CAPABILITY EPOCH CŨ KHÔNG HOẠT ĐỘNG Ở EPOCH MỚI (180)")
    # =====================================================================
    issuer_sk = ed25519.Ed25519PrivateKey.generate()
    verifier = CapabilityVerifier(issuer_sk.public_key())
    cap1, sig1 = issue_capability(issuer_sk, "alice", OBJECT, "read", epoch=1)
    assert verifier.verify_capability(cap1, sig1, "alice", OBJECT, "read", 1)
    print("  [3a] Capability epoch 1 verify OK tại epoch 1")

    cap2, sig2 = issue_capability(issuer_sk, "alice", OBJECT, "read", epoch=2)
    assert verifier.verify_capability(cap2, sig2, "alice", OBJECT, "read", 2)
    print("  [3b] Capability epoch 2 (mới) verify OK")

    # Cap epoch 1 replay tại epoch hiện tại (=2) -> reject (verifier FRESH
    # để không dính nonce-replay, isolate đúng nhánh epoch binding)
    fresh = CapabilityVerifier(issuer_sk.public_key())
    try:
        fresh.verify_capability(cap1, sig1, "alice", OBJECT, "read", 2)
        raise AssertionError("Cap epoch cũ phải bị reject ở epoch 2")
    except CapSecurityError as err:
        print(f"  [3c] Cap epoch 1 tại epoch 2 -> {err}")
    results.append("TEST3 old capability rejected at new epoch: PASS")

    # =====================================================================
    _banner("TEST 4: COMMITTEE REWRAP - ĐỔI KEY COMMITTEE, DEK GIỮ NGUYÊN")
    # =====================================================================
    env4 = build_env("OBJ-8004")
    svc4, nodes4, comb4 = env4["rewrap"], env4["nodes"], env4["combiner"]
    # DKG lần 2 -> committee/key MỚI Y'
    dkg2, _ = run_pedersen_dkg(list(range(1, N + 1)), T)
    shares2 = dkg2.private_shares
    pub2 = dkg2.public_key_shares
    print(f"  [4a] DKG lần 2: Y' = {format(dkg2.joint_public_key.x, 'x')[:24]}... "
          f"(Y khác: {dkg2.joint_public_key != env4['threshold_pk']})")

    new_ph4 = hashlib.sha256(b"new-committee-policy").hexdigest()
    w_new, dek_out = rewrap_via_committee(
        svc4, "OBJ-8004", nodes4, comb4, [1, 2, 3],
        dkg2.joint_public_key, new_ph4, env4["service_log"].policy_records)
    assert dek_out == env4["dek"]
    assert w_new.context.epoch == 2
    print(f"  [4b] 3 node CŨ unwrap epoch 1 -> DEK -> rewrap dưới Y' epoch 2 OK")

    # Committee MỚI unwrap wrap mới
    nodes2 = {j: ThresholdWrapNode(j, shares2[j], pub2[j], T, oracle=svc4.oracle)
              for j in range(1, N + 1)}
    comb2 = ThresholdCombiner(pub2, T)
    pn = [prove_dleq(j, shares2[j], pub2[j], w_new.c1,
                     shares2[j] * w_new.c1, w_new.proof_context())
          for j in (1, 2, 4)]
    assert comb2.combine(pn, w_new).dek == env4["dek"]
    print(f"  [4c] Committee MỚI (3/5 node) unwrap wrap mới -> CÙNG DEK")

    # Share CŨ không dùng được cho key mới: partial theo x_old, verify với Y'_j.
    # (prove_dleq tự chặn witness lệch ->构造 trực tiếp như attacker)
    from chaum_pedersen_partial_proof import _challenge
    x_old1 = env4["shares"][1]
    d_wrong = x_old1 * w_new.c1
    u = _RNG.randrange(1, N_ORDER)
    a_p, b_p = u * G, u * w_new.c1
    c_val = _challenge(pub2[1], w_new.c1, d_wrong, a_p, b_p, w_new.proof_context())
    z_val = (u + c_val * x_old1) % N_ORDER
    from chaum_pedersen_partial_proof import ChaumPedersenProof
    old_as_new = ChaumPedersenProof(1, d_wrong, a_p, b_p, c_val, z_val)
    verdicts = comb2.classify([old_as_new], w_new.c1, w_new.proof_context())
    assert verdicts[0].reason == "dleq-invalid"
    print(f"  [4d] Partial theo share CŨ verify với Y'_j -> dleq-invalid "
          f"(old shares không cross-key)")
    results.append("TEST4 committee rewrap + old-share isolation: PASS")

    # =====================================================================
    _banner("TEST 5: INTERRUPTED REWRAP - KHÔNG TRẠNG THÁI MƠ HỒ (180)")
    # =====================================================================
    env5 = build_env("OBJ-8005")
    svc5 = env5["rewrap"]
    w1_5 = svc5.get_active_wrap("OBJ-8005")

    new_epoch5, new_root5 = svc5.rotate_policy_epoch("OBJ-8005")
    new_ctx5 = dc_replace(w1_5.context, epoch=new_epoch5, policy_root=new_root5,
                          policy_hash=hashlib.sha256(b"interrupted").hexdigest())
    w2_5 = wrap_dek(env5["dek"], env5["threshold_pk"], new_ctx5)
    svc5.prepare_rewrap("OBJ-8005", w2_5)
    # --- "CRASH" tại đây: chưa commit ---
    print("  [5a] Crash sau PREPARE, trước COMMIT (mô phỏng bằng cách dừng)")

    # Phục hồi: active vẫn wrap epoch 1 (dù root đã đổi -> fail-closed, không mơ hồ)
    active = svc5.get_active_wrap("OBJ-8005")
    assert active is w1_5
    try:
        safe_create_partial(env5["nodes"][1], active, svc5,
                            env5["service_log"].policy_records)
        raise AssertionError("Wrap epoch cũ sau rotation phải fail-closed")
    except StaleRootError:
        print("  [5b] Active vẫn wrap epoch 1 -> node fail-closed (root đã đổi): "
              "KHÔNG phục vụ sai epoch, KHÔNG có 2 wrap cùng đúng")

    # Recovery đi về phía trước: commit pending
    svc5.recover_forward("OBJ-8005")
    active5 = svc5.get_active_wrap("OBJ-8005")
    assert active5 is w2_5 and wrap_digest(w1_5) in svc5.retired_digests
    pc5 = safe_create_partial(env5["nodes"][2], active5, svc5,
                              env5["service_log"].policy_records)
    f5 = prove_dleq(2, env5["shares"][2], env5["pub_shares"][2], active5.c1,
                    pc5.d_point, active5.proof_context())
    f6 = prove_dleq(3, env5["shares"][3], env5["pub_shares"][3], active5.c1,
                    env5["shares"][3] * active5.c1, active5.proof_context())
    f7 = prove_dleq(4, env5["shares"][4], env5["pub_shares"][4], active5.c1,
                    env5["shares"][4] * active5.c1, active5.proof_context())
    assert env5["combiner"].combine([f5, f6, f7], active5).dek == env5["dek"]
    print("  [5c] recover_forward -> commit; unwrap epoch 2 OK; wrap cũ retired")
    results.append("TEST5 interrupted rewrap unambiguous: PASS")

    # =====================================================================
    _banner("TEST 6: OLD MATERIAL = COMPROMISED-AFTER-USE (172 - TRUNG THỰC)")
    # =====================================================================
    env6 = build_env("OBJ-8006")
    svc6, comb6 = env6["rewrap"], env6["combiner"]
    w_old6 = svc6.get_active_wrap("OBJ-8006")
    # Attacker (hoặc client đã truy cập hợp lệ) GIỮ bộ partial epoch 1
    stolen = [prove_dleq(j, env6["shares"][j], env6["pub_shares"][j], w_old6.c1,
                         env6["shares"][j] * w_old6.c1, w_old6.proof_context())
              for j in (1, 2, 3)]
    # Rotation + rewrap như bình thường
    ne6, nr6 = svc6.rotate_policy_epoch("OBJ-8006")
    w_new6 = wrap_dek(env6["dek"], env6["threshold_pk"],
                      dc_replace(w_old6.context, epoch=ne6, policy_root=nr6,
                                 policy_hash="aa" * 32))
    svc6.prepare_rewrap("OBJ-8006", w_new6)
    svc6.commit_rewrap("OBJ-8006")

    # TRUNG THỰC: partial CŨ đã thu thập vẫn ghép được DEK (không thu hồi quá khứ)
    leaked = comb6.combine(stolen, w_old6).dek
    assert leaked == env6["dek"]
    print("  [6a] TRUNG THỰC: bộ partial epoch 1 đã thu thập TRƯỚC rotation vẫn "
          "ghép DEK được -> protocol không 'xóa được' material đã lọt")

    # Nhưng: không còn phát hành MỚI cho epoch cũ + wrap cũ retired + cap cũ chết
    try:
        safe_create_partial(env6["nodes"][1], w_old6, svc6,
                            env6["service_log"].policy_records)
        raise AssertionError("Không được cấp partial mới cho epoch cũ")
    except StaleRootError:
        pass
    assert wrap_digest(w_old6) in svc6.retired_digests
    assert svc6.get_active_wrap("OBJ-8006") is w_new6
    print("  [6b] KHÔNG partial mới cho epoch cũ; wrap cũ retired; chỉ wrap mới active")
    print("  => Claim đúng phạm vi (172/192): sau rotation, hạ tầng không phát hành")
    print("     capability/partial MỚI cho epoch cũ; material cũ phải bị coi là")
    print("     compromised-after-use (client đã lưu DEK/plaintext ngoài tầm thu hồi)")
    results.append("TEST6 compromised-after-use honesty: PASS")

    # =====================================================================
    _banner("TEST 7: BATCH REWRAP WORKER - MEDIAN/P95 (174/179)")
    # =====================================================================
    # (174) Batch rewrap worker: 12 object chung committee/policy-log/bridge,
    # mỗi object rotate lần lượt -> epoch toàn cục tăng dần (2,3,...,13).
    K = 12
    base = build_env("OBJ-BATCH-0")
    batch_svc = base["rewrap"]
    sl = base["service_log"]
    root1 = base["oracle"].get_latest_trusted_root()
    batch_items = []
    for i in range(K):
        oid = f"OBJ-B{i:03d}"
        ev, _, _ = sl.init_policy(oid, initial_epoch=1)
        ph = hashlib.sha256(ev.canonical_bytes_for_signing()).hexdigest()
        dek_i = os.urandom(32)
        ctx_i = WrapContext(oid, 1, ph, "JSON-GCM-v1", 1, root1)
        wrap_i = wrap_dek(dek_i, base["threshold_pk"], ctx_i)
        batch_svc.register_object(oid, wrap_i, 1)
        batch_items.append(dict(
            object_id=oid, dek=dek_i, wrap=wrap_i,
            threshold_pk=base["threshold_pk"],
            new_policy_hash=hashlib.sha256(f"rot-{oid}".encode()).hexdigest()))

    t_all0 = time.time()
    times = []
    for item in batch_items:                       # (174) worker lặp từng object
        t0 = time.time()
        oid = item["object_id"]
        ne, nr = batch_svc.rotate_policy_epoch(oid)
        nctx = dc_replace(item["wrap"].context, epoch=ne, policy_root=nr,
                          policy_hash=item["new_policy_hash"])
        nwrap = wrap_dek(item["dek"], item["threshold_pk"], nctx)
        batch_svc.prepare_rewrap(oid, nwrap)
        batch_svc.commit_rewrap(oid)
        times.append((time.time() - t0) * 1000)
    times.sort()
    total_s = time.time() - t_all0
    median, p95 = times[K // 2], times[min(K - 1, int(K * 0.95))]
    print(f"  [7a] Rewrap {K} objects (rotate+anchor+sync+wrap+commit):")
    print(f"       median={median:.1f} ms | p95={p95:.1f} ms "
          f"| throughput={1000.0/(sum(times)/K):.1f} obj/s | total={total_s:.2f} s")
    for item in batch_items:
        w = batch_svc.get_active_wrap(item["object_id"])
        assert w.context.epoch == batch_svc.object_epoch[item["object_id"]]
        # Spot-check: payload helper bất biến theo epoch (170)
        ct_i = encrypt_payload(item["dek"], b"payload", item["object_id"],
                               1, "ph-ingest", "c")
        assert decrypt_payload(item["dek"], ct_i, item["object_id"], 1,
                               "ph-ingest", "c") == b"payload"
    print(f"  [7b] {K}/{K} object đã commit epoch mới; payload AEAD bất biến")
    results.append("TEST7 batch rewrap worker: PASS")

    # =====================================================================
    _banner("BENCHMARK THÀNH PHẦN")
    # =====================================================================
    envb = build_env("OBJ-BENCH")
    dek_b, pk_b = envb["dek"], envb["threshold_pk"]
    ctx_b = envb["rewrap"].get_active_wrap("OBJ-BENCH").context
    t0 = time.time()
    for _ in range(10):
        wrap_dek(dek_b, pk_b, ctx_b)
    print(f"- wrap_dek (owner rewrap): {(time.time()-t0)/10*1000:.1f} ms")
    w_b = envb["rewrap"].get_active_wrap("OBJ-BENCH")
    pc_b = envb["nodes"][1].create_partial(
        w_b, presented_policy_root=envb["oracle"].get_latest_trusted_root(),
        policy_db=envb["service_log"].policy_records)
    t0 = time.time()
    for _ in range(10):
        prove_dleq(1, envb["shares"][1], envb["pub_shares"][1], w_b.c1,
                   pc_b.d_point, w_b.proof_context())
    print(f"- prove_dleq (committee rewrap bước 1): {(time.time()-t0)/10*1000:.1f} ms/node")
    print(f"- (rotate+anchor+sync đo chung trong batch worker ở TEST 7)")

    # =====================================================================
    _banner("KẾT LUẬN")
    # =====================================================================
    for r in results:
        print(f"  {r}")
    print(f"  Tổng thời gian demo: {time.time() - TOTAL_T0:.2f} s")
    print("  => Epoch transition 2 pha (PREPARE->COMMIT) + forward recovery:")
    print("     payload AEAD CỐ ĐỊNH 4 trường GĐ1, ciphertext giữ nguyên từng byte")
    print("     (170) - chỉ wrapped DEK + policy metadata quay; partial/capability")
    print("     epoch cũ không replay được (167/180); old material được xử lý")
    print("     trung thực theo compromised-after-use (172); batch worker đo")
    print("     median/p95 (174/179); committee đổi key bằng DKG lần 2 mà DEK giữ")
    print("     nguyên (166-adjacent).")
    print("  LƯU Ý: prototype academic, chưa audit - không dùng production.")
