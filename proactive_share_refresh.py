"""
================================================================================
GIAI ĐOẠN 4 - PROACTIVE SHARE REFRESH
Lời giải câu: "Cài proactive share refresh không đổi public key nếu primitive
                cho phép." 
================================================================================
"""

import os
import time
import hashlib
import random
import itertools
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Iterable

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# --- Câu 1: toán học EC + Lagrange + DKG + lỗi fail-closed -------------------
from dkg_threshold_service import (
    ECPoint,
    G,
    N_ORDER,
    evaluate_polynomial,
    lagrange_coefficient,
    run_pedersen_dkg,
    DKGParty,
)

# --- Câu 2: broadcast có chữ ký (bind context) + bộ key ủy ban ---------------
from vss_share_verification import (
    broadcast_bytes,
    sign_broadcast,
    committee_keygen,
    ShareCheckResult,
)

# --- Câu 3 + 4 + 5: wrap DEK, DLEQ proof, combiner ---------------------------
from wrap_dek_partial_decryption import (
    WrapContext,
    ThresholdWrappedDEK,
    wrap_dek,
    ThresholdWrapNode,
    verify_partial,
    combine_and_unwrap,
)
from chaum_pedersen_partial_proof import (
    ChaumPedersenProof,
    prove_dleq,
)
from combiner_filter_and_combine import ThresholdCombiner, InsufficientPartials

# --- GĐ1 & GĐ2 ---------------------------------------------------------------
from signedandapend_events import PolicyLogService
from anchorroot import EngramAnchorBridge
from freshnesswindowandlatesttrustedroot import (
    KeyNodeTrustedRootOracle,
    FreshnessWindowConfig,
)

# --- GĐ4 câu 1: payload/wrap helpers + DKG key cache -------------------------
from epoch_transition_rewrap import (
    encrypt_payload,
    decrypt_payload,
    wrap_digest,
    key_material,
)

_RNG = random.SystemRandom()

N, T = 5, 3

# Trạng thái của service refresh (mục 180: không bao giờ mơ hồ)
IDLE, PENDING, COMMITTED, ABORTED = "IDLE", "PENDING", "COMMITTED", "ABORTED"


# =============================================================================
# 1. LỖI FAIL-CLOSED
# =============================================================================
class RefreshAbortError(Exception):
    """Refresh bị hủy (QUAL < t / barrier / sanity fail) - rollback về share cũ."""


class RefreshPeriodMismatch(Exception):
    """Node lệch thế hệ (period) - chặn phát partial cho tới khi resync."""


# =============================================================================
# 2. HORNER TRÊN GROUP - đánh giá Y'_j từ COMMITMENT (không cần secret)
#    Y'_j = Y_j + sum_{i in QUAL} sum_k (j^k) * C_{i,k}
# =============================================================================
def _horner_point(commitments: List[ECPoint], x: int) -> ECPoint:
    """sum_k (x^k) * C_k trên group (Horner, scalar-trái = form chuẩn của codebase)."""
    acc = ECPoint(None, None)
    for c_k in reversed(commitments):
        acc = (x % N_ORDER) * acc + c_k
    return acc


def _verify_zero_poly_share(member_id: int, delta: int,
                            commitments: List[ECPoint]) -> bool:
    """Kiểm tra delta của zero-polynomial: delta*G == sum_k (j^k)*C_k (câu 1)."""
    return DKGParty.verify_share(member_id, delta, commitments)


# =============================================================================
# 3. REFRESH TRANSCRIPT - kiểm chứng CÔNG KHAI, không chứa secret (172)
# =============================================================================
@dataclass
class RefreshTranscript:
    """
    Bản ghi công khai của một vòng refresh:
      - context = "refresh|period=P|root=R" (gắn epoch+policy root GĐ2) -> chống
        replay transcript cũ (167/172);
      - commitments C_k = g_k*G (C_0 BẮT BUỘC là điểm vô cực = a_0 = 0);
      - chữ ký Ed25519 của TỪNG party trên broadcast (tái dùng câu 2);
      - qualified/disqualified để mọi người tính lại Y' không cần secret.
    KHÔNG phần tử nào là scalar bí mật (share / hệ số g).
    """

    period: int
    context: str
    commitments: Dict[int, List[ECPoint]]
    signatures: Dict[int, bytes]
    qualified: List[int]
    disqualified: List[int]
    threshold: int
    base_public_shares: Dict[int, ECPoint] = field(default_factory=dict)

    # ------------------------------------------------------------------
    @staticmethod
    def context_bytes(period: int, policy_root: str) -> str:
        """Ngữ cảnh ký = period (tăng đơn điệu) + latest trusted root (GĐ2)."""
        return f"refresh|period={period}|root={policy_root}"

    # ------------------------------------------------------------------
    def key_delta(self) -> ECPoint:
        """sum_i C_{i,0} - PHẢI là điểm vô cực thì public key mới giữ nguyên."""
        acc = ECPoint(None, None)
        for commits in self.commitments.values():
            acc = acc + commits[0]
        return acc

    # ------------------------------------------------------------------
    def derived_public_share(self, member_id: int, old_public_share: ECPoint) -> ECPoint:
        """BẤT KỲ AI suy được Y'_j từ transcript + Y_j cũ - không cần secret."""
        acc = old_public_share
        for pid in self.qualified:
            acc = acc + _horner_point(self.commitments[pid], member_id)
        return acc

    # ------------------------------------------------------------------
    def verify_public(self, expected_period: int, expected_root: str,
                      signing_pks: Dict[int, ed25519.Ed25519PublicKey]) -> List[str]:
        """
        Independent public verifier (172): ai có public key ủy ban cũng chạy được.
        Trả về danh sách lỗi rỗng = transcript hợp lệ.
        """
        problems: List[str] = []
        expected_ctx = self.context_bytes(expected_period, expected_root)
        if self.period != expected_period:
            problems.append(f"period {self.period} != kỳ vọng {expected_period}")
        if self.context != expected_ctx:
            problems.append(
                f"context sai (replay từ root/period khác?) có={self.context!r}")
        if not self.qualified or len(self.qualified) < self.threshold:
            problems.append(
                f"QUAL={len(self.qualified)} < t={self.threshold} - không hợp lệ")
        qual = set(self.qualified)
        if self.key_delta() != ECPoint(None, None):
            problems.append(
                "sum C_0 != vô cực -> a_0 != 0 -> public key sẽ bị LỆCH (166)")
        for pid, commits in self.commitments.items():
            if not commits or not isinstance(commits[0], ECPoint):
                problems.append(f"party {pid}: thiếu commitment")
                continue
            if pid in qual and not commits[0].is_infinity():
                problems.append(
                    f"party {pid}: C_0 là {commits[0].to_bytes().hex()[:16]}... "
                    "không phải vô cực -> a_0 != 0 (166)")
            pk = signing_pks.get(pid)
            if pk is None:
                problems.append(f"party {pid}: không có public key tin cậy")
                continue
            sig = self.signatures.get(pid)
            if sig is None:
                problems.append(f"party {pid}: thiếu chữ ký broadcast")
                continue
            try:
                pk.verify(sig, broadcast_bytes(self.context, pid, commits))
            except (InvalidSignature, ValueError):
                problems.append(
                    f"party {pid}: chữ ký broadcast sai (tampered/replay context)")
        return problems

    # ------------------------------------------------------------------
    def to_public_dump(self) -> str:
        """Chuỗi hex công khai của transcript - dùng cho kiểm tra rò rỉ secret."""
        parts = [f"period={self.period}", f"ctx={self.context}"]
        for pid in sorted(self.commitments):
            parts.append(f"C{pid}=" + ",".join(c.to_bytes().hex() for c in self.commitments[pid]))
            parts.append(f"sig{pid}=" + self.signatures[pid].hex())
        parts.append("qual=" + ",".join(map(str, self.qualified)))
        return "|".join(parts)

    # ------------------------------------------------------------------
    def leak_scan(self, secrets: Iterable[int]) -> List[str]:
        """(172) Bất kỳ secret scalar nào bị in ra transcript -> báo cáo."""
        dump = self.to_public_dump()
        leaks = []
        for s in secrets:
            if s is None or s % N_ORDER == 0:
                continue                      # 0 không phải secret, hex("0") match mọi nơi
            form = format(s % N_ORDER, "064x")
            if form in dump:
                leaks.append(f"scalar {form[:16]}... xuất hiện trong transcript")
        return leaks


# =============================================================================
# 4. REFRESH PARTY - 1 node trong ủy ban, giữ share HIỆN HÀNH + backup
# =============================================================================
class RefreshParty:
    """
    Một thành viên ủy ban t-of-n.  Không bao giờ có full key.
    - active_share/active_public_share: bộ share ĐANG PHỤC VỤ (duy nhất 1 bộ).
    - backup_*: ảnh chụp trước khi swap -> node crash-sai-phase restore được.
    - candidate_*: bộ share MỚI sau prepare, CHƯA active cho tới khi commit
      nguyên tử toàn ủy ban (180 - không half-commit).
    """

    def __init__(self, party_id: int, committee_size: int, threshold: int,
                 share: int, public_share: ECPoint, signing_sk: ed25519.Ed25519PrivateKey,
                 rng: Optional[random.Random] = None):
        self.party_id = party_id
        self.n = committee_size
        self.t = threshold
        self.signing_sk = signing_sk
        self.rng = rng or _RNG

        self.active_share = share % N_ORDER
        self.active_public_share = public_share
        self.backup_share = self.active_share
        self.backup_public_share = public_share
        self.backup_period: Optional[int] = None
        self.period: Optional[int] = None
        self.refreshed = True

        # Vòng refresh hiện tại
        self.coeffs: Optional[List[int]] = None       # hệ số ZERO-polynomial g(x)
        self.commitments: Optional[List[ECPoint]] = None
        self.inbox: Dict[int, int] = {}               # sender -> delta nhận được
        self.checks: Dict[int, ShareCheckResult] = {}
        self.complaints: List[int] = []
        self.candidate_share: Optional[int] = None
        self.candidate_public_share: Optional[ECPoint] = None
        self.ready = False

    # ------------------------------------------------------------------
    def round1_generate(self) -> List[ECPoint]:
        """
        Sinh zero-polynomial g(x) bậc (t-1) với hằng số g(0)=0 -> Y bất biến.
        Commitment Feldman: C_0 = 0*G = vô cực, C_k = g_k*G (k>=1).
        """
        self.coeffs = [0] + [self.rng.randrange(1, N_ORDER) for _ in range(self.t - 1)]
        self.commitments = [c * G for c in self.coeffs]
        return list(self.commitments)

    # ------------------------------------------------------------------
    def delta_for(self, receiver_id: int) -> int:
        """Delta riêng g(receiver) - gửi qua kênh riêng (prototype: in-memory)."""
        if self.coeffs is None:
            raise RuntimeError("round1_generate chưa chạy")
        return evaluate_polynomial(self.coeffs, receiver_id)

    # ------------------------------------------------------------------
    def verify_delta(self, sender_id: int, delta: Optional[int],
                     commitments: List[ECPoint]) -> ShareCheckResult:
        """Mỗi receiver TỰ kiểm delta nhận được (equation Feldman, tái dùng câu 1)."""
        if delta is None:
            res = ShareCheckResult(self.party_id, sender_id, False, "refresh",
                                   "không nhận được delta (mất gói / node chết)")
        elif not _verify_zero_poly_share(self.party_id, delta, commitments):
            res = ShareCheckResult(
                self.party_id, sender_id, False, "refresh",
                f"vi phạm zero-poly: {delta}*G != sum(j^k*C_k) với j={self.party_id}")
        else:
            res = ShareCheckResult(self.party_id, sender_id, True, "refresh", "OK")
        self.checks[sender_id] = res
        return res

    # ------------------------------------------------------------------
    def swap_candidate(self):
        """Hoán đổi nguyên tử TẠI NODE: active <- candidate, backup <- active cũ."""
        self.backup_share = self.active_share
        self.backup_public_share = self.active_public_share
        self.backup_period = self.period
        self.active_share = self.candidate_share
        self.active_public_share = self.candidate_public_share
        self.refreshed = True
        self.candidate_share = None
        self.candidate_public_share = None
        self.ready = False

    # ------------------------------------------------------------------
    def restore_from_backup(self):
        """(180) Node swap-sai-phase tự lùi về ảnh chụp known-good trước đó."""
        self.active_share = self.backup_share
        self.active_public_share = self.backup_public_share
        if self.backup_period is not None:
            self.period = self.backup_period
        self.refreshed = True
        self.candidate_share = None
        self.candidate_public_share = None
        self.ready = False


# =============================================================================
# 5. PROACTIVE REFRESH SERVICE - điều phối prepare/commit 2 pha + recovery
# =============================================================================
class ProactiveRefreshService:
    """
    Điều phối vòng refresh cho ủy ban t-of-n:
      prepare()  : round 1-3 (commitment + phân phối delta + verify/complaint +
                   candidate) -> transcript, status PENDING (share CHƯA đổi).
      commit()   : BARRIER - chỉ swap khi TẤT CẢ ready; swap nguyên tử toàn
                   ủy ban; period += 1 (đơn điệu, không lùi).
      recover()  : sau crash - prepare hoàn tất -> commit đi tới; nếu không ->
                   abort (rollback) => không bao giờ trạng thái mơ hồ (180).
      abort()    : hủy vòng, drop candidate, GIỮ nguyên bộ share đang phục vụ.
    GATE phát partial: can_issue_partials() yêu cầu period đồng nhất toàn ủy ban
    và node phải thuộc thế hệ refresh hiện hành (node bị loại -> chặn, 182).
    """

    def __init__(self, parties: Dict[int, RefreshParty], threshold: int,
                 root_provider: Callable[[], str], period: int = 1,
                 signing_pks: Optional[Dict[int, ed25519.Ed25519PublicKey]] = None,
                 allow_stale_parties: bool = False):
        self.parties = parties
        self.t = threshold
        self.root_provider = root_provider          # -> latest trusted root (GĐ2)
        self.period = period
        self.signing_pks = signing_pks or {}
        self.allow_stale_parties = allow_stale_parties
        self.status = IDLE
        self.transcript: Optional[RefreshTranscript] = None
        self.not_refreshed: set = set()
        self.phase_times: Dict[str, List[float]] = {"prepare_ms": [], "commit_ms": []}

        for pid, p in parties.items():
            p.period = period
            p.backup_period = period

    # ------------------------------------------------------------------
    def public_shares(self) -> Dict[int, ECPoint]:
        return {pid: p.active_public_share for pid, p in self.parties.items()}

    def private_share(self, party_id: int) -> int:
        return self.parties[party_id].active_share

    # ------------------------------------------------------------------
    def assert_uniform_period(self):
        """(180) Mọi node phải cùng period - lệch => fail-closed, không phục vụ."""
        periods = {pid: p.period for pid, p in self.parties.items()}
        if len(set(periods.values())) > 1:
            raise RefreshPeriodMismatch(
                f"Node lệch thế hệ (period): {periods} - chặn phát partial, "
                "yêu cầu recover()/restore_from_backup() trước khi phục vụ.")

    # ------------------------------------------------------------------
    def can_issue_partials(self, party_id: int) -> bool:
        """Cổng chặn partial của node: period đồng nhất + thuộc thế hệ hiện hành."""
        try:
            self.assert_uniform_period()
        except RefreshPeriodMismatch:
            return False
        p = self.parties.get(party_id)
        if p is None or p.period != self.period:
            return False
        if not p.refreshed and not self.allow_stale_parties:
            return False          # share cũ bị gate (182) - không âm thầm dùng
        return True

    # ------------------------------------------------------------------
    def issue_partial(self, party_id: int, wrapped: ThresholdWrappedDEK) -> ChaumPedersenProof:
        """
        Node phát partial decryption cho wrap (DLEQ, câu 4) - QUA GATE:
        node lệch thế hệ / share cũ -> RefreshPeriodMismatch, không partial.
        """
        if not self.can_issue_partials(party_id):
            raise RefreshPeriodMismatch(
                f"Node {party_id} KHÔNG được phát partial "
                f"(period={self.parties[party_id].period}, service={self.period}, "
                f"refreshed={self.parties[party_id].refreshed})")
        p = self.parties[party_id]
        d_point = p.active_share * wrapped.c1
        return prove_dleq(party_id, p.active_share, p.active_public_share,
                          wrapped.c1, d_point, wrapped.proof_context())

    # ------------------------------------------------------------------
    def prepare(self, share_tamper: Optional[Callable[[int, int, int], int]] = None,
                hold_delivery: Optional[Callable[[int, int], bool]] = None,
                commitment_tamper: Optional[Callable[[int, List[ECPoint]], List[ECPoint]]] = None
                ) -> RefreshTranscript:
        """
        Round 1-3 của proactive refresh.  Hooks giả lập chaos (mục 176):
          share_tamper(sender, receiver, delta)  -> delta bị sửa trên đường truyền
          hold_delivery(sender, receiver)        -> mất gói (node chết / partition)
          commitment_tamper(pid, commitments)    -> commitment broadcast bị sửa
        """
        if self.status == PENDING:
            raise RefreshAbortError(
                "Đang có refresh PENDING - commit hoặc abort trước khi prepare vòng mới")
        t0 = time.time()
        new_period = self.period + 1
        root = self.root_provider()
        ctx = RefreshTranscript.context_bytes(new_period, root)

        for p in self.parties.values():
            p.inbox.clear()
            p.checks.clear()
            p.complaints = []
            p.candidate_share = None
            p.candidate_public_share = None
            p.ready = False

        # ---- Round 1: broadcast commitment zero-polynomial ----
        commitments: Dict[int, List[ECPoint]] = {}
        for pid, p in self.parties.items():
            commits = p.round1_generate()
            if commitment_tamper is not None:
                commits = commitment_tamper(pid, commits)
            commitments[pid] = list(commits)
            p.commitments = list(commits)

        # ---- Phân phối delta qua kênh riêng (fault-injection) ----
        for sender, p in self.parties.items():
            for receiver in self.parties:
                if hold_delivery is not None and hold_delivery(sender, receiver):
                    continue                      # mất gói: không giao
                delta = p.delta_for(receiver)
                if share_tamper is not None:
                    delta = share_tamper(sender, receiver, delta)
                self.parties[receiver].inbox[sender] = delta

        # ---- Round 2: verify + complaint resolution (hỏi lại 1 lần) ----
        disqualified: set = set()
        for receiver, p in self.parties.items():
            for sender in self.parties:
                res = p.verify_delta(sender, p.inbox.get(sender), commitments[sender])
                if not res.ok:
                    p.complaints.append(sender)
            for sender in p.complaints:
                if hold_delivery is not None and hold_delivery(sender, receiver):
                    disqualified.add(sender)      # re-ask vẫn mất gói -> loại
                    continue
                resend = self.parties[sender].delta_for(receiver)
                if share_tamper is not None:
                    resend = share_tamper(sender, receiver, resend)
                self.parties[receiver].inbox[sender] = resend
                if not p.verify_delta(sender, resend, commitments[sender]).ok:
                    disqualified.add(sender)       # attacker vẫn gửi sai -> loại

        qual = [pid for pid in self.parties if pid not in disqualified]
        if len(qual) < self.t:
            self.status = ABORTED
            for p in self.parties.values():
                p.inbox.clear()
                p.checks.clear()
                p.candidate_share = None
                p.candidate_public_share = None
                p.ready = False
            raise RefreshAbortError(
                f"REFRESH ABORT: QUAL={len(qual)} < t={self.t} "
                f"(disqualified={sorted(disqualified)}) - ROLLBACK về bộ share cũ, "
                "không bao giờ sinh bộ share lệch (fail-closed như DKG-abort, 182).")

        # ---- Round 3: candidate share MỚI (public key không đổi, 166) ----
        base_public = {pid: p.active_public_share for pid, p in self.parties.items()}
        for j in qual:
            p = self.parties[j]
            delta_sum = sum(p.inbox.get(s, 0) for s in qual) % N_ORDER
            candidate = (p.active_share + delta_sum) % N_ORDER
            candidate_pub = p.active_public_share + _horner_sum(commitments, qual, j)
            if candidate * G != candidate_pub:
                self.status = ABORTED
                raise RefreshAbortError(
                    f"Party {j}: candidate share không khớp candidate public share "
                    "- commitment/delta mâu thuẫn, hủy vòng.")
            p.candidate_share = candidate
            p.candidate_public_share = candidate_pub
            p.ready = True

        sigs = {pid: sign_broadcast(self.parties[pid].signing_sk, ctx, pid, commitments[pid])
                for pid in self.parties}
        transcript = RefreshTranscript(
            period=new_period, context=ctx, commitments=commitments, signatures=sigs,
            qualified=qual, disqualified=sorted(disqualified), threshold=self.t,
            base_public_shares=base_public)

        # ---- Kiểm CÔNG KHAI từ transcript (172) trước khi tuyên bố PENDING ----
        problems = transcript.verify_public(new_period, root, self.signing_pks)
        if problems:
            self.status = ABORTED
            raise RefreshAbortError(f"Transcript không qua public verify: {problems}")
        for j in qual:
            if transcript.derived_public_share(j, base_public[j]) != \
                    self.parties[j].candidate_public_share:
                self.status = ABORTED
                raise RefreshAbortError(
                    f"Party {j}: Y'_j suy từ transcript != candidate public share")

        self.transcript = transcript
        self.status = PENDING
        self.phase_times["prepare_ms"].append((time.time() - t0) * 1000)
        return transcript

    # ------------------------------------------------------------------
    def commit(self) -> float:
        """
        COMMIT NGUYÊN TÂN (180): swap toàn ủy ban chỉ khi TẤT CẢ party thuộc
        QUAL đã prepared (party bị loại khỏi QUAL không có candidate và cũng
        KHÔNG được swap - giữ share cũ, bị gate chặn phát partial - 182).
        Period tăng đơn điệu 1 bước cho MỌI node (node đã xác nhận vòng này),
        nên ủy ban luôn đồng nhất period - không có '2 bộ share cùng đúng'.
        """
        if self.status != PENDING or self.transcript is None:
            raise RefreshAbortError(f"commit yêu cầu PENDING (hiện {self.status})")
        qual_ready = set(self.transcript.qualified)
        not_ready = [pid for pid in qual_ready if not self.parties[pid].ready]
        if not_ready:
            raise RefreshAbortError(
                f"COMMIT BARRIER: QUAL {not_ready} chưa prepared - KHÔNG swap một phần "
                "(interrupted refresh không để trạng thái mơ hồ, 180).")
        t0 = time.time()
        tr = self.transcript
        problems = tr.verify_public(tr.period, self.root_provider(), self.signing_pks)
        if problems:
            raise RefreshAbortError(
                f"Root/period đổi giữa prepare và commit -> hủy: {problems}")
        qual = set(tr.qualified)
        for pid, p in self.parties.items():
            if pid in qual and p.candidate_share is not None:
                p.swap_candidate()
            else:
                p.refreshed = False
                self.not_refreshed.add(pid)
            p.period = tr.period
            p.inbox.clear()
            p.checks.clear()
        self.period = tr.period
        self.status = COMMITTED
        elapsed = (time.time() - t0) * 1000
        self.phase_times["commit_ms"].append(elapsed)
        return elapsed

    # ------------------------------------------------------------------
    def abort(self):
        """Hủy vòng: drop candidate, GIỮ bộ share đang phục vụ - không đổi period."""
        for p in self.parties.values():
            p.candidate_share = None
            p.candidate_public_share = None
            p.ready = False
            p.inbox.clear()
            p.checks.clear()
        self.status = ABORTED

    # ------------------------------------------------------------------
    def recover(self) -> str:
        """
        Recovery sau crash (180): prepare hoàn tất cho đủ QUAL -> commit đi tới
        (period đã anchor không lùi được); nếu có party QUAL thiếu candidate
        (crash giữa chừng / node swap-sai-phases) -> abort/rollback.  KHÔNG BAO
        GIỜ có 2 bộ share cùng 'đúng'.
        """
        if self.status == PENDING and self.transcript is not None:
            qual = self.transcript.qualified
            if all(self.parties[pid].ready for pid in qual):
                self.commit()
                return "FORWARD-COMMIT"
            self.abort()
            return "ABORT-ROLLBACK"
        return "NO-OP"


def _horner_sum(commitments: Dict[int, List[ECPoint]], qualified: Iterable[int],
                member_id: int) -> ECPoint:
    """sum_{i in QUAL} sum_k (member_id^k) * C_{i,k} - tính trên group, không secret."""
    acc = ECPoint(None, None)
    for pid in qualified:
        acc = acc + _horner_point(commitments[pid], member_id)
    return acc


# =============================================================================
# 6. RECOVERY GUIDE (deliverable 178)
# =============================================================================
RECOVERY_GUIDE = """
+--------------------------------------------------------------------------------
| RECOVERY GUIDE - PROACTIVE SHARE REFRESH (mục 178/180)
+--------------------------------------------------------------------------------
| A. Chuẩn bị bắt buộc TRƯỚC mỗi vòng refresh:
|    1. Backup có thể khôi phục: node lưu (share, public_share, period) TRƯỚC
|       khi swap -> RefreshParty.backup_* / restore_from_backup().
|    2. Transcript được lưu làm audit: chỉ commitment + chữ ký, không secret.
| B. Sau crash, gọi recover() - KHÔNG tự quyết định tại từng node:
|    - prepare() đã hoàn tất cho TẤT CẢ party  -> FORWARD-COMMIT (period+1).
|    - còn party chưa ready                      -> ABORT-ROLLBACK (share cũ).
| C. Node lệch thế hệ (RefreshPeriodMismatch / can_issue_partials == False):
|    - Nếu là crash-sai-phase: node restore_from_backup() -> chạy lại vòng mới.
|    - Nếu là node rời mạng quá lâu / share cũ: KHÔNG cho phục vụ; loại khỏi
|      committee bằng RESHARING (mục 167) - vì share cũ là compromised-after-use.
| D. Root policy đổi giữa prepare và commit: commit tự hủy (transcript gắn
|    root) -> chạy lại vòng mới với root mới nhất (chống replay, 167/172).
| E. QUAL < t: abort + giữ bộ share cũ; mở rộng committee / sửa node rồi mới
|    retry.  Không bao giờ "nhích" share của 1 mình 1 node để qua mắt barrier.
| F. ĐI CÙNG epoch rewrap (mục 165): refresh giữ nguyên Y nên wrap cũ vẫn
|    unwrap được bằng share cũ - muốn thu hồi phải rewrap DEK dưới epoch mới.
+--------------------------------------------------------------------------------
"""


# =============================================================================
# 7. PIPELINE - dựng môi trường thật (GĐ1+GĐ2+GĐ3 cache)
# =============================================================================
def build_refresh_env(object_id: str = "OBJ-9001", payload_size: int = 256) -> dict:
    """Một môi trường: policy log GĐ1 + oracle GĐ2 + DKG cache + wrap DEK epoch 1."""
    km = key_material()                       # DKG (n=5,t=3) chạy 1 lần, cache
    log = PolicyLogService(ed25519.Ed25519PrivateKey.generate())
    event, _, _ = log.init_policy(object_id, initial_epoch=1)
    ph_ingest = hashlib.sha256(event.canonical_bytes_for_signing()).hexdigest()
    bridge = EngramAnchorBridge(ed25519.Ed25519PrivateKey.generate())
    anchor1 = bridge.anchor_epoch(1, log.mmr)
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

    signing_sks, signing_pks = committee_keygen(N)
    parties = {j: RefreshParty(j, N, T, km["shares"][j], km["pub_shares"][j],
                               signing_sks[j])
               for j in range(1, N + 1)}
    svc = ProactiveRefreshService(parties, T, oracle.get_latest_trusted_root,
                                  period=1, signing_pks=signing_pks)
    return dict(object_id=object_id, log=log, bridge=bridge, oracle=oracle,
                dek=dek, payload=payload, payload_ct=payload_ct, codec=codec,
                ph_ingest=ph_ingest, wrapped=wrapped, svc=svc,
                signing_sks=signing_sks, signing_pks=signing_pks, **km)


def make_committee(n: int, t: int, root_provider: Callable[[], str]):
    """Ủy ban (n,t) tươi từ DKG thật - dùng cho benchmark theo n, t (mục 169)."""
    dkg, _ = run_pedersen_dkg(list(range(1, n + 1)), t)
    sks, pks = committee_keygen(n)
    parties = {j: RefreshParty(j, n, t, dkg.private_shares[j],
                               dkg.public_key_shares[j], sks[j])
               for j in sorted(dkg.private_shares)}
    svc = ProactiveRefreshService(parties, t, root_provider, period=1, signing_pks=pks)
    return svc, dkg


def _banner(title: str):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


# =============================================================================
# 8. DEMO + TESTS (cổng nghiệm thu Giai đoạn 4 - câu 166)
# =============================================================================
if __name__ == "__main__":
    TOTAL_T0 = time.time()
    results = []
    env = build_refresh_env()
    svc: ProactiveRefreshService = env["svc"]
    Y = env["threshold_pk"]

    # =====================================================================
    _banner("TEST 1: REFRESH KHÔNG ĐỔI PUBLIC KEY (mục 166 - 'nếu primitive cho phép')")
    # =====================================================================
    print("- Primitive: share cộng tính trên secp256k1 (Shamir qua lũy thừa).")
    print("  Refresh = x'_j = x_j + g(j) với zero-polynomial g(0)=0.")
    shares_before = {j: svc.private_share(j) for j in svc.parties}
    pubs_before = svc.public_shares()

    tr1 = svc.prepare()
    assert svc.status == PENDING
    print(f"- prepare(): period {svc.period} -> {tr1.period}, status=PENDING "
          f"(share CHƯA đổi - 2 pha, 180)")
    assert svc.private_share(1) == shares_before[1], "PENDING không được đổi share"

    ms = svc.commit()
    assert svc.status == COMMITTED and svc.period == tr1.period == 2
    print(f"- commit(): nguyên tử {ms:.1f} ms, period={svc.period}, status=COMMITTED")

    # (a) sum C_0 == vô cực -> Y bất biến
    assert tr1.key_delta() == ECPoint(None, None)
    print("- key_delta = sum_i C_i,0 = điểm VÔ CỰC  => Y' = Y + 0 = Y (nguyên điểm)")

    # (b) share đã đổi, public share suy từ transcript khớp share thật
    changed = sum(1 for j in svc.parties if svc.private_share(j) != shares_before[j])
    assert changed == len(tr1.qualified)
    for j in tr1.qualified:
        assert svc.private_share(j) * G == svc.public_shares()[j]
        assert tr1.derived_public_share(j, pubs_before[j]) == svc.public_shares()[j]
    print(f"- {changed}/{len(tr1.qualified)} share ĐÃ ĐỔI; Y'_j = share'*G "
          "và khớp transcript suy công khai")

    # (c) với MỌI subset size t: sum lambda_j * Y'_j == Y  (không cần secret)
    subset_ok = 0
    for subset in itertools.combinations(sorted(svc.parties), T):
        acc = ECPoint(None, None)
        for j in subset:
            acc = acc + (lagrange_coefficient(j, list(subset)) * svc.public_shares()[j])
        assert acc == Y
        subset_ok += 1
    print(f"- MỌI {subset_ok} subset C({len(svc.parties)},{T}) nội suy Lagrange trên "
          "Y'_j đều ra đúng Y (public key bất biến)")
    results.append("TEST1 public key unchanged: PASS")

    # =====================================================================
    _banner("TEST 2: TRANSCRIPT KIỂM CHỨNG ĐƯỢC, KHÔNG TỐI LỘ SECRET (mục 172)")
    # =====================================================================
    probs = tr1.verify_public(tr1.period, env["oracle"].get_latest_trusted_root(),
                              env["signing_pks"])
    assert probs == [], probs
    print(f"- verify_public() bởi bên thứ 3 (chỉ có public key ủy ban): HỢP LỆ "
          f"({len(tr1.commitments)} chữ ký Ed25519 trên context {tr1.context!r})")

    # Không rò rĩ share cũ / share mới / hệ số g
    secrets = [shares_before[j] for j in svc.parties] + \
              [svc.private_share(j) for j in svc.parties] + \
              [c for p in svc.parties.values() if p.coeffs for c in p.coeffs]
    leaks = tr1.leak_scan(secrets)
    assert not leaks, leaks
    print(f"- leak_scan trên {len(secrets)} secret (share cũ/mới + hệ số g): "
          "KHÔNG secret nào xuất hiện trong transcript")

    # Tamper 1 commitment -> public verify bắt ngay
    bad_commits = dict(tr1.commitments)
    bad_commits[2] = list(bad_commits[2])
    bad_commits[2][1] = (bad_commits[2][1].x + 1) * G if not bad_commits[2][1].is_infinity() else G
    forged = RefreshTranscript(
        period=tr1.period, context=tr1.context, commitments=bad_commits,
        signatures=tr1.signatures, qualified=tr1.qualified,
        disqualified=tr1.disqualified, threshold=tr1.threshold,
        base_public_shares=tr1.base_public_shares)
    probs_bad = forged.verify_public(tr1.period, env["oracle"].get_latest_trusted_root(),
                                     env["signing_pks"])
    assert any("chữ ký" in p for p in probs_bad), probs_bad
    print(f"- Tamper C_1 của party 2 -> bị bắt: {probs_bad[0]}")

    # Bảo vệ public key khỏi a_0 != 0 ngay cả khi receiver bị mua chuộc
    liar_commits = [(77777) * G, (1234567) * G, (7654321) * G]   # C_0 != vô cực
    key_drift = RefreshTranscript(
        period=tr1.period, context=tr1.context,
        commitments={**tr1.commitments, 4: liar_commits},
        signatures={**tr1.signatures, 4: sign_broadcast(
            env["signing_sks"][4], tr1.context, 4, liar_commits)},
        qualified=tr1.qualified, disqualified=tr1.disqualified,
        threshold=tr1.threshold, base_public_shares=tr1.base_public_shares)
    probs_drift = key_drift.verify_public(tr1.period,
                                          env["oracle"].get_latest_trusted_root(),
                                          env["signing_pks"])
    assert key_drift.key_delta() != ECPoint(None, None)
    assert any("C_0" in p for p in probs_drift), probs_drift
    print("- Party 4 ký broadcast với a_0 != 0 (C_0 != vô cực): public verifier "
          f"báo NGAY: {probs_drift[0][:70]}...")
    results.append("TEST2 transcript publicly verifiable + no leak: PASS")

    # =====================================================================
    _banner("TEST 3: REFRESH GIAN LẬN - TAMPER/ĐỘI LƯNG VỚI Y BỊ LỌC  (mục 182)")
    # =====================================================================
    env3 = build_refresh_env(object_id="OBJ-9003")
    svc3: ProactiveRefreshService = env3["svc"]
    Y3 = env3["threshold_pk"]

    # 3a. Delta bị sửa trên đường truyền -> complaint -> loại khỏi QUAL
    def tamper_hook(sender, receiver, delta):
        return (delta + 4242) % N_ORDER if sender == 5 else delta
    tr3 = svc3.prepare(share_tamper=tamper_hook)
    assert 5 in tr3.disqualified and 5 not in tr3.qualified
    assert tr3.key_delta() == ECPoint(None, None)
    svc3.commit()
    print(f"- share_tamper(5->*) : party 5 bị LOẠI, QUAL={tr3.qualified} (>= t) "
          f"- key_delta vẫn vô cực => Y giữ nguyên")
    acc = ECPoint(None, None)
    qual3 = list(tr3.qualified)
    for j in qual3:
        acc = acc + (lagrange_coefficient(j, qual3) * svc3.public_shares()[j])
    assert acc == Y3
    print(f"- Lagrange trên QUAL={qual3} (cùng thế hệ) -> ra đúng Y; party 5 "
          "(share thế hệ cũ) KHÔNG trộn được vào - trộn thế hệ sẽ fail-closed")
    print(f"- party 5 vẫn GIỮ share cũ -> bị GATE chặn: "
          f"can_issue_partials(5)={svc3.can_issue_partials(5)} (182 - share cũ "
          "không được âm thầm dùng)")

    # 3b. Mất gói kéo dài (node chết) -> QUAL < t -> ABORT + ROLLBACK nguyên tử
    env3b = build_refresh_env(object_id="OBJ-9003b")
    svc3b: ProactiveRefreshService = env3b["svc"]
    snapshot = {j: svc3b.private_share(j) for j in svc3b.parties}
    dead = {3, 4, 5}

    def hold_all_from_dead(sender, receiver):
        return sender in dead
    try:
        svc3b.prepare(hold_delivery=hold_all_from_dead)
        raise AssertionError("phải abort khi QUAL < t")
    except RefreshAbortError as err:
        print(f"- 3 node chết -> {err}")
    assert svc3b.status == ABORTED and svc3b.period == 1
    assert all(svc3b.private_share(j) == snapshot[j] for j in svc3b.parties)
    print("- ROLLBACK nguyên tử: period=1, MỌI share giữ nguyên, status=ABORTED "
          "(không trạng thái mơ hồ, 180)")

    # Retry không fault -> thành công (liveness quay lại)
    tr3b = svc3b.prepare()
    svc3b.commit()
    assert svc3b.period == 2
    print(f"- Retry không fault: QUAL={tr3b.qualified}, period={svc3b.period} "
          "(liveness phục hồi sau khi sửa node)")
    results.append("TEST3 malicious refresh + abort/rollback: PASS")

    # =====================================================================
    _banner("TEST 4: E2E SAU REFRESH - KHÔNG REWRAP, KHÔNG RE-ENCRYPT (mục 171)")
    # =====================================================================
    env4 = build_refresh_env(object_id="OBJ-9004")
    svc4: ProactiveRefreshService = env4["svc"]
    wrapped_old = env4["wrapped"]                     # bọc DƯỚI Y từ TRƯỚC refresh
    digest_old = wrap_digest(wrapped_old)

    tr4 = svc4.prepare()
    svc4.commit()
    assert wrap_digest(wrapped_old) == digest_old, "wrap không được động tới"
    print(f"- Wrap epoch 1 bọc trước refresh, digest giữ nguyên: {digest_old[:16]}...")
    print(f"- Public key Y không đổi => wrap CŨ vẫn unwrap được, KHÔNG rewrap (171)")

    policy_db = env4["log"].policy_records
    root1 = env4["oracle"].get_latest_trusted_root()

    # GĐ2 gate trước khi phát partial (oracle phải còn tươi + policy ACTIVE)
    env4["oracle"].resolve_fresh_policy(env4["object_id"], root1, policy_db)

    def unwrap_with(subset):
        # issue_partial đi qua GATE period của refresh + prove_dleq (câu 4)
        proofs = [svc4.issue_partial(j, wrapped_old) for j in subset]
        comb = ThresholdCombiner(svc4.public_shares(), T)
        return comb.combine(proofs, wrapped_old).dek

    subsets = list(itertools.combinations(sorted(svc4.parties), T))
    for subset in (subsets[0], subsets[len(subsets) // 2], subsets[-1]):
        assert unwrap_with(list(subset)) == env4["dek"]
    print(f"- Unwrap DEK từ 3 subset khác nhau của {len(subsets)} subset size t: "
          "toàn bộ trả về đúng DEK (t node bất kỳ vẫn phục vụ)")

    # Đối chiếu pipeline câu 3 với share MỚI (node qua oracle GĐ2 + proof compact)
    nodes4 = {j: ThresholdWrapNode(j, svc4.private_share(j),
                                   svc4.public_shares()[j], T, oracle=env4["oracle"])
              for j in svc4.parties}
    sub0 = list(subsets[0])
    compact = [nodes4[j].create_partial(wrapped_old, presented_policy_root=root1,
                                        policy_db=policy_db) for j in sub0]
    assert all(verify_partial(c, svc4.public_shares()[c.party_id],
                              wrapped_old.c1, wrapped_old.proof_context())
               for c in compact)
    assert combine_and_unwrap(compact, svc4.public_shares(), T, wrapped_old) == env4["dek"]
    print("- Pipeline câu 3 (ThresholdWrapNode + proof compact) với share SAU refresh: "
          "verify_partial từng node + combine -> cùng DEK")

    # Payload ciphertext KHÔNG bị re-encrypt (171/181)
    plain = decrypt_payload(env4["dek"], env4["payload_ct"], env4["object_id"], 1,
                            env4["ph_ingest"], env4["codec"])
    assert plain == env4["payload"]
    print("- Payload ciphertext GIỮ NGUYÊN từ trước refresh -> giải mã đúng "
          "(không re-encrypt payload để refresh share)")
    results.append("TEST4 no rewrap/no re-encrypt E2E: PASS")

    # =====================================================================
    _banner("TEST 5: SHARE CŨ = COMPROMISED-AFTER-USE - CLAIM TRUNG THỰC (173)")
    # =====================================================================
    env5 = build_refresh_env(object_id="OBJ-9005")
    svc5: ProactiveRefreshService = env5["svc"]
    old_shares = {j: svc5.private_share(j) for j in svc5.parties}
    old_pubs = svc5.public_shares()

    svc5.prepare()
    svc5.commit()
    new_shares = {j: svc5.private_share(j) for j in svc5.parties}
    new_pubs = svc5.public_shares()

    wrapped5 = env5["wrapped"]

    def proof_with(share, pub, j):
        d = share * wrapped5.c1
        return prove_dleq(j, share, pub, wrapped5.c1, d, wrapped5.proof_context())

    # (a) Mobile adversary: 2 share cũ (kém t) -> không làm được gì
    comb_new = ThresholdCombiner(new_pubs, T)
    try:
        comb_new.combine([proof_with(old_shares[j], old_pubs[j], j) for j in (1, 2)],
                         wrapped5)
        raise AssertionError("2 partial phải fail-closed")
    except InsufficientPartials as err:
        print(f"- Kẻ thù di động giữ 2 share CŨ: {err.report.accepted_ids} hợp lệ "
              f"/ {T} yêu cầu -> fail-closed: {str(err)[:48]}...")

    # (b) Registry MỚI (Y'_j): proof share cũ (hợp lệ với Y_j cũ) bị verifier TỪ CHỐI
    stale_proof = proof_with(old_shares[3], old_pubs[3], 3)      # proof hợp lệ... với Y_3 cũ
    verdicts = comb_new.classify([stale_proof], wrapped5.c1, wrapped5.proof_context())
    assert not verdicts[0].accepted and verdicts[0].reason == "dleq-invalid"
    print(f"- Proof share cũ của party 3 (hợp lệ với Y_3 cũ) dưới registry Y'_j mới: "
          f"verdict={verdicts[0].reason} -> verifier độc lập từ chối (câu 4)")
    # Thêm: prover TỪ CHỐI ghép share cũ với Y'_j mới (witness nhất quán)
    try:
        prove_dleq(3, old_shares[3], new_pubs[3], wrapped5.c1,
                   old_shares[3] * wrapped5.c1, wrapped5.proof_context())
        raise AssertionError("prove_dleq phải từ chối witness lệch thế hệ")
    except ValueError as err:
        print(f"- prove_dleq tự chặn trước: '{err}'")

    # (c) Trộn 2 thế hệ: DLEQ từng phần ĐẠT (registry đúng thế hệ) nhưng Lagrange
    #     trên chỉ số trộn KHÔNG tái tạo x -> AEAD tag fail (bảo vệ mobile adv.)
    mixed_registry = {1: old_pubs[1], 2: old_pubs[2], 3: new_pubs[3],
                      4: new_pubs[4], 5: new_pubs[5]}
    mixed_proofs = [proof_with(old_shares[1], old_pubs[1], 1),
                    proof_with(old_shares[2], old_pubs[2], 2),
                    proof_with(new_shares[3], new_pubs[3], 3),
                    proof_with(new_shares[4], new_pubs[4], 4)]
    comb_mixed = ThresholdCombiner(mixed_registry, T)
    report = comb_mixed.classify(mixed_proofs, wrapped5.c1, wrapped5.proof_context())
    assert all(v.accepted for v in report), report
    try:
        comb_mixed.combine(mixed_proofs, wrapped5)
        raise AssertionError("trộn thế hệ phải fail")
    except InsufficientPartials as err:
        print(f"- Trộn share 2 thế hệ: cả {len(mixed_proofs)} partial DLEQ ĐẠT nhưng "
              f"AEAD tag sai (Lagrange trộn != x) -> fail-closed: {str(err)[:44]}...")

    # (d) TRUNG THỰC (173): 3 share CŨ + registry CŨ vẫn unwrap wrap CŨ
    comb_stale_client = ThresholdCombiner(old_pubs, T)
    dek_stale = comb_stale_client.combine(
        [proof_with(old_shares[j], old_pubs[j], j) for j in (1, 2, 3)], wrapped5).dek
    assert dek_stale == env5["dek"]
    print("- TRUNG THỰC: client CHƯA cập nhật registry + 3 share CŨ vẫn unwrap được "
          "wrap cũ  =>  refresh KHÔNG thu hồi wrap;")
    print("  => mobile adversary cần t share CÙNG thế hệ; muốn thu hồi wrap cũ phải "
          "epoch rewrap (mục 165/câu 1) - không thổi phồng forward-security.")
    results.append("TEST5 old material compromised-after-use (trung thực): PASS")

    # =====================================================================
    _banner("TEST 6: INTERRUPTED REFRESH - KHÔNG TRẠNG THÁI MƠ HỒ (mục 180/181)")
    # =====================================================================
    env6 = build_refresh_env(object_id="OBJ-9006")
    svc6: ProactiveRefreshService = env6["svc"]

    # 6a. Crash ngay SAU prepare (tất cả ready) -> recover() commit đi tới
    tr6 = svc6.prepare()
    assert svc6.status == PENDING
    outcome = svc6.recover()
    assert outcome == "FORWARD-COMMIT" and svc6.period == tr6.period == 2
    print(f"- Crash sau khi prepare hoàn tất: recover() -> {outcome}, period={svc6.period}")

    # 6b. Node swap SAI PHASE (swap sớm 1 mình) -> recover() abort -> GATE chặn
    tr6b = svc6.prepare()
    rogue = svc6.parties[3]
    assert rogue.ready
    rogue.swap_candidate()          # swap local trước khi toàn ủy ban commit
    rogue.period = tr6b.period      # tự nhận period mới
    assert len({p.period for p in svc6.parties.values()}) > 1
    try:
        svc6.assert_uniform_period()
        raise AssertionError("phải phát hiện period lệch")
    except RefreshPeriodMismatch as err:
        print(f"- Party 3 swap sớm 1 mình -> {err}")
    assert not svc6.can_issue_partials(3) and not svc6.can_issue_partials(1)
    print("- GATE: can_issue_partials = False cho TẤT CẢ node -> không partial nào "
          "được phát khi ủy ban lệch thế hệ (fail-closed)")

    outcome = svc6.recover()
    assert outcome == "ABORT-ROLLBACK" and svc6.period == 2
    print(f"- recover(): {outcome} - period KHÔNG đổi (2), ủy ban chưa swap -> "
          "trạng thái duy nhất, không mơ hồ")

    # Resync: node lỗi lùi về backup known-good -> ủy ban đồng nhất lại
    rogue.restore_from_backup()
    svc6.assert_uniform_period()
    assert svc6.can_issue_partials(1) and svc6.can_issue_partials(3)
    print("- Party 3 restore_from_backup() -> period đồng nhất, GATE mở lại")

    # Chạy lại vòng mới thành công
    tr6c = svc6.prepare()
    svc6.commit()
    assert svc6.period == tr6c.period == 3
    print(f"- Vòng mới sau resync: period={svc6.period} (không lùi, đơn điệu)")

    # 6c. Node chết kéo dài nhưng QUAL >= t -> refresh vẫn xong, node chết BỊ GATE
    env6c = build_refresh_env(object_id="OBJ-9006c")
    svc6c: ProactiveRefreshService = env6c["svc"]
    tr6c2 = svc6c.prepare(hold_delivery=lambda s, r: s in {4, 5})
    svc6c.commit()
    assert tr6c2.disqualified == [4, 5] and len(tr6c2.qualified) == T
    assert svc6c.can_issue_partials(1) and not svc6c.can_issue_partials(4)
    print(f"- 2 node chết: QUAL={tr6c2.qualified} (đúng t) -> vẫn refresh được; "
          "node 4/5 giữ share cũ -> can_issue_partials=False (182)")
    results.append("TEST6 interrupted refresh + recovery: PASS")

    # =====================================================================
    _banner("TEST 7: ROOT POLICY ĐỔI -> REPLAY TRANSCRIPT CŨ BỊ TỪ CHỐI (167/172)")
    # =====================================================================
    env7 = build_refresh_env(object_id="OBJ-9007")
    svc7: ProactiveRefreshService = env7["svc"]
    tr7 = svc7.prepare()
    svc7.commit()
    root_old = env7["oracle"].get_latest_trusted_root()
    assert tr7.context == RefreshTranscript.context_bytes(2, root_old)

    # Quay epoch chính sách (SUSPENDED -> ACTIVE) -> root mới, epoch 2 (GĐ1+GĐ2)
    env7["log"].transition_policy(env7["object_id"], "SUSPENDED")
    env7["log"].transition_policy(env7["object_id"], "ACTIVE")
    anchor2 = env7["bridge"].anchor_epoch(2, env7["log"].mmr)
    proof_1_2 = env7["bridge"].get_consistency_proof(1, 2)
    root_new = env7["oracle"].sync_latest_trusted_root(anchor2, consistency_proof=proof_1_2)
    assert root_new != root_old
    print(f"- Root rotation: {root_old[:16]}... -> {root_new[:16]}... (epoch 2)")

    replay = tr7.verify_public(tr7.period, root_new, env7["signing_pks"])
    assert any("context sai" in p for p in replay), replay
    print(f"- Replay transcript cũ dưới root mới: {replay[0][:56]}... -> BỊ TỪ CHỐI")

    # Ký lại broadcast của ROUND 1 dưới context mới bằng CHỮ KÝ CŨ -> fail
    try:
        env7["signing_pks"][1].verify(tr7.signatures[1],
                                      broadcast_bytes(RefreshTranscript.context_bytes(
                                          tr7.period, root_new), 1, tr7.commitments[1]))
        raise AssertionError("chữ ký cũ phải fail dưới context mới")
    except InvalidSignature:
        print("- Chữ ký broadcast cũ dưới context period/root mới: InvalidSignature "
              "(transcript gắn epoch + policy root, chống replay 167)")
    results.append("TEST7 root rotation replay rejection: PASS")

    # =====================================================================
    _banner("BENCHMARK REFRESH THEO n, t (mục 169/180)")
    # =====================================================================
    fake_root = lambda: "ab" * 32
    for (bn, bt) in [(3, 2), (5, 3), (7, 4)]:
        bsvc, _ = make_committee(bn, bt, fake_root)
        t0 = time.time()
        btr = bsvc.prepare()
        prep_ms = (time.time() - t0) * 1000
        t0 = time.time()
        bsvc.commit()
        comm_ms = (time.time() - t0) * 1000
        t0 = time.time()
        probs = btr.verify_public(btr.period, fake_root(), bsvc.signing_pks)
        verify_ms = (time.time() - t0) * 1000
        assert not probs
        print(f"- n={bn}, t={bt}: prepare {prep_ms:6.1f} ms | commit {comm_ms:5.1f} ms "
              f"| public verify {verify_ms:5.1f} ms | "
              f"commitment/node {prep_ms / bn:5.1f} ms")
    print("- Chi phí chủ yếu: n*(t-1) scalar-mul commitment (256-bit, pure Python);")
    print("  Horner xác minh delta/Y'_j dùng scalar NHỎ (j^k) nên rất rẻ.")

    # =====================================================================
    _banner("RECOVERY GUIDE (deliverable 178)")
    # =====================================================================
    print(RECOVERY_GUIDE)

    # =====================================================================
    _banner("KẾT LUẬN")
    # =====================================================================
    for r in results:
        print(f"  {r}")
    print(f"  Tổng thời gian demo: {time.time() - TOTAL_T0:.2f} s")
    print("  => Proactive refresh cộng thêm zero-polynomial g(0)=0: share đổi,")
    print("     public key Y NGUYÊN ĐIỂM (kiểm lại được công khai từ transcript);")
    print("     transcript chỉ có commitment + chữ ký, không lộ secret;")
    print("     prepare/commit 2 pha + recover() => interrupted refresh không bao")
    print("     giờ để trạng thái mơ hồ; share cũ là compromised-after-use và bị")
    print("     gate chặn - thu hồi wrap cũ phải epoch rewrap (câu 165).")
    print("  LƯU Ý: prototype academic, chưa audit - không dùng production.")
