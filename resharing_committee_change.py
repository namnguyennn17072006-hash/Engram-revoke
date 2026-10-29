"""
================================================================================
GIAI ĐOẠN 4 - RESHARING KHI THAY THRESHOLD / COMMITTEE MEMBERSHIP
Lời giải câu: "Cài resharing khi thay threshold hoặc committee membership."

================================================================================
"""

import os
import time
import hashlib
import random
import itertools
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# --- Câu 1: toán học EC + Lagrange + DKG (Mode B) ----------------------------
from dkg_threshold_service import (
    ECPoint,
    G,
    N_ORDER,
    evaluate_polynomial,
    lagrange_coefficient,
    run_pedersen_dkg,
    DKGParty,
)

# --- Câu 2: broadcast có chữ ký + bộ key ủy ban ------------------------------
from vss_share_verification import (
    broadcast_bytes,
    sign_broadcast,
    committee_keygen,
    ShareCheckResult,
)

# --- Câu 3 + 4 + 5: wrap/partial/DLEQ/combiner -------------------------------
from wrap_dek_partial_decryption import (
    WrapContext,
    ThresholdWrappedDEK,
    wrap_dek,
    ThresholdWrapNode,
    verify_partial,
    combine_and_unwrap,
)
from chaum_pedersen_partial_proof import prove_dleq, ChaumPedersenProof
from combiner_filter_and_combine import ThresholdCombiner, InsufficientPartials

# --- GĐ4 câu 2: tái dùng Horner + lỗi + key cache ----------------------------
from proactive_share_refresh import (
    _horner_point,
    RefreshAbortError,
    RefreshPeriodMismatch,
)

# --- GĐ4 câu 1: epoch rewrap + payload helpers + build_env ------------------
from epoch_transition_rewrap import (
    encrypt_payload,
    decrypt_payload,
    wrap_digest,
    EpochRewrapService,
    safe_create_partial,
    rewrap_via_committee,
    batch_rewrap_worker,
    issue_capability,
    key_material,
)

# --- GĐ1: capability (old capability ở epoch mới) ----------------------------
from capabilityverifier import CapabilityVerifier
from capabilityverifier import SecurityError as CapabilitySecurityError

# --- GĐ1 & GĐ2 ---------------------------------------------------------------
from signedandapend_events import PolicyLogService
from anchorroot import EngramAnchorBridge
from freshnesswindowandlatesttrustedroot import (
    KeyNodeTrustedRootOracle,
    FreshnessWindowConfig,
)

_RNG = random.SystemRandom()

N, T = 5, 3                                    # ủy ban CŨ mặc định (câu 1)

# Vai trò trong một vòng resharing
RETURNING = "returning"    # member cũ = dealer + nhận share mới
RETIRING = "retiring"      # member cũ CHỈ là dealer (rời ủy ban sau round)
JOINING = "joining"        # thành viên mới (không có share cũ)

# Trạng thái service (181 - không bao giờ mơ hồ)
IDLE, PENDING, COMMITTED, ABORTED = "IDLE", "PENDING", "COMMITTED", "ABORTED"


# =============================================================================
# 1. LỖI FAIL-CLOSED (kế thừa ngữ nghĩa câu 2)
# =============================================================================
class ReshareAbortError(RefreshAbortError):
    """Reshare bị hủy - ROLLBACK, không bao giờ sinh bộ share lệch."""


class ResharePeriodMismatch(RefreshPeriodMismatch):
    """Member lệch thế hệ sau resharing - chặn phát partial tới khi resync."""


# =============================================================================
# 2. HORNER TRÊN GROUP - suy Y'_j từ COMMITMENT (không cần secret, 172)
# =============================================================================
def _horner_sum(commitments: Dict[int, List[ECPoint]], dealer_ids, member_id: int) -> ECPoint:
    """Y'_j = sum_{i in dealers} sum_k (j^k) * C_{i,k} - tính trên group."""
    acc = ECPoint(None, None)
    for pid in dealer_ids:
        acc = acc + _horner_point(commitments[pid], member_id)
    return acc


# =============================================================================
# 3. RESHARING TRANSCRIPT - công khai, không secret, gắn period+root (172/168)
# =============================================================================
@dataclass
class ReshareTranscript:
    """
    Bản ghi công khai của một vòng resharing:
      - context = "reshare|from=P|to=P'|root=R|n=|t=" (gắn period + policy root
        GĐ2 + shape ủy ban MỚI) -> chống replay transcript cũ (168/172);
      - commitments của MỖI dealer: C_{i,0} = lambda_i*Y_i (PUBLIC),
        C_{i,k} = a_{i,k}*G (k >= 1);
      - chữ ký Ed25519 của dealer trên broadcast (tái dùng câu 2).
    KHÔNG phần tử nào là scalar bí mật (x_i, a_{i,k}).
    """

    period_from: int
    period_to: int
    context: str
    commitments: Dict[int, List[ECPoint]]
    signatures: Dict[int, bytes]
    dealers: List[int]                  # ban phân phát = member cũ
    member_ids: List[int]               # ủy ban MỚI
    threshold_old: int
    threshold_new: int
    old_public_shares: Dict[int, ECPoint]

    # ------------------------------------------------------------------
    @staticmethod
    def context_bytes(period_from: int, period_to: int, policy_root: str,
                      n_new: int, t_new: int) -> str:
        return (f"reshare|from={period_from}|to={period_to}|root={policy_root}"
                f"|n={n_new}|t={t_new}")

    # ------------------------------------------------------------------
    def key_invariant(self) -> List[str]:
        """
        BẤT BIẾN (167): C_{i,0} PHẢI đúng lambda_i(S)*Y_i với S = tập dealers
        => secret mới x' = sum_{i in S} lambda_i*x_i = x cũ  => Y' = Y.
        Dealer nào C_0 lệch = đang thay secret NGẦM -> bị bắt ngay bằng mắt
        thường (lambda_i suy được công khai từ S và chỉ số i).
        """
        problems = []
        for pid in self.dealers:
            c0 = self.commitments[pid][0]
            lam = lagrange_coefficient(pid, self.dealers)
            expect = lam * self.old_public_shares.get(pid, ECPoint(None, None))
            if c0 != expect:
                problems.append(
                    f"dealer {pid}: C_0 ({c0.to_bytes().hex()[:16]}...) != "
                    f"lambda_i*Y_i ({expect.to_bytes().hex()[:16]}...) -> "
                    "secret sẽ bị thay NGẦM (167)")
        return problems

    # ------------------------------------------------------------------
    def derived_public_share(self, member_id: int) -> ECPoint:
        """BẤT KỲ AI suy được Y'_j từ transcript - không cần secret (172)."""
        return _horner_sum(self.commitments, self.dealers, member_id)

    # ------------------------------------------------------------------
    def verify_public(self, expected_context: str,
                      signing_pks: Dict[int, ed25519.Ed25519PublicKey]) -> List[str]:
        """Independent public verifier - chỉ cần public key ủy ban."""
        problems: List[str] = []
        if self.context != expected_context:
            problems.append(
                f"context sai (replay từ period/root khác?) có={self.context!r}")
        if len(self.dealers) < self.threshold_new:
            problems.append(
                f"dealers={len(self.dealers)} < t_new={self.threshold_new}")
        if len(self.member_ids) < self.threshold_new:
            problems.append(
                f"members={len(self.member_ids)} < t_new={self.threshold_new}")
        problems += self.key_invariant()
        for pid in self.dealers:
            commits = self.commitments.get(pid)
            if not commits:
                problems.append(f"dealer {pid}: thiếu commitment")
                continue
            pk = signing_pks.get(pid)
            if pk is None:
                problems.append(f"dealer {pid}: không có public key tin cậy")
                continue
            sig = self.signatures.get(pid)
            if sig is None:
                problems.append(f"dealer {pid}: thiếu chữ ký broadcast")
                continue
            try:
                pk.verify(sig, broadcast_bytes(self.context, pid, commits))
            except (InvalidSignature, ValueError):
                problems.append(
                    f"dealer {pid}: chữ ký broadcast sai (tampered/replay)")
        return problems

    # ------------------------------------------------------------------
    def to_public_dump(self) -> str:
        parts = [f"ctx={self.context}",
                 "members=" + ",".join(map(str, self.member_ids))]
        for pid in sorted(self.commitments):
            parts.append(f"C{pid}=" + ",".join(c.to_bytes().hex()
                                               for c in self.commitments[pid]))
            parts.append(f"sig{pid}=" + self.signatures[pid].hex())
        return "|".join(parts)

    # ------------------------------------------------------------------
    def leak_scan(self, secrets) -> List[str]:
        """(172) Secret scalar nào bị in vào transcript -> báo cáo."""
        dump = self.to_public_dump()
        leaks = []
        for s in secrets:
            if s is None or s % N_ORDER == 0:
                continue
            if format(s % N_ORDER, "064x") in dump:
                leaks.append(f"scalar {format(s % N_ORDER, '064x')[:16]}... "
                             "xuất hiện trong transcript")
        return leaks


# =============================================================================
# 4. RESHARE PARTY - 1 cá thể vừa dealer vừa/hoặc member
# =============================================================================
class ReshareParty:
    """
    Một cá thể trong vòng resharing:
      - is_dealer (returning/retiring): giữ x_i cũ, sinh poly bậc (t_new-1)
        với hằng số CHÍNH LÀ x_i, broadcast C_{i,0}=Y_i, gửi share cho member.
      - is_member (returning/joining): nhận s_{i,j} từ MỌI dealer, tự xác minh
        (Feldman), cộng lại thành x'_j - CHỈ có 1 bộ share đang phục vụ.
    active_*  : bộ share ĐANG PHỤC VỤ (duy nhất 1 bộ - không half-state, 181)
    backup_*  : ảnh chụp trước swap -> crash-sai-phase restore được
    candidate_*: bộ share MỚI sau prepare, CHƯA active cho tới commit nguyên tử
    """

    def __init__(self, party_id: int, role: str, threshold_new: int,
                 old_share: Optional[int] = None,
                 old_public: Optional[ECPoint] = None,
                 signing_sk: Optional[ed25519.Ed25519PrivateKey] = None,
                 rng: Optional[random.Random] = None):
        if role not in (RETURNING, RETIRING, JOINING):
            raise ValueError(f"role không hợp lệ: {role}")
        self.party_id = party_id
        self.role = role
        self.t_new = threshold_new
        self.signing_sk = signing_sk
        self.rng = rng or _RNG

        self.old_share = None if old_share is None else old_share % N_ORDER
        self.old_public = old_public
        self.is_dealer = role in (RETURNING, RETIRING)
        self.is_member = role in (RETURNING, JOINING)

        # Share đang phục vụ: returning bắt đầu bằng share cũ (vẫn hợp lệ dưới
        # Y vì secret không đổi); joining chưa có gì cho tới khi commit.
        self.active_share = self.old_share if role == RETURNING else None
        self.active_public = self.old_public if role == RETURNING else None
        self.backup_share = self.active_share
        self.backup_public = self.active_public
        self.backup_period: Optional[int] = None      # ảnh chụp known-good (181)

        # Vòng resharing hiện tại
        self.coeffs: Optional[List[int]] = None
        self.commitments: Optional[List[ECPoint]] = None
        self.inbox: Dict[int, int] = {}
        self.checks: Dict[int, ShareCheckResult] = {}
        self.complaints: List[int] = []
        self.candidate_share: Optional[int] = None
        self.candidate_public: Optional[ECPoint] = None
        self.ready = False
        self.period: Optional[int] = None

    # ------------------------------------------------------------------
    def round1_generate(self, dealer_ids: List[int]) -> List[ECPoint]:
        """
        Sinh poly mới bậc (t_new-1) với HẰNG SỐ = lambda_i * x_i:
            f_i(0) = lambda_i(S) * x_i     (S = tập dealer, |S| >= t_old)
            =>  sum_{i in S} f_i(0) = sum lambda_i*x_i = x  =>  Y' = Y
        C_{i,0} = f_i(0)*G = lambda_i * Y_i  -> PUBLIC (lambda_i và Y_i đều
        công khai) - đây là trái tim của resharing "giữ secret" (167).
        """
        if not self.is_dealer:
            raise RuntimeError(f"party {self.party_id} không phải dealer")
        if self.old_share is None:
            raise RuntimeError("dealer phải có share cũ")
        lam = lagrange_coefficient(self.party_id, dealer_ids)
        const = (lam * self.old_share) % N_ORDER
        self.coeffs = [const] + \
            [self.rng.randrange(1, N_ORDER) for _ in range(self.t_new - 1)]
        self.commitments = [c * G for c in self.coeffs]
        return list(self.commitments)

    # ------------------------------------------------------------------
    def share_for(self, receiver_id: int) -> int:
        """s_{i,j} = f_i(j) gửi qua kênh riêng (prototype: in-memory)."""
        if self.coeffs is None:
            raise RuntimeError("round1_generate chưa chạy")
        return evaluate_polynomial(self.coeffs, receiver_id)

    # ------------------------------------------------------------------
    def verify_share_from(self, dealer_id: int, share: Optional[int],
                          commitments: List[ECPoint]) -> ShareCheckResult:
        """Member TỰ kiểm share của từng dealer (equation Feldman, câu 1)."""
        if share is None:
            res = ShareCheckResult(self.party_id, dealer_id, False, "reshare",
                                   "không nhận được share (mất gói / node chết)")
        elif not DKGParty.verify_share(self.party_id, share, commitments):
            res = ShareCheckResult(
                self.party_id, dealer_id, False, "reshare",
                f"vi phạm Feldman: {share}*G != sum(j^k*C_k) "
                f"với j={self.party_id}")
        else:
            res = ShareCheckResult(self.party_id, dealer_id, True, "reshare", "OK")
        self.checks[dealer_id] = res
        return res

    # ------------------------------------------------------------------
    def swap_candidate(self):
        """Hoán đổi nguyên tử TẠI MEMBER: backup <- active cũ, active <- mới."""
        self.backup_share = self.active_share
        self.backup_public = self.active_public
        self.backup_period = self.period
        self.active_share = self.candidate_share
        self.active_public = self.candidate_public
        self.candidate_share = None
        self.candidate_public = None
        self.ready = False

    # ------------------------------------------------------------------
    def restore_from_backup(self):
        """(181) Member swap-sai-phase lùi về ảnh chụp known-good
        (share, public share VÀ period - không bao giờ để lệch thế hệ)."""
        self.active_share = self.backup_share
        self.active_public = self.backup_public
        if self.backup_period is not None:
            self.period = self.backup_period
        self.candidate_share = None
        self.candidate_public = None
        self.ready = False


# =============================================================================
# 5. RESHARING SERVICE - prepare/commit 2 pha + barrier + recovery (181)
# =============================================================================
class ResharingService:
    """
    Điều phối một vòng resharing (Mode A - giữ secret, Y bất biến):
      prepare_reshare() : dealer broadcast commitment (C_0 = lambda_i*Y_i) + phân phát
                          share -> member verify + complaint -> candidate.
                          Trạng thái PENDING (share CHƯA đổi).
      commit()          : BARRIER - chỉ swap khi TẤT CẢ member đã prepared;
                          swap nguyên tử; period += 1 (đơn điệu).
      recover()         : sau crash - prepare hoàn tất -> commit đi tới;
                          thiếu member -> abort/rollback (181 - không mơ hồ).
      abort()           : drop candidate, GIỮ share đang phục vụ + đồng bộ
                          period lệch (member swap-sai-phase lùi backup, 181).
    BẤT BIẾN: sum_j lambda_j Y'_j = f'(0) = sum_{i in S} lambda_i*x_i = x cũ
    CỔNG (182): member retiring / lệch thế hệ -> can_issue_partials() = False.
    """

    def __init__(self, parties: Dict[int, ReshareParty], threshold_old: int,
                 threshold_new: int, root_provider: Callable[[], str],
                 signing_pks: Optional[Dict[int, ed25519.Ed25519PublicKey]] = None,
                 period: int = 1):
        self.parties = parties
        self.dealer_ids = sorted(pid for pid, p in parties.items() if p.is_dealer)
        self.member_ids = sorted(pid for pid, p in parties.items() if p.is_member)
        self.t_old = threshold_old
        self.t_new = threshold_new
        self.root_provider = root_provider
        self.signing_pks = signing_pks or {}
        self.period = period
        self.status = IDLE
        self.transcript: Optional[ReshareTranscript] = None
        self.retired_ids: set = set()
        self.phase_times: Dict[str, List[float]] = {"prepare_ms": [], "commit_ms": []}
        for p in parties.values():
            p.period = period

    # ------------------------------------------------------------------
    def public_shares(self) -> Dict[int, ECPoint]:
        """Registry public share của ủy ban MỚI (client dùng để verify DLEQ)."""
        return {pid: self.parties[pid].active_public for pid in self.member_ids}

    def private_share(self, party_id: int) -> int:
        return self.parties[party_id].active_share

    # ------------------------------------------------------------------
    def _context_for(self, period_to: int, root: str) -> str:
        return ReshareTranscript.context_bytes(
            self.period, period_to, root, len(self.member_ids), self.t_new)

    # ------------------------------------------------------------------
    def assert_uniform_period(self):
        """(181) Mọi member phải cùng period - lệch => fail-closed."""
        periods = {pid: self.parties[pid].period for pid in self.member_ids}
        if len(set(periods.values())) > 1:
            raise ResharePeriodMismatch(
                f"Member lệch thế hệ (period): {periods} - chặn phát partial, "
                "yêu cầu recover()/restore_from_backup() trước khi phục vụ.")

    # ------------------------------------------------------------------
    def can_issue_partials(self, party_id: int) -> bool:
        """
        Cổng phát partial:
        - member retiring (rời ủy ban)      -> False   (182: share cũ không
          được âm thầm dùng dù vẫn hợp lệ toán học dưới Y);
        - period lệch                       -> False   (181);
        - member chưa có share (joining chờ commit) -> False.
        Lưu ý trung thực: trong lúc PENDING, member returning vẫn phục vụ
        bằng share CŨ (Y không đổi nên share cũ vẫn đúng) - chỉ member
        MỚI phải đợi commit.
        """
        if party_id not in self.member_ids:
            return False
        try:
            self.assert_uniform_period()
        except ResharePeriodMismatch:
            return False
        return self.parties[party_id].active_share is not None

    # ------------------------------------------------------------------
    def issue_partial(self, party_id: int, wrapped: ThresholdWrappedDEK) -> ChaumPedersenProof:
        """Member phát partial decryption (DLEQ, câu 4) - QUA GATE period."""
        if not self.can_issue_partials(party_id):
            raise ResharePeriodMismatch(
                f"Member {party_id} KHÔNG được phát partial "
                f"(role={self.parties[party_id].role}, "
                f"period={self.parties[party_id].period}, service={self.period})")
        p = self.parties[party_id]
        d_point = p.active_share * wrapped.c1
        return prove_dleq(party_id, p.active_share, p.active_public,
                          wrapped.c1, d_point, wrapped.proof_context())

    # ------------------------------------------------------------------
    def prepare_reshare(
        self,
        share_tamper: Optional[Callable[[int, int, int], int]] = None,
        hold_delivery: Optional[Callable[[int, int], bool]] = None,
        commitment_tamper: Optional[Callable[[int, List[ECPoint]], List[ECPoint]]] = None,
    ) -> ReshareTranscript:
        """
        Round 1-3 của resharing.  Hooks giả lập chaos node churn (mục 176):
          share_tamper(sender, receiver, share)  -> share bị sửa trên đường truyền
          hold_delivery(sender, receiver)        -> mất gói (node chết/partition)
          commitment_tamper(pid, commitments)    -> commitment broadcast bị sửa
        """
        if self.status == PENDING:
            raise ReshareAbortError(
                "Đang có resharing PENDING - commit hoặc abort trước khi prepare vòng mới")
        t0 = time.time()
        period_to = self.period + 1
        root = self.root_provider()
        ctx = self._context_for(period_to, root)

        for p in self.parties.values():
            p.inbox.clear()
            p.checks.clear()
            p.complaints = []
            p.candidate_share = None
            p.candidate_public = None
            p.ready = False

        # ---- Round 1: dealer broadcast (C_0 = lambda_i*Y_i - PUBLIC) ----
        commitments: Dict[int, List[ECPoint]] = {}
        for pid in self.dealer_ids:
            commits = self.parties[pid].round1_generate(self.dealer_ids)
            if commitment_tamper is not None:
                commits = commitment_tamper(pid, commits)
            commitments[pid] = list(commits)
            self.parties[pid].commitments = list(commits)

        # ---- Phân phối share qua kênh riêng (fault-injection) ----
        for sender in self.dealer_ids:
            sp = self.parties[sender]
            for receiver in self.member_ids:
                if hold_delivery is not None and hold_delivery(sender, receiver):
                    continue
                share = sp.share_for(receiver)
                if share_tamper is not None:
                    share = share_tamper(sender, receiver, share)
                self.parties[receiver].inbox[sender] = share

        # ---- Round 2: verify + complaint resolution (hỏi lại 1 lần) ----
        disqualified: set = set()
        for receiver in self.member_ids:
            rp = self.parties[receiver]
            for sender in self.dealer_ids:
                res = rp.verify_share_from(sender, rp.inbox.get(sender),
                                           commitments[sender])
                if not res.ok:
                    rp.complaints.append(sender)
            for sender in rp.complaints:
                if hold_delivery is not None and hold_delivery(sender, receiver):
                    disqualified.add(sender)      # re-ask vẫn mất gói -> offline
                    continue
                resend = self.parties[sender].share_for(receiver)
                if share_tamper is not None:
                    resend = share_tamper(sender, receiver, resend)
                rp.inbox[sender] = resend
                if not rp.verify_share_from(sender, resend, commitments[sender]).ok:
                    disqualified.add(sender)       # attacker vẫn gửi sai

        # ---- Mode A: KHÔNG cho loại dealer âm thầm (182/173) ----
        # x' = sum_{i in S} lambda_i(S)*x_i = x; loại 1 dealer là ĐỔI tập S
        # -> lambda đổi -> Lagrange sai -> Y lệch NGẦM.
        if disqualified:
            self.status = ABORTED
            raise ReshareAbortError(
                f"RESHARE ABORT: dealer {sorted(disqualified)} phân phát share "
                f"hỏng/offline (QUAL={len(self.dealer_ids) - len(disqualified)}/"
                f"{len(self.dealer_ids)}). Mode A KHÔNG được loại dealer giữa "
                "vì lambda_i(S) tính trên tập S đã commit -> C_0 lệch -> secret "
                "mới sẽ KHÔNG bằng x cũ (Y lệch ngầm). Sửa node rồi retry, "
                "hoặc bắt đầu lại với dealer_ids nhỏ hơn (>= t_old), hoặc "
                "chuyển MODE B (key mới Y' + rewrap, mục 165).")

        # ---- Round 3: candidate share MỚI cho member (Y bất biến, 167) ----
        for j in self.member_ids:
            m = self.parties[j]
            candidate = sum(m.inbox.get(i, 0) for i in self.dealer_ids) % N_ORDER
            # Y'_j suy từ COMMITMENT - KHÔNG cộng public share cũ (khác refresh)
            candidate_public = _horner_sum(commitments, self.dealer_ids, j)
            if candidate * G != candidate_public:
                self.status = ABORTED
                raise ReshareAbortError(
                    f"Member {j}: candidate share không khớp Y'_j suy từ "
                    "commitment - share/commitment mâu thuẫn, hủy vòng.")
            m.candidate_share = candidate
            m.candidate_public = candidate_public
            m.ready = True

        sigs = {pid: sign_broadcast(self.parties[pid].signing_sk, ctx, pid,
                                    commitments[pid])
                for pid in self.dealer_ids}
        old_pub = {pid: self.parties[pid].old_public for pid in self.dealer_ids}
        transcript = ReshareTranscript(
            period_from=self.period, period_to=period_to, context=ctx,
            commitments=commitments, signatures=sigs,
            dealers=list(self.dealer_ids), member_ids=list(self.member_ids),
            threshold_old=self.t_old, threshold_new=self.t_new,
            old_public_shares=old_pub)

        # ---- Kiểm CÔNG KHAI từ transcript trước khi tuyên bố PENDING ----
        problems = transcript.verify_public(ctx, self.signing_pks)
        if problems:
            self.status = ABORTED
            raise ReshareAbortError(f"Transcript không qua public verify: {problems}")
        for j in self.member_ids:
            if transcript.derived_public_share(j) != self.parties[j].candidate_public:
                self.status = ABORTED
                raise ReshareAbortError(
                    f"Member {j}: Y'_j suy từ transcript != candidate public share")

        self.transcript = transcript
        self.status = PENDING
        self.phase_times["prepare_ms"].append((time.time() - t0) * 1000)
        return transcript

    # ------------------------------------------------------------------
    def commit(self) -> float:
        """
        COMMIT NGUYÊN TÂN (181): swap MỌI member cùng lúc, chỉ khi TẤT CẢ
        member đã prepared.  Member retiring bị đánh dấu retired (gate chặn).
        """
        if self.status != PENDING or self.transcript is None:
            raise ReshareAbortError(f"commit yêu cầu PENDING (hiện {self.status})")
        not_ready = [pid for pid in self.member_ids if not self.parties[pid].ready]
        if not_ready:
            raise ReshareAbortError(
                f"COMMIT BARRIER: member {not_ready} chưa prepared - KHÔNG swap "
                "một phần (interrupted resharing không để trạng thái mơ hồ, 181).")
        t0 = time.time()
        tr = self.transcript
        problems = tr.verify_public(self._context_for(tr.period_to,
                                                      self.root_provider()),
                                    self.signing_pks)
        if problems:
            raise ReshareAbortError(
                f"Root/period đổi giữa prepare và commit -> hủy: {problems}")
        for j in self.member_ids:
            m = self.parties[j]
            m.swap_candidate()
            m.period = tr.period_to
            m.inbox.clear()
            m.checks.clear()
        for pid in self.dealer_ids:
            if not self.parties[pid].is_member:
                self.retired_ids.add(pid)     # retiring: không còn serve (182)
            self.parties[pid].period = tr.period_to
        self.period = tr.period_to
        self.status = COMMITTED
        elapsed = (time.time() - t0) * 1000
        self.phase_times["commit_ms"].append(elapsed)
        return elapsed

    # ------------------------------------------------------------------
    def abort(self):
        """Hủy vòng: drop candidate, GIỮ bộ share đang phục vụ, và LÀM NHẤT
        period: member nào đã swap-sai-phase (lệch thế hệ) -> lùi backup
        (181 - sau abort luôn còn đúng 1 trạng thái duy nhất)."""
        for m in self.member_ids:
            p = self.parties[m]
            p.candidate_share = None
            p.candidate_public = None
            p.ready = False
            p.inbox.clear()
            p.checks.clear()
            if p.period != self.period:
                p.restore_from_backup()
        for pid in self.dealer_ids:
            p = self.parties[pid]
            if p.period != self.period:
                p.restore_from_backup()
        self.status = ABORTED

    # ------------------------------------------------------------------
    def recover(self) -> str:
        """
        Recovery sau crash (180/181): prepare hoàn tất -> commit đi tới;
        thiếu member -> abort/rollback.  KHÔNG BAO GIỜ 2 bộ share cùng 'đúng'.
        """
        if self.status == PENDING and self.transcript is not None:
            if all(self.parties[j].ready for j in self.member_ids):
                self.commit()
                return "FORWARD-COMMIT"
            self.abort()
            return "ABORT-ROLLBACK"
        return "NO-OP"


# =============================================================================
# 6. MODE B - KEY MỚI Y' + REWRAP (loại member thật sự, mục 165 + 173)
# =============================================================================
def rotate_committee_with_new_key(
    new_party_ids: List[int],
    new_threshold: int,
    rewrap_svc: EpochRewrapService,
    old_nodes: Dict[int, ThresholdWrapNode],
    old_combiner: ThresholdCombiner,
    object_ids: List[str],
    new_policy_hash: str,
    policy_db: Dict[str, dict],
    subset: Optional[List[int]] = None,
):
    """
    MODE B (167 + 165): ủy ban MỚI chạy lại DKG (câu 1) -> public key Y' MỚI;
    ủy ban CŨ partial-unwrap từng object (vẫn dưới Y, root còn tươi) rồi
    rewrap DEK sang Y' + policy epoch mới.  Kết quả:
      - share/wrap của member bị loại CHẾT hẳn (DLEQ dưới Y' fail - TEST 6);
      - payload ciphertext KHÔNG bị đụng tới (chỉ wrapped DEK thay - 171);
      - member mới phục vụ ngay, không còn phụ thuộc member cũ.
    Đổi threshold + membership cùng lúc được (dkg mới t_new trên n_new).
    """
    dkg_new, _ = run_pedersen_dkg(list(new_party_ids), new_threshold)
    subset = list(subset) if subset else sorted(old_nodes)[:new_threshold]
    new_wraps: Dict[str, ThresholdWrappedDEK] = {}
    for oid in object_ids:
        new_wrap, _dek = rewrap_via_committee(
            rewrap_svc, oid, old_nodes, old_combiner, subset,
            dkg_new.joint_public_key, new_policy_hash, policy_db)
        new_wraps[oid] = new_wrap
    return dkg_new, new_wraps


# =============================================================================
# 7. RECOVERY GUIDE (deliverable 179)
# =============================================================================
RESHARE_RECOVERY_GUIDE = """
+--------------------------------------------------------------------------------
| RECOVERY GUIDE - RESHARING THRESHOLD / MEMBERSHIP (mục 167/179/181)
+--------------------------------------------------------------------------------
| A. Chọn chế độ TRƯỚC khi chạy:
|    - Chỉ đổi t hoặc thêm member, CŨNG CÓ member cũ tin cậy đang online
|      -> MODE A (giữ secret, Y bất biến, không rewrap, không re-encrypt).
|    - Loại member bị compromise / mất member cũ vĩnh viễn / đổi t mà không
|      còn đủ member cũ -> MODE B (DKG key mới Y' + rewrap DEK, mục 165).
| B. MODE A: mọi dealer trong S (dealer_ids) PHẢI phân phát đúng. 1 dealer hỏng ->
|    ABORT + ROLLBACK (không loại dealer giữa chừng: lambda_i tính trên tập S
|    đã commit - bỏ dealer là đổi lambda -> Y lệch ngầm). Sửa node rồi retry.
|    Không bao giờ "bỏ qua" 1 dealer để qua mắt barrier.
| C. Sau crash gọi recover(): prepare hoàn tất -> FORWARD-COMMIT (period+1);
|    thiếu member -> ABORT-ROLLBACK (share cũ vẫn phục vụ).
| D. Member swap-sai-phase (lệch period, can_issue_partials = False):
|    restore_from_backup() rồi chạy lại vòng mới; hoặc nếu đã commit xong thì
|    để servicePeriod đồng nhất lại bằng recover().
| E. Member retiring sau commit: BỊ GATE chặn partial (182). Nếu còn cần họ
|    phục vụ thì không được để họ retiring; nếu không -> đưa hẳn ra khỏi
|    committee (Mode B nếu muốn thu hồi quyền của họ).
| F. ROOT policy đổi giữa prepare và commit: commit tự hủy (transcript gắn
|    root) -> chạy lại vòng mới với root mới nhất (chống replay, 168/172).
| G. Sau khi resharing: công bố registry Y'_j mới cho client; client update
|    registry thì share cũ bị DLEQ từ chối (173) - claim trung thực.
+--------------------------------------------------------------------------------
"""


# =============================================================================
# 8. PIPELINE - dựng môi trường thật (GĐ1+GĐ2+GĐ3 cache)
# =============================================================================
def build_reshare_env(object_id: str = "OBJ-RS-1", new_ids: Optional[List[int]] = None,
                      t_new: Optional[int] = None, payload_size: int = 256) -> dict:
    """
    Môi trường Mode A: policy log GĐ1 + oracle GĐ2 + DKG cache (ủy ban cũ
    1..5, t=3) + wrap DEK epoch 1 + bộ party theo vai trò (returning/retiring/
    joining) cho tập member MỚI.
    """
    km = key_material()
    new_ids = list(new_ids) if new_ids else list(range(1, N + 1))
    t_new = t_new if t_new is not None else T + 1

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

    max_id = max(max(new_ids), N)
    signing_sks, signing_pks = committee_keygen(max_id)
    parties: Dict[int, ReshareParty] = {}
    for j in range(1, N + 1):                     # member CŨ
        role = RETURNING if j in new_ids else RETIRING
        parties[j] = ReshareParty(j, role, t_new, old_share=km["shares"][j],
                                  old_public=km["pub_shares"][j],
                                  signing_sk=signing_sks[j])
    for j in new_ids:                             # member MỚI (id ngoài 1..5)
        if j > N:
            parties[j] = ReshareParty(j, JOINING, t_new, signing_sk=signing_sks[j])

    svc = ResharingService(parties, T, t_new, oracle.get_latest_trusted_root,
                           signing_pks=signing_pks, period=1)
    return dict(object_id=object_id, log=log, bridge=bridge, oracle=oracle,
                dek=dek, payload=payload, payload_ct=payload_ct, codec=codec,
                ph_ingest=ph_ingest, wrapped=wrapped, svc=svc,
                signing_sks=signing_sks, signing_pks=signing_pks,
                new_ids=new_ids, t_new=t_new, **km)


def build_rewrap_committee_env(object_prefix: str = "OBJ-RSB", n_objects: int = 1,
                               payload_size: int = 128) -> dict:
    """
    Môi trường Mode B (câu 165): n object đã ingest + wrap dưới key CŨ,
    EpochRewrapService sẵn sàng để rotate_policy_epoch + rewrap.
    """
    km = key_material()
    log = PolicyLogService(ed25519.Ed25519PrivateKey.generate())
    bridge = EngramAnchorBridge(ed25519.Ed25519PrivateKey.generate())
    oracle = KeyNodeTrustedRootOracle(
        bridge.bridge_pk, FreshnessWindowConfig(max_anchor_age_seconds=60.0))

    objects = []
    for k in range(1, n_objects + 1):
        oid = f"{object_prefix}-{k}"
        event, _, _ = log.init_policy(oid, initial_epoch=1)
        ph = hashlib.sha256(event.canonical_bytes_for_signing()).hexdigest()
        objects.append((oid, ph))
    anchor1 = bridge.anchor_epoch(1, log.mmr)
    oracle.sync_latest_trusted_root(anchor1)

    rewrap_svc = EpochRewrapService(log, bridge, oracle)
    old_nodes = {j: ThresholdWrapNode(j, km["shares"][j], km["pub_shares"][j],
                                      T, oracle=oracle)
                 for j in range(1, N + 1)}
    old_combiner = ThresholdCombiner(km["pub_shares"], T)
    dek = os.urandom(32)
    objects_meta = []
    for oid, ph in objects:
        payload = os.urandom(payload_size)
        payload_ct = encrypt_payload(dek, payload, oid, 1, ph, "JSON-GCM-v1")
        ctx = WrapContext(object_id=oid, version=1, policy_hash=ph,
                          codec_id="JSON-GCM-v1", epoch=1,
                          policy_root=anchor1.mmr_root)
        wrapped = wrap_dek(dek, km["threshold_pk"], ctx)
        rewrap_svc.register_object(oid, wrapped, initial_epoch=1)
        objects_meta.append(dict(object_id=oid, ph_ingest=ph, payload=payload,
                                 payload_ct=payload_ct, wrap=wrapped))
    return dict(objects=objects_meta, log=log, bridge=bridge, oracle=oracle,
                rewrap=rewrap_svc, old_nodes=old_nodes, old_combiner=old_combiner,
                dek=dek, **km)


def _banner(title: str):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


# =============================================================================
# 9. DEMO + TESTS (cổng nghiệm thu Giai đoạn 4 - câu 167)
# =============================================================================
if __name__ == "__main__":
    TOTAL_T0 = time.time()
    results = []

    # =====================================================================
    _banner("TEST 1: RESHARE ĐỔI THRESHOLD 3->4, Y NGUYÊN ĐIỂM (mục 167)")
    # =====================================================================
    print("- MODE A: dealer i coi lambda_i(S)*x_i là HẰNG SỐ poly bậc (t_new-1):")
    print("    f_i(x) = lambda_i*x_i + a_i1*x + ... ;  C_i,0 = lambda_i*Y_i (PUBLIC)")
    print("    x'_j = sum_i f_i(j) => sum lambda_j*Y'_j = sum lambda_i*x_i = x => Y'=Y")
    env1 = build_reshare_env(object_id="OBJ-RS-1", new_ids=list(range(1, 6)), t_new=4)
    svc1: ResharingService = env1["svc"]
    Y = env1["threshold_pk"]
    old_shares = {j: svc1.private_share(j) for j in svc1.parties}

    tr1 = svc1.prepare_reshare()
    assert svc1.status == PENDING
    assert svc1.private_share(1) == old_shares[1], "PENDING không được đổi share"
    print(f"- prepare_reshare(): period 1 -> {tr1.period_to}, status=PENDING "
          f"(share CHƯA đổi - 2 pha, 181)")
    ms = svc1.commit()
    assert svc1.period == tr1.period_to == 2 and svc1.status == COMMITTED
    print(f"- commit(): barrier nguyên tử {ms:.1f} ms, period={svc1.period}")

    # Bất biến: Y giữ nguyên trên MỌI subset size t_new của ủy ban mới
    subset_ok = 0
    for subset in itertools.combinations(sorted(svc1.member_ids), 4):
        acc = ECPoint(None, None)
        for j in subset:
            acc = acc + (lagrange_coefficient(j, list(subset)) * svc1.public_shares()[j])
        assert acc == Y
        subset_ok += 1
    changed = sum(1 for j in svc1.member_ids
                  if svc1.private_share(j) != old_shares[j])
    assert changed == len(svc1.member_ids)
    print(f"- {changed}/{len(svc1.member_ids)} share MỚI (khác share cũ); "
          f"MỌI {subset_ok} subset size t_new=4 nội suy Lagrange -> đúng Y")
    print("- => đổi được cả bậc t (3->4) mà KHÔNG rewrap, KHÔNG đổi public key")
    results.append("TEST1 threshold change 3->4, Y unchanged: PASS")

    # =====================================================================
    _banner("TEST 2: ĐỔI MEMBERSHIP (2 out, 2 in) + E2E UNWRAP (167/171)")
    # =====================================================================
    env2 = build_reshare_env(object_id="OBJ-RS-2", new_ids=[2, 3, 4, 6, 7], t_new=3)
    svc2: ResharingService = env2["svc"]
    Y2 = env2["threshold_pk"]
    print(f"- Ủy ban cũ [1..5] t=3  ->  ủy ban mới [2,3,4,6,7] t=3")
    print("  returning=[2,3,4] (vừa dealer vừa member), retiring=[1,5], joining=[6,7]")

    tr2 = svc2.prepare_reshare()
    svc2.commit()
    assert sorted(svc2.member_ids) == [2, 3, 4, 6, 7]
    assert svc2.retired_ids == {1, 5}
    print(f"- Commit xong: member mới={sorted(svc2.member_ids)}, "
          f"retired={sorted(svc2.retired_ids)} (bị GATE chặn partial)")

    # Y'_j suy CÔNG KHAI từ transcript khớp share thật (172)
    for j in svc2.member_ids:
        assert tr2.derived_public_share(j) == svc2.public_shares()[j]
        assert svc2.private_share(j) * G == svc2.public_shares()[j]
    acc = ECPoint(None, None)
    for j in sorted(svc2.member_ids):
        acc = acc + (lagrange_coefficient(j, sorted(svc2.member_ids))
                     * svc2.public_shares()[j])
    assert acc == Y2
    print("- Y'_j suy từ transcript khớp share'*G; Lagrange 4 member -> đúng Y2")

    # GATE: retiring bị chặn, member mới được phục vụ (182)
    assert not svc2.can_issue_partials(1) and not svc2.can_issue_partials(5)
    assert svc2.can_issue_partials(6) and svc2.can_issue_partials(2)
    print(f"- can_issue_partials: retired 1/5 -> False; member 2/6 -> True (182)")

    # E2E: unwrap wrap CŨ bằng ủy ban MỚI - cả pipeline câu 4+5 và câu 3
    root2 = env2["oracle"].get_latest_trusted_root()
    env2["oracle"].resolve_fresh_policy(env2["object_id"], root2,
                                        env2["log"].policy_records)
    proofs = [svc2.issue_partial(j, env2["wrapped"]) for j in (2, 3, 6)]
    report = ThresholdCombiner(svc2.public_shares(), 3).combine(proofs, env2["wrapped"])
    assert report.dek == env2["dek"]
    print(f"- Ủy ban MỚI unwrap wrap epoch 1 (DLEQ + combiner): DEK đúng, "
          f"dùng members={report.used_ids}")

    nodes2 = {j: ThresholdWrapNode(j, svc2.private_share(j),
                                   svc2.public_shares()[j], 3, oracle=env2["oracle"])
              for j in svc2.member_ids}
    compact = [nodes2[j].create_partial(env2["wrapped"], presented_policy_root=root2,
                                        policy_db=env2["log"].policy_records)
               for j in (3, 6, 7)]
    assert all(verify_partial(c, svc2.public_shares()[c.party_id],
                              env2["wrapped"].c1, env2["wrapped"].proof_context())
               for c in compact)
    assert combine_and_unwrap(compact, svc2.public_shares(), 3,
                              env2["wrapped"]) == env2["dek"]
    print("- Pipeline câu 3 (proof compact) với share mới -> cùng DEK")

    plain = decrypt_payload(env2["dek"], env2["payload_ct"], env2["object_id"], 1,
                            env2["ph_ingest"], env2["codec"])
    assert plain == env2["payload"]
    print("- Payload ciphertext GIỮ NGUYÊN từ trước resharing -> giải mã đúng "
          "(171: không re-encrypt payload)")
    results.append("TEST2 membership change + E2E no re-encrypt: PASS")

    # =====================================================================
    _banner("TEST 3: TRANSCRIPT CÔNG KHAI, KHÔNG LỘ SECRET, TAMPER BỊ BẮT (172)")
    # =====================================================================
    probs = tr2.verify_public(tr2.context, env2["signing_pks"])
    assert probs == [], probs
    print(f"- verify_public() với CHỈ public key ủy ban: HỢP LỆ "
          f"({len(tr2.dealers)} chữ ký Ed25519, context={tr2.context!r})")

    secrets = [env2["shares"][i] for i in range(1, N + 1)] + \
              [svc2.private_share(j) for j in svc2.member_ids] + \
              [c for i in tr2.dealers for c in (env2["svc"].parties[i].coeffs or [])]
    leaks = tr2.leak_scan(secrets)
    assert not leaks, leaks
    print(f"- leak_scan trên {len(secrets)} secret (share cũ/mới + hệ số a): "
          "KHÔNG secret nào trong transcript")

    # 3a. Tamper 1 commitment -> chữ ký broadcast fail
    bad_commits = dict(tr2.commitments)
    bad_commits[2] = list(bad_commits[2])
    bad_commits[2][1] = (bad_commits[2][1].x + 1) * G
    forged = ReshareTranscript(
        period_from=tr2.period_from, period_to=tr2.period_to, context=tr2.context,
        commitments=bad_commits, signatures=tr2.signatures, dealers=tr2.dealers,
        member_ids=tr2.member_ids, threshold_old=tr2.threshold_old,
        threshold_new=tr2.threshold_new, old_public_shares=tr2.old_public_shares)
    probs_bad = forged.verify_public(tr2.context, env2["signing_pks"])
    assert any("chữ ký" in p for p in probs_bad), probs_bad
    print(f"- Tamper C_1 của dealer 2 -> bị bắt: {probs_bad[0]}")

    # 3b. Dealer C_0 != lambda_i*Y_i -> thay secret NGẦM bị bắt bằng mắt thường
    liar = [(99991) * G, (12) * G, (34) * G]      # C_0 != lambda_4*Y_4
    drift = ReshareTranscript(
        period_from=tr2.period_from, period_to=tr2.period_to, context=tr2.context,
        commitments={**tr2.commitments, 4: liar},
        signatures={**tr2.signatures, 4: sign_broadcast(
            env2["signing_sks"][4], tr2.context, 4, liar)},
        dealers=tr2.dealers, member_ids=tr2.member_ids,
        threshold_old=tr2.threshold_old, threshold_new=tr2.threshold_new,
        old_public_shares=tr2.old_public_shares)
    probs_drift = drift.verify_public(tr2.context, env2["signing_pks"])
    assert any("NGẦM" in p for p in probs_drift), probs_drift
    print(f"- Dealer 4 broadcast C_0 != lambda_4*Y_4: {probs_drift[0][:70]}...")
    print("  => 'reshare' không thể lén đổi secret mà không bị public verifier bắt")
    results.append("TEST3 transcript public/no-leak/tamper: PASS")

    # =====================================================================
    _banner("TEST 4: GIAN LẬN + INTERRUPTED RESHARING - KHÔNG MƠ HỒ (176/181)")
    # =====================================================================
    # 4a. Share bị sửa trên đường truyền -> complaint -> ABORT (không loại ngầm)
    env4 = build_reshare_env(object_id="OBJ-RS-4", t_new=4)
    svc4: ResharingService = env4["svc"]
    snap4 = {j: svc4.private_share(j) for j in svc4.member_ids}
    try:
        svc4.prepare_reshare(share_tamper=lambda s, r, x: (x + 777) % N_ORDER
                             if s == 4 else x)
        raise AssertionError("phải abort khi dealer gửi share hỏng")
    except ReshareAbortError as err:
        print(f"- Dealer 4 gửi share hỏng -> {str(err)[:96]}...")
    assert svc4.status == ABORTED and svc4.period == 1
    assert all(svc4.private_share(j) == snap4[j] for j in svc4.member_ids)
    print("- ROLLBACK nguyên tử: period=1, MỌI share giữ nguyên (không mơ hồ)")

    # 4b. Node chết (mất gói kéo dài) -> cũng ABORT (Mode A cần đủ dealer)
    try:
        svc4.prepare_reshare(hold_delivery=lambda s, r: s == 5)
        raise AssertionError("phải abort khi dealer 5 offline")
    except ReshareAbortError as err:
        print(f"- Dealer 5 offline -> abort: {str(err)[:70]}...")
    print("- => Mode A mất liveness khi thiếu dealer -> phải sửa node hoặc Mode B (182)")

    # 4c. Crash sau khi prepare xong -> recover() commit đi tới
    tr4 = svc4.prepare_reshare()
    outcome = svc4.recover()
    assert outcome == "FORWARD-COMMIT" and svc4.period == tr4.period_to == 2
    print(f"- Crash sau prepare hoàn tất: recover() -> {outcome}, period={svc4.period}")

    # 4d. Member swap SỚM 1 mình -> GATE chặn TẤT CẢ -> abort -> restore -> chạy lại
    tr4b = svc4.prepare_reshare()
    rogue = svc4.parties[3]
    assert rogue.ready
    rogue.swap_candidate()
    rogue.period = tr4b.period_to
    assert len({svc4.parties[j].period for j in svc4.member_ids}) > 1
    try:
        svc4.assert_uniform_period()
        raise AssertionError("phải phát hiện period lệch")
    except ResharePeriodMismatch as err:
        print(f"- Member 3 swap sớm 1 mình -> {str(err)[:86]}...")
    assert not svc4.can_issue_partials(3) and not svc4.can_issue_partials(2)
    print("- GATE: can_issue_partials=False cho TẤT cả member -> không partial nào "
          "được phát khi ủy ban lệch thế hệ")
    outcome = svc4.recover()
    assert outcome == "ABORT-ROLLBACK" and svc4.period == 2
    print(f"- recover(): {outcome} (period không đổi) -> trạng thái duy nhất")
    rogue.restore_from_backup()
    svc4.assert_uniform_period()
    assert svc4.can_issue_partials(3)
    tr4c = svc4.prepare_reshare()
    svc4.commit()
    assert svc4.period == tr4c.period_to == 3
    print(f"- restore_from_backup() + vòng mới thành công: period={svc4.period}")
    results.append("TEST4 adversarial + interrupted recovery: PASS")

    # =====================================================================
    _banner("TEST 5: ĐỔI THRESHOLD GIẢM 3->2 (cùng committee) - Y VẪN BẤT BIẾN")
    # =====================================================================
    env5 = build_reshare_env(object_id="OBJ-RS-5", new_ids=list(range(1, 6)), t_new=2)
    svc5: ResharingService = env5["svc"]
    Y5 = env5["threshold_pk"]
    tr5 = svc5.prepare_reshare()
    svc5.commit()
    sub = [1, 4]
    acc = ECPoint(None, None)
    for j in sub:
        acc = acc + (lagrange_coefficient(j, sub) * svc5.public_shares()[j])
    assert acc == Y5
    proofs5 = [svc5.issue_partial(j, env5["wrapped"]) for j in sub]
    dek5 = ThresholdCombiner(svc5.public_shares(), 2).combine(
        proofs5, env5["wrapped"]).dek
    assert dek5 == env5["dek"]
    print(f"- 3->2: chỉ cần 2 node ({sub}) để unwrap - Y giữ nguyên, "
          "t_ngưỡng đổi được cả 2 chiều")
    results.append("TEST5 threshold decrease 3->2: PASS")

    # =====================================================================
    _banner("TEST 6: MODE B - KEY MỚI Y' + REWRAP: LOẠI MEMBER THẬT SỰ (173/165)")
    # =====================================================================
    print("- TRUNG THỰC (173): Mode A KHÔNG thu hồi share/wrap của member bị loại")
    print("  (secret y hệt nhau).  'Loại member' thật sự = MODE B:")
    envb = build_rewrap_committee_env(object_prefix="OBJ-RS-B", n_objects=1)
    obj = envb["objects"][0]
    oid = obj["object_id"]
    old_wrap = envb["rewrap"].get_active_wrap(oid)
    old_digest = wrap_digest(old_wrap)
    issuer_sk = ed25519.Ed25519PrivateKey.generate()
    cap, cap_sig = issue_capability(issuer_sk, "alice", oid, "read", epoch=1)

    new_ids_b = [2, 3, 4, 6, 7]           # 1,5 bị LOẠI; 6,7 vào; t giữ 3
    dkg_new, new_wraps = rotate_committee_with_new_key(
        new_party_ids=new_ids_b, new_threshold=3, rewrap_svc=envb["rewrap"],
        old_nodes=envb["old_nodes"], old_combiner=envb["old_combiner"],
        object_ids=[oid], new_policy_hash="policy-hash-v2",
        policy_db=envb["log"].policy_records, subset=[1, 2, 3])
    new_wrap = new_wraps[oid]
    print(f"- Ủy ban mới {new_ids_b} t=3: DKG -> Y' mới; rewrap epoch 2 -> "
          f"wrap {old_digest[:12]}... -> {wrap_digest(new_wrap)[:12]}...")

    # DEK giữ nguyên -> payload KHÔNG re-encrypt (171)
    assert envb["rewrap"].get_active_wrap(oid) is new_wrap
    assert old_digest in envb["rewrap"].retired_digests
    plain_b = decrypt_payload(envb["dek"], obj["payload_ct"], oid, 1,
                              obj["ph_ingest"], "JSON-GCM-v1")
    assert plain_b == obj["payload"]
    print("- Wrap cũ -> retired set (get_active_wrap từ chối); payload GIỮ NGUYÊN")

    # 6a. Share CŨ fail DLEQ dưới registry Y' mới
    comb_new = ThresholdCombiner(dkg_new.public_key_shares, 3)
    old_proofs = [prove_dleq(j, envb["shares"][j], envb["pub_shares"][j], new_wrap.c1,
                             envb["shares"][j] * new_wrap.c1, new_wrap.proof_context())
                  for j in (1, 2, 3)]
    verdicts = comb_new.classify(old_proofs, new_wrap.c1, new_wrap.proof_context())
    assert not any(v.accepted for v in verdicts), verdicts
    try:
        comb_new.combine(old_proofs, new_wrap)
        raise AssertionError("share cũ phải fail-closed dưới Y'")
    except InsufficientPartials as err:
        print(f"- Share CŨ (member 1,2,3) dưới registry Y': "
              f"{err.report.accepted_ids} hợp lệ -> fail-closed (173)")

    # 6b. Share MỚI unwrap wrap MỚI (qua gate + oracle GĐ2)
    new_proofs = [prove_dleq(j, dkg_new.private_shares[j],
                             dkg_new.public_key_shares[j], new_wrap.c1,
                             dkg_new.private_shares[j] * new_wrap.c1,
                             new_wrap.proof_context())
                  for j in (3, 4, 6)]
    dek_new = comb_new.combine(new_proofs, new_wrap).dek
    assert dek_new == envb["dek"]
    print(f"- Share MỚI của {sorted(new_ids_b)[:3]}... unwrap wrap MỚI: DEK đúng")

    # 6c. Old capability không hoạt động ở epoch mới (168/181)
    verifier = CapabilityVerifier(issuer_sk.public_key())
    try:
        verifier.verify_capability(cap, cap_sig, "alice", oid, "read",
                                   current_policy_epoch=envb["rewrap"].global_epoch)
        raise AssertionError("capability epoch 1 phải fail ở epoch mới")
    except CapabilitySecurityError as err:
        print(f"- Old capability (epoch 1) ở epoch {envb['rewrap'].global_epoch}: "
              f"{str(err)[:60]}...")

    # 6d. Node mới phát partial cho wrap mới qua safe_create_partial (GĐ2 gate)
    new_node = ThresholdWrapNode(6, dkg_new.private_shares[6],
                                 dkg_new.public_key_shares[6], 3,
                                 oracle=envb["oracle"])
    partial = safe_create_partial(new_node, new_wrap, envb["rewrap"],
                                  envb["log"].policy_records)
    assert verify_partial(partial, dkg_new.public_key_shares[6], new_wrap.c1,
                          new_wrap.proof_context())
    print("- Member mới 6 phát partial cho wrap mới qua oracle GĐ2: verify OK")
    results.append("TEST6 Mode B new key + rewrap (trung thực 173): PASS")

    # =====================================================================
    _banner("BENCHMARK RESHARING THEO n, t VÀ SỐ OBJECT (mục 169/180/174)")
    # =====================================================================
    fake_root = lambda: "cd" * 32
    print("MODE A (giữ secret - chỉ reshare share, KHÔNG rewrap):")
    for (n_old, t_old, t_new) in [(3, 2, 3), (5, 3, 4), (7, 4, 5)]:
        dkg, _ = run_pedersen_dkg(list(range(1, n_old + 1)), t_old)
        sks, pks = committee_keygen(n_old)
        parties = {j: ReshareParty(j, RETURNING, t_new,
                                   old_share=dkg.private_shares[j],
                                   old_public=dkg.public_key_shares[j],
                                   signing_sk=sks[j])
                   for j in sorted(dkg.private_shares)}
        bsvc = ResharingService(parties, t_old, t_new, fake_root, signing_pks=pks)
        t0 = time.time()
        btr = bsvc.prepare_reshare()
        prep_ms = (time.time() - t0) * 1000
        t0 = time.time()
        bsvc.commit()
        comm_ms = (time.time() - t0) * 1000
        t0 = time.time()
        assert not btr.verify_public(btr.context, bsvc.signing_pks)
        verify_ms = (time.time() - t0) * 1000
        print(f"  - n {n_old}->{n_old}, t {t_old}->{t_new}: prepare {prep_ms:6.1f} ms "
              f"| commit {comm_ms:5.1f} ms | public verify {verify_ms:5.1f} ms "
              f"| dealer {prep_ms / n_old:5.1f} ms")

    print("MODE B (key mới DKG + rewrap - theo SỐ OBJECT, mục 174/180):")
    batch_env = build_rewrap_committee_env(object_prefix="OBJ-BENCH", n_objects=4)
    t0 = time.time()
    dkg_b, _ = run_pedersen_dkg([2, 3, 4, 6, 7], 3)
    dkg_ms = (time.time() - t0) * 1000
    print(f"  - DKG ủy ban mới (n=5,t=3): {dkg_ms:.1f} ms (1 lần cho cả đợt)")
    batch = [dict(object_id=o["object_id"], dek=batch_env["dek"], wrap=o["wrap"],
                  threshold_pk=dkg_b.joint_public_key,
                  new_policy_hash="policy-hash-v3")
             for o in batch_env["objects"]]
    stats = batch_rewrap_worker(batch_env["rewrap"], batch,
                                batch_env["log"].policy_records)
    print(f"  - Batch rewrap {stats['count']} object: median {stats['median_ms']:.1f} ms "
          f"| p95 {stats['p95_ms']:.1f} ms | "
          f"throughput {stats['throughput_obj_per_s']:.1f} obj/s")
    print("  - Chi phí Mode A chủ yếu: n_old*(t_new-1) scalar-mul 256-bit (pure")
    print("    Python); Horner xác minh dùng scalar nhỏ (j^k) nên rất rẻ.")
    print("  - Chi phí Mode B: DKG 1 lần + rewrap mỗi object "
          "(prove_dleq + rotate policy epoch).")

    # =====================================================================
    _banner("RESHARE RECOVERY GUIDE (deliverable 179)")
    # =====================================================================
    print(RESHARE_RECOVERY_GUIDE)

    # =====================================================================
    _banner("KẾT LUẬN")
    # =====================================================================
    for r in results:
        print(f"  {r}")
    print(f"  Tổng thời gian demo: {time.time() - TOTAL_T0:.2f} s")
    print("  => Mode A: member coi share cũ là hằng số poly mới -> đổi được CẢ")
    print("     threshold lẫn membership mà public key Y NGUYÊN ĐIỂM;")
    print("     transcript công khai (commitment + chữ ký), không lộ secret;")
    print("     prepare/commit 2 pha + recover() => interrupted resharing không")
    print("     để trạng thái mơ hồ; Mode B (DKG mới + rewrap) là cách duy nhất")
    print("     để THẬT SỰ thu hồi quyền của member bị loại (claim trung thực 173).")
    print("  LƯU Ý: prototype academic, chưa audit - không dùng production.")
