----------------------------- MODULE EngramRevokeMutant -----------------------------
(***************************************************************************)
(* ENGRAM-REVOKE - GIAI ĐOẠN 2                                            *)
(* Mô hình hóa Policy State Machine và Network Partition bằng TLA+/TLC    *)
(*                                                                         *)
(* Đối chiếu 1-1 với cài đặt Python:                                      *)
(*   signedandapend_events.py           : State machine + Terminal Inv.    *)
(*   anchorroot.py                      : Epoch anchoring + consistency    *)
(*   freshnesswindowandlatesttrustedroot.py : Freshness window/fail-closed *)
(*   test_adversarial_suite.py          : Stale-root/rollback/equivocation *)
(*                                        / concurrent access-revoke tests *)
(*                                                                         *)
(* INVARIANTS (I1..I5) KIỂM CHỨNG BẰNG TLC:                                *)
(*   I1  TerminalStable   : REVOKED/EXPIRED không bao giờ quay lại ACTIVE  *)
(*                          (Terminal State Invariant)                     *)
(*   I2  EpochMonotonic   : Latest trusted epoch tại Key Node không lùi    *)
(*                          (chống rollback/equivocation lịch sử)          *)
(*   I3  StaleRejected    : Chỉ cấp khóa khi present đúng latest root     *)
(*                          (stale policy proof bị từ chối)                *)
(*   I4  FailClosed       : Mất freshness (partition) => không cấp khóa    *)
(*   I5  NoLeak           : Sau mốc revoke commit không còn key release    *)
(*                          (concurrent revoke thắng future key release)   *)
(*                                                                         *)
(* NETWORK PARTITION:                                                       *)
(*   StartPartition -> AgePartition (freshness window trôi dần) ->          *)
(*   ExpireFreshness (fail-closed) -> EndPartition -> Refresh/Sync         *)
(***************************************************************************)
EXTENDS Integers, Sequences

(***************************************************************************)
(* HẰNG SỐ MÔ HÌNH                                                          *)
(***************************************************************************)
CONSTANTS
  MaxEpoch,          \* Động sâu tối đa của epoch (biên trạng thái cho TLC)
  FreshnessWindow    \* Số bước partition trước khi freshness window hết hạn

(***************************************************************************)
(* TRẠNG THÁI POLICY - Khớp VALID_TRANSITIONS / TERMINAL_STATES              *)
(* trong signedandapend_events.py                                          *)
(***************************************************************************)
PolicyStates   == {"NONE", "ACTIVE", "SUSPENDED", "REVOKED", "EXPIRED"}
TerminalStates == {"REVOKED", "EXPIRED"}

ValidTransitions == { <<"ACTIVE",   "SUSPENDED">>,
                      <<"SUSPENDED","ACTIVE">>,
                      <<"ACTIVE",   "EXPIRED">>,
                      <<"ACTIVE",   "REVOKED">>,
                      <<"SUSPENDED","REVOKED">>,
                      <<"REVOKED", "ACTIVE">> }

(***************************************************************************)
(* ĐÁNH DẤU KẾT QUẢ TRUY CẬP - Khớp metrics trong                          *)
(* freshnesswindowandlatesttrustedroot.py                                  *)
(***************************************************************************)
Outcomes == {"none", "granted", "stale", "failclosed", "blocked"}

(***************************************************************************)
(* ROOTVIEW: client có thể trình bày root của epoch 0..MaxEpoch            *)
(* (0 = chưa từng nhận root; tương ứng FailClosedFreshnessError)            *)
(***************************************************************************)
RootViews == 0..MaxEpoch

(***************************************************************************)
(* BIẾN TRẠNG THÁI                                                          *)
(***************************************************************************)
VARIABLES
  \* --- Lõi: Policy state machine + anchoring + key node ---
  pstate,        \* Trạng thái policy hiện tại
  pepoch,        \* Epoch của policy (tăng khi chuyển trạng thái terminal)
  aepoch,        \* Epoch của anchor mới nhất do EngramAnchorBridge đã neo
  netUp,         \* TRUE: mạng khỏe | FALSE: network partition
  kEpoch,        \* Latest trusted root tại Key Node (đại diện bằng epoch)
  kFresh,        \* Freshness window còn hiệu lực tại Key Node
  partitionAge,  \* Số bước partition đã trôi qua
  revokeDone,    \* Revoke đã commit chưa
  outcome,       \* Kết quả request-access gần nhất (đọc được trên trace)
  presented,     \* Root do client trình bày trong request gần nhất
  \* 3 FLAG AN TOÁN - ghi nhận ngay TẠI THỜI ĐIỂM cấp khóa, không reset:
  staleGrant,    \* Từng cấp khóa cho stale proof chưa?   (I3, phải luôn FALSE)
  unfreshGrant,  \* Từng cấp khóa khi mất freshness chưa? (I4, phải luôn FALSE)
  leak,          \* Từng cấp khóa SAU revoke commit chưa? (I5, phải luôn FALSE)

  \* --- Biến lịch sử/phái sinh (được update đồng bộ trong Next) ---
  maxKE,         \* Epoch lớn nhất Key Node từng thấy (phát hiện rollback)
  terminalSeen   \* Từng đi vào trạng thái terminal chưa

coreVars == <<pstate, pepoch, aepoch, netUp, kEpoch, kFresh, partitionAge,
              revokeDone, outcome, presented, staleGrant, unfreshGrant, leak>>

vars == coreVars \o <<maxKE, terminalSeen>>

(***************************************************************************)
(* ĐIỀU KIỆN BAN ĐẦU                                                        *)
(***************************************************************************)
Init ==
  /\ pstate       = "NONE"
  /\ pepoch       = 1
  /\ aepoch       = 0
  /\ netUp        = TRUE
  /\ kEpoch       = 0
  /\ kFresh       = FALSE    \* Chưa sync root nao -> fail-closed ngay
  /\ partitionAge = 0
  /\ revokeDone   = FALSE
  /\ outcome      = "none"
  /\ presented    = 0
  /\ staleGrant   = FALSE
  /\ unfreshGrant = FALSE
  /\ leak         = FALSE
  /\ maxKE        = 0
  /\ terminalSeen = FALSE

(***************************************************************************)
(* ACTION 1: InitPolicy - NONE -> ACTIVE, ký signed event, neo epoch 1      *)
(* (signedandapend_events.py: init_policy)                                 *)
(***************************************************************************)
InitPolicy ==
  /\ pstate = "NONE"
  /\ pstate' = "ACTIVE"
  /\ pepoch' = pepoch
  /\ aepoch' = 1
  /\ IF netUp
     THEN /\ kEpoch'      = 1        \* Key Node sync được root epoch 1
          /\ kFresh'      = TRUE
          /\ partitionAge' = 0
     ELSE /\ kEpoch'      = kEpoch   \* Đang partition: fail-closed, chưa sync
          /\ kFresh'      = kFresh
          /\ partitionAge' = partitionAge
  /\ UNCHANGED <<netUp, revokeDone, outcome, presented,
                 staleGrant, unfreshGrant, leak>>

(***************************************************************************)
(* ACTION 2: Transition - Chuyển trạng thái theo State Machine             *)
(* Terminal state invariant được enforce tại đây (I1)                      *)
(* (signedandapend_events.py: transition_policy)                           *)
(***************************************************************************)
Transition(newSt) ==
  /\ TRUE                                         \* MUTANT: bỏ guard terminal
  /\ <<pstate, newSt>> \in ValidTransitions
  /\ (newSt \in TerminalStates) => (pepoch < MaxEpoch)
  /\ pstate'     = newSt
  /\ pepoch'     = (IF newSt \in TerminalStates THEN pepoch + 1 ELSE pepoch)
  /\ revokeDone' = (IF newSt = "REVOKED" THEN TRUE ELSE revokeDone)
  /\ UNCHANGED <<aepoch, netUp, kEpoch, kFresh, partitionAge,
                 outcome, presented, staleGrant, unfreshGrant, leak>>

(***************************************************************************)
(* ACTION 3: Anchor - Neo MMR root theo epoch (chỉ khi mạng khỏe)          *)
(* Yeu cau pstate # "NONE": khong the neo truoc khi policy duoc init        *)
(* (guard nay bao toan I2 - khong cho InitPolicy tua kEpoch tuong lai)      *)
(* (anchorroot.py: EngramAnchorBridge.anchor_epoch)                        *)
(***************************************************************************)
Anchor ==
  /\ pstate # "NONE"
  /\ netUp
  /\ aepoch < MaxEpoch
  /\ aepoch' = aepoch + 1
  /\ UNCHANGED <<pstate, pepoch, netUp, kEpoch, kFresh, partitionAge,
                 revokeDone, outcome, presented, staleGrant, unfreshGrant, leak>>

(***************************************************************************)
(* ACTION 4: Sync - Key Node nhận anchor + consistency proof -> cap nhat    *)
(* latest trusted root (aepoch chi tang -> I2 duoc bao toan theo xay dung)  *)
(* (anchorroot.py + freshnesswindowandlatesttrustedroot.py: sync_latest..)  *)
(***************************************************************************)
Sync ==
  /\ pstate # "NONE"
  /\ netUp
  /\ aepoch > kEpoch
  /\ kEpoch'      = aepoch
  /\ kFresh'      = TRUE
  /\ partitionAge' = 0
  /\ UNCHANGED <<pstate, pepoch, aepoch, netUp, revokeDone,
                 outcome, presented, staleGrant, unfreshGrant, leak>>

(***************************************************************************)
(* ACTION 5: Refresh - Sau partition, dong bo lai anchor cuoi de           *)
(* khôi phục freshness (khoa Python cho phep sync cung epoch neu root giong)*)
(***************************************************************************)
Refresh ==
  /\ pstate # "NONE"
  /\ netUp
  /\ ~kFresh
  /\ aepoch > 0
  /\ aepoch >= kEpoch
  /\ kFresh'      = TRUE
  /\ partitionAge' = 0
  /\ UNCHANGED <<pstate, pepoch, aepoch, netUp, kEpoch, revokeDone,
                 outcome, presented, staleGrant, unfreshGrant, leak>>

(***************************************************************************)
(* ACTIONS 6-8: NETWORK PARTITION                                          *)
(*   StartPartition -> AgePartition -> ExpireFreshness (fail-closed)       *)
(*   -> EndPartition -> Refresh/Sync                                       *)
(* (freshnesswindowandlatesttrustedroot.py: FreshnessWindowConfig)        *)
(***************************************************************************)
StartPartition ==
  /\ netUp
  /\ netUp'        = FALSE
  /\ partitionAge' = 0
  /\ UNCHANGED <<pstate, pepoch, aepoch, kEpoch, kFresh, revokeDone,
                 outcome, presented, staleGrant, unfreshGrant, leak>>

AgePartition ==
  /\ ~netUp
  /\ partitionAge < FreshnessWindow
  /\ partitionAge' = partitionAge + 1
  \* Freshness chi duoc phep GIAM/duy tri, khong bao gio tu quay lai TRUE
  \* (khong the tu recovery khi dang partition - phai qua Sync/Refresh co netUp)
  /\ kFresh'       = (kFresh /\ (partitionAge' < FreshnessWindow))
  /\ UNCHANGED <<pstate, pepoch, aepoch, netUp, kEpoch, revokeDone,
                 outcome, presented, staleGrant, unfreshGrant, leak>>

EndPartition ==
  /\ ~netUp
  /\ netUp'        = TRUE
  /\ partitionAge' = 0
  /\ UNCHANGED <<pstate, pepoch, aepoch, kEpoch, kFresh, revokeDone,
                 outcome, presented, staleGrant, unfreshGrant, leak>>

(***************************************************************************)
(* ACTION 9: RequestAccess - Luong tai diem chinh cua Key Node             *)
(* Trinh tu kiem tra khop resolve_fresh_policy():                          *)
(*   1. ~kFresh        -> "failclosed"   (I4: Partition mode fail closed)   *)
(*   2. presented#kEpoch-> "stale"       (I3: Stale proof bi tu choi)      *)
(*   3. pstate#ACTIVE  -> "blocked"      (I1: Terminal/Suspended blocked)  *)
(*   3 FLAG an toan duoc ghi nhan TAI THOI DIEM cap khoa -> khong con hien  *)
(*   tuong "outcome cu con ton tai sau khi state doi" (false positive).     *)
(*   Neu he thong sai lech (sua loi guard) -> flag = TRUE -> TLC bat!       *)
(* (freshnesswindowandlatesttrustedroot.py: resolve_fresh_policy)          *)
(***************************************************************************)
RequestAccess(p) ==
  /\ p \in RootViews
  /\ presented' = p
  /\ outcome'   = (IF      ~kFresh       THEN "failclosed"
                   ELSE IF p # kEpoch    THEN "stale"
                   ELSE IF pstate # "ACTIVE" THEN "blocked"
                   ELSE "granted")
  /\ staleGrant'   = (staleGrant   \/ (outcome' = "granted" /\ p # kEpoch))
  /\ unfreshGrant' = (unfreshGrant \/ (outcome' = "granted" /\ ~kFresh))
  /\ leak'         = (leak         \/ (outcome' = "granted" /\ revokeDone))
  /\ UNCHANGED <<pstate, pepoch, aepoch, netUp, kEpoch, kFresh,
                 partitionAge, revokeDone>>

(***************************************************************************)
(* BƯỚC TIẾP THEO (Next) + BIẾN LỊCH SỬ PHÁI SINH                          *)
(* Dung pattern chuan: tach Actions rieng de khong bi quantifier \E nuot    *)
(* cac conjunct maxKE'/terminalSeen' nam sau do (loi phan tich TLA+)        *)
(***************************************************************************)
Actions ==
  \/ InitPolicy
  \/ \E st \in {"SUSPENDED", "ACTIVE", "REVOKED", "EXPIRED"} : Transition(st)
  \/ Anchor
  \/ Sync
  \/ Refresh
  \/ StartPartition
  \/ AgePartition
  \/ EndPartition
  \/ \E p \in RootViews : RequestAccess(p)

Next ==
  /\ Actions
  /\ maxKE'       = (IF kEpoch' > maxKE THEN kEpoch' ELSE maxKE)   \* I2
  /\ terminalSeen' = (terminalSeen \/ (pstate' \in TerminalStates)) \* I1

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* INVARIANTS - KIỂM CHỨNG BẰNG TLC                                        *)
(***************************************************************************)
TypeOK ==
  /\ pstate       \in PolicyStates
  /\ pepoch       \in 1..MaxEpoch
  /\ aepoch       \in 0..MaxEpoch
  /\ netUp        \in BOOLEAN
  /\ kEpoch       \in 0..MaxEpoch
  /\ kFresh       \in BOOLEAN
  /\ partitionAge \in 0..FreshnessWindow
  /\ revokeDone   \in BOOLEAN
  /\ outcome      \in Outcomes
  /\ presented    \in RootViews
  /\ staleGrant   \in BOOLEAN
  /\ unfreshGrant \in BOOLEAN
  /\ leak         \in BOOLEAN
  /\ maxKE        \in 0..MaxEpoch
  /\ terminalSeen \in BOOLEAN

I1TerminalStable  == terminalSeen => pstate \in TerminalStates
I2EpochMonotonic  == kEpoch = maxKE
\* I3/I4 dung 3 flag ghi nhan tai thoi diem cap khoa (khong false positive
\* do outcome cu con ton tai sau khi state thay doi)
I3StaleRejected   == staleGrant = FALSE
I4FailClosed      == unfreshGrant = FALSE
I5NoLeak          == leak = FALSE
RevokeLatched     == revokeDone => (pstate = "REVOKED")

Safety == TypeOK /\ I1TerminalStable /\ I2EpochMonotonic /\ I3StaleRejected
          /\ I4FailClosed /\ I5NoLeak /\ RevokeLatched

(***************************************************************************)
(* LIVENESS (tùy chọn - cần fairness + giả định partition có hồi):         *)
(*   PartitionHealed  == netUp ~> kFresh                                   *)
(* Đo lường suy giảm liveness thực nghiệm bằng LivenessMetrics trong      *)
(* freshnesswindowandlatesttrustedroot.py (không phụ thuộc TLC).           *)
(***************************************************************************)

=============================================================================
