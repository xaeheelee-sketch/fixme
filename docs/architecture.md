# Agent Architecture Diagrams

`fixme.md`에 정의된 Automated Vulnerability Fix Agent의 구조를 한눈에 보기 위한 다이어그램 모음.

## 1) 전체 파이프라인 (S1 → S6)

```
        ┌────────────────────┐
        │   Metis JSON       │  정적분석 결과
        └─────────┬──────────┘
                  ▼
   ┌────────────────────────────┐
   │ S1. 전처리·화이트리스트     │  No LLM
   │  • scope/severity/path 필터│
   │  • inline ignore 주석      │
   │  • feedback_db 과거 reject │
   │  → git 브랜치 생성          │
   └─────────────┬──────────────┘
                 ▼
   ┌────────────────────────────┐
   │ S2. Triage 분류            │  Light LLM
   │  qwen3.6-27b-fp8           │  (Pydantic 강제)
   │  → TP_SIMPLE / TP_DESIGN   │
   │    FALSE_POSITIVE / OOS    │
   └─────────────┬──────────────┘
                 ▼
   ┌────────────────────────────┐
   │ S3. 라우팅                  │
   └──┬──────────┬──────────┬───┘
      ▼          ▼          ▼
   ┌──────┐  ┌──────┐  ┌─────────┐
   │ S3a  │  │ S3b  │  │  S3c    │
   │결정론│  │ LLM  │  │ Explain │
   │Fixer │  │+Self │  │  Only   │
   │No LLM│  │Heal  │  │ (LLM)   │
   └──┬───┘  └──┬───┘  └────┬────┘
      │         │           │
      └────┬────┘           │
           ▼                │
   ┌──────────────┐         │
   │ S4. 검증      │         │
   │ Build→Test→  │         │
   │ Sanitizer→   │         │
   │ Metis recheck│         │
   └──────┬───────┘         │
          │                 │
          └────────┬────────┘
                   ▼
   ┌────────────────────────────┐
   │ S5. 산출물 (HITL Gate)     │
   │  • metis-autofix/<run_id>  │
   │  • report.json / patches/  │
   │  • explanations/ summary.md│
   │  ★ main 직접 머지 금지     │
   └─────────────┬──────────────┘
                 ▼
   ┌────────────────────────────┐
   │ S6. Feedback 수집           │
   │  decisions.jsonl(append)   │
   │  → 다음 실행 S1/S3b 주입   │
   └────────────────────────────┘
```

## 2) S2 Triage 라우팅 (우선순위 순)

```
        TriageDecision
              │
              ▼
   ┌──────────────────────────┐
   │ 1. CWE ∈ explain_only?   │─Y→ S3c 강제
   └──────────┬───────────────┘
              │ N
              ▼
   ┌──────────────────────────┐
   │ 2. safety_critical path? │─Y→ S3c 강제
   └──────────┬───────────────┘
              │ N
              ▼
   ┌──────────────────────────┐
   │ 3. TP_SIMPLE + S3a지원? │─Y→ S3a
   └──────────┬───────────────┘
              │ N
              ▼
   ┌──────────────────────────┐
   │ 4. TP_SIMPLE & conf≥0.6 │─Y→ S3b
   └──────────┬───────────────┘
              │ N
              ▼
   ┌──────────────────────────┐
   │ 5. TP_DESIGN             │─Y→ S3c
   └──────────┬───────────────┘
              │ N
              ▼
   ┌──────────────────────────┐
   │ 6. FALSE_POSITIVE        │─Y→ whitelist 후보
   └──────────┬───────────────┘
              │ N
              ▼
       OUT_OF_SCOPE / conf<0.6
           → SKIP + log
```

## 3) S3b LangGraph (Self-Healing Loop)

```
        ┌─────────────────────┐
   START│ retrieve_context    │ No LLM
        │ • 함수본체+헤더     │
        │ • file_sha_before   │
        │ • negative_examples │
        └──────────┬──────────┘
                   ▼
        ┌─────────────────────┐
        │ generate_fix        │ gtp-oss-120b
        │ T:0.1→0.2→0.3      │ FixOutput(Pydantic)
        │ • search/replace    │
        │ • anchor_line       │
        │ • rationale         │
        └──────────┬──────────┘
                   ▼
        ┌─────────────────────┐
        │ apply_patch         │ No LLM
        │ ① SHA 동일?         │
        │ ② match==1?         │
        │ ③ anchor±3?         │
        │ ④ diff≤max?         │
        │ ⑤ safety scan?      │
        └──────┬───────┬──────┘
            OK │       │ FAIL
               ▼       ▼
        ┌──────────┐  retry<MAX?
        │ verify   │   Y→ analyze_error
        │ (=S4)    │   N→ rollback→END
        └──┬───────┘        (FAIL)
           │
   ┌───────┴────────┐
   ▼                ▼
 SUCCESS         FAIL
  END           │
 (commit       ┌┴─ retry<MAX? ─Y→┐
  keep)        │                  │
               N                  ▼
               ▼          ┌──────────────┐
        rollback→END      │ rollback     │
        (S3c 강등 mark)   │ (직전 커밋만)│
                          └──────┬───────┘
                                 ▼
                          ┌──────────────┐
                          │analyze_error │ qwen3.6
                          │ T:0.4        │ → hint
                          └──────┬───────┘
                                 │
                                 └─→ generate_fix
                                      (재시도)

   상태: retry_count, attempt_history,
         verify_status(BUILD/TEST/SANITIZER/
         METIS_RECHECK/SAFETY_SCAN/DIFF_TOO_LARGE)
```

핵심 4원칙이 흐름에 그대로 박혀 있음 — ① **결정론 우선**(S3a) → ② **LLM은 좁고 깊게**(S3b 셀프힐링) → ③ **설계 변경은 설명만**(S3c) → ④ 모든 산출은 **사람이 PR로 검토**(HITL).
