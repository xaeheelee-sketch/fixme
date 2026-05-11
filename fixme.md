# Role
당신은 LangChain과 LangGraph를 활용하여 C/C++ 임베디드 환경의 보안 취약점을 자동으로 분류·수정하는 'Automated Vulnerability Fix Agent'를 개발하는 수석 파이썬 엔지니어입니다.

# Design Philosophy
사내 운용을 전제로 다음 4가지 원칙을 1급 요구사항으로 둡니다.

1. **좁게 시작한다(Narrow Scope First)**: 모든 CWE를 풀려 하지 않고, 자동수정 적합도가 높은 CWE 화이트리스트로 시작합니다.
2. **분류가 수정보다 먼저다(Triage First)**: 모든 finding을 같은 흐름에 넣지 않고, 먼저 4종으로 분류해 적절한 처리기로 라우팅합니다.
3. **결정론을 우선한다(Deterministic > LLM)**: 패턴이 명확한 CWE는 AST/규칙 기반 파이썬 fixer로 처리하고, LLM은 비결정적 케이스에만 투입합니다.
4. **사람이 최종 결정한다(HITL Mandatory)**: 어떤 수정도 main에 직접 머지하지 않습니다. 모든 산출물은 검토용 PR/패치로만 노출됩니다.

# System Overview
정적 분석 도구(Metis)에서 검출된 취약점(JSON 포맷)을 입력받아 다음 6단계로 처리합니다.

```
Metis JSON
  → [S1] 전처리·화이트리스트 (No LLM)
  → [S2] Triage 분류 (Small LLM)
  → [S3] 라우팅 적용
        ├─ 3a. 결정론적 Fixer (No LLM)         ── 단순 패턴 CWE
        ├─ 3b. LLM Fixer + Self-Healing (LangGraph) ── 비결정적 케이스
        └─ 3c. Explain-Only Generator (LLM)    ── 설계 변경 필요
  → [S4] 검증 (Build + Test + Sanitizer + Metis 전체 recheck)
  → [S5] 산출물 생성 (브랜치 커밋 + 패치 + 리포트)
  → [S6] 피드백 수집 (다음 실행에 PR accept/reject 반영)
```

# Tech Stack
- Framework: Python, LangChain, LangGraph
- LLM APIs (사내 OpenAI 호환 게이트웨이):
  - **Main Fixer**: `gtp-oss-120b` (S3b 코드 수정 전담)
  - **Light LLM**: `qwen3.6-27b-fp8` (S2 Triage, S3b 에러 분석, S3c Explain 전담)
- Output Parsing: Pydantic + OpenAI tool/function calling (Regex fallback 금지)
- 외부 의존성: `git`(롤백 스냅샷), Metis CLI(재검증), 컴파일 툴체인, ASan/UBSan 지원 컴파일러(가능 시)

# Core Workflow & Architecture

## S0. Configuration & Scope Control
`config.yaml`로 다음을 외부화합니다.

```yaml
scope:
  # 자동/LLM 수정 시도 대상 CWE
  enabled_cwes:
    # 결정론 fixer 또는 LLM 수정 후보 (S3a / S3b 라우팅)
    - CWE-457   # Uninitialized variable (S3a)
    - CWE-476   # Null pointer dereference (S3a 다수, 복잡건 S3b) — Top1, 171건
    - CWE-401   # Memory leak (S3a 단순건)
    - CWE-563   # Unused variable (S3a)
    - CWE-120   # Buffer copy without size check
    - CWE-787   # Out-of-bounds Write (S3b)
    - CWE-119   # Buffer bounds 일반 (S3b) — Top4, 70건
    - CWE-125   # Out-of-bounds Read (S3b) — Top6, 31건
    - CWE-190   # Integer overflow (S3a 단순건)
    - CWE-369   # Divide by zero
    - CWE-415   # Double free
    - CWE-416   # Use after free
    - CWE-20    # Improper input validation (S3b, NULL/길이 체크 추가 위주) — Top2, 74건
  # scope에는 포함하되 자동수정은 시도하지 않고 무조건 Explain-only(S3c)로만 처리하는 CWE.
  # 이유: 설계 변경/아키텍처/프로토콜 레벨 결정이 필요해 자동수정이 위험하지만, 리뷰어 트리아지에 설명문서가 가치 있음.
  explain_only_cwes:
    - CWE-284   # Improper access control
    - CWE-327   # Broken/risky crypto
    - CWE-22    # Path traversal
    - CWE-319   # Cleartext transmission
  min_severity: Medium
  path_allowlist: ["src/**", "lib/**"]
  path_blocklist: ["third_party/**", "vendor/**", "**/*generated*"]
  safety_critical_paths: ["src/safety/**"]   # 자동수정 절대 금지, Explain-only로만 처리
models:
  triage: qwen3.6-27b-fp8
  fixer:  gtp-oss-120b
  analyzer: qwen3.6-27b-fp8
limits:
  max_retries: 3
  max_diff_lines: 30           # 단일 fix가 30줄 초과하면 자동 reject → Explain-only로 강등
  per_run_token_budget: 5_000_000
runners:
  build_cmd:  "make -j"
  test_cmd:   "ctest --output-on-failure"
  sanitizer_cmd: "make CFLAGS='-fsanitize=address,undefined -g' -j"
  metis_cmd:  "metis scan --json"
```

`enabled_cwes`에 없는 finding은 처음부터 처리 대상에서 제외됩니다(스코프 통제).

## S1. Preprocessing & Whitelisting (No LLM)
함수: `parse_and_filter_vulnerabilities(raw_json, config, feedback_db) -> list[dict]`

순서대로 적용:
1. **Scope 필터**: `enabled_cwes ∪ explain_only_cwes`, `min_severity`, `path_allow/blocklist`. 두 집합 모두 scope 안.
2. **Scope-out 카운팅**: scope에서 제외된 finding 수를 CWE별로 집계해 `report.json.scope_out`에 보존(운영자가 "의도적 제외" 인지 가능하도록).
3. **Rule-based Whitelist**: `[{"file_name": "mkdep.c", "cwe": "CWE-120", "snippet_contains": "memcpy(depname"}]` 형태 규칙
4. **Inline Comment Whitelist**:
   - `// metis-ignore: CWE-XXX` (해당 라인)
   - `// metis-ignore-next-line: CWE-XXX`
   - `// metis-ignore-begin: CWE-XXX` ~ `// metis-ignore-end` (블록)
   - 다중 CWE: `metis-ignore: CWE-120,CWE-787`
5. **Past-rejection lookup**: `feedback_db`에서 이전에 reject된 동일 (file, line range, CWE) 튜플 제외
6. **파일 단위 그룹핑**: 동일 파일은 순차 처리하도록 묶음 반환

처리 시작 전 git 베이스 SHA를 기록하고, 작업 브랜치 `metis-autofix/<run_id>`를 생성합니다.

## S2. Triage Classification (Light LLM)
함수: `triage_vulnerability(vuln, code_context) -> TriageDecision`

**Light LLM(`qwen3.6-27b-fp8`)** 한 번 호출로 finding을 4종 중 하나로 분류합니다. Pydantic + tool calling 강제.

```python
class TriageDecision(BaseModel):
    label: Literal["TP_SIMPLE", "TP_DESIGN", "FALSE_POSITIVE", "OUT_OF_SCOPE"]
    confidence: float                # 0.0~1.0
    rationale: str                   # 1~2문장
    suggested_strategy: Literal["DETERMINISTIC", "LLM_FIX", "EXPLAIN_ONLY", "SKIP"]
```

라우팅 규칙(우선순위 순서대로 평가, 먼저 매칭되는 규칙 적용):
1. **CWE가 `explain_only_cwes`에 속함** → **S3c (Explain-only) 강제**. triage label/strategy 무시. 자동수정 시도 금지.
2. `safety_critical_paths` 매칭 → **S3c (Explain-only) 강제**.
3. `TP_SIMPLE` + CWE가 결정론 fixer 지원 → **S3a**
4. `TP_SIMPLE` + 미지원 CWE → **S3b** (`confidence >= 0.6`일 때만)
5. `TP_DESIGN` → **S3c (Explain-only)**
6. `FALSE_POSITIVE` → 화이트리스트 후보 큐에 적재(사람 승인 후 등록)
7. `OUT_OF_SCOPE` 또는 `confidence < 0.6` → 스킵 + 로그

## S3. Apply (3 Sub-flows)

### S3a. Deterministic Fixer (No LLM)
CWE별 파이썬 함수 레지스트리. 각 함수는 `(vuln, source) -> Optional[Patch]`.

초기 지원 대상(확장 가능):
- `CWE-476` (단순 null deref): 사용 직전 null check 삽입 — **최우선 구현 대상**. 실데이터에서 가장 큰 비중(Top1)이라 정확도가 시스템 ROI를 좌우함. 다음 패턴 우선 처리: ① 단일 인자 deref (`p->x`, `*p`) 직전 `if (!p) return <err>;`, ② 함수 진입부 파라미터 NULL guard 추가.
- `CWE-457` (Uninitialized variable): 선언부에 `= 0` / `= NULL` / `= {0}` 삽입
- `CWE-563` (Unused variable): 선언 제거 또는 `(void)var;`
- `CWE-401` (Memory leak, 단순 케이스): 매칭되는 `free()`를 에러 경로에 삽입
- `CWE-190` (단순 정수 오버플로우): `size_t` 타입 캐스팅, `SIZE_MAX` 체크 삽입

각 fixer는 **AST 또는 정밀 정규식** 기반이며, 한 fix당 변경 라인을 5줄 이내로 제한합니다. 매칭 실패 시 즉시 S3b로 강등(escalate).

> **현실적 처리율 가이드**: 660건 규모 입력 기준, S3a로 자동수정 가능한 비율은 ~15~20%(주로 CWE-476/190 단순건). 나머지는 S3b LLM 시도(성공률 30~50%) 또는 S3c Explain-only로 분배되는 게 정상. "전체 cover" 가 목표가 아님.

### S3b. LLM Fixer with Self-Healing Loop (LangGraph)

#### State Definition (AgentState)
- `vuln_info`: dict (CWE, severity 포함)
- `original_code_context`: str (취약점이 속한 **함수 본체 전체** + 관련 헤더 선언, 함수 추출 실패 시 ±20줄 fallback)
- `current_fixed_code`: dict (`search_block`, `replace_block`, `anchor_line`, `rationale`)
- `applied_diff`: str (직전 시도의 unified diff)
- `file_sha_before`: str (패치 직전 파일 SHA-256)
- `retry_count`: int (Max = 3)
- `attempt_history`: list[dict] (과거 시도 (fix, error_log, hint) 누적)
- `negative_examples`: list[dict] (S6 feedback에서 가져온 "이 파일/CWE에서 과거 reject된 패턴")
- `error_log`: str
- `error_analysis_hint`: str
- `verify_status`: Literal["SUCCESS", "FAILED_BUILD", "FAILED_TEST", "FAILED_SANITIZER", "FAILED_METIS_RECHECK", "FAILED_SAFETY_SCAN", "FAILED_DIFF_TOO_LARGE"]

#### Nodes
1. **`retrieve_context_node`** (No LLM): 함수 본체 + 헤더/typedef + `file_sha_before` 계산. S6 피드백에서 `negative_examples` 로드.
2. **`generate_fix_node`** (`gtp-oss-120b`, T: 0.1→0.2→0.3 단계 상승):
   - Input: `vuln_info`, `original_code_context`, `error_analysis_hint`, `attempt_history`, `negative_examples`
   - Pydantic 스키마 강제:
     ```python
     class FixOutput(BaseModel):
         search_block: str
         replace_block: str
         anchor_line: int
         rationale: str          # 수정 근거 1~2문장
         changes_behavior: bool  # 동작 변경 여부 자가 신고
     ```
   - retry 단계별 프롬프트 차별화: ① 일반 → ② hint 강조 → ③ "minimal patch only, 동작 변경 금지"
3. **`apply_patch_node`** (No LLM) — 다음 안전 검사를 모두 통과해야 쓰기:
   1. 파일 SHA = `file_sha_before` (외부 변경 없음)
   2. `search_block` 매칭 횟수 == 1 (0 또는 ≥2면 retry)
   3. 매칭 라인이 `anchor_line` ±3줄 이내
   4. diff 크기 ≤ `max_diff_lines` (초과 시 `FAILED_DIFF_TOO_LARGE`)
   5. **Safety scan**: `replace_block`에 의심 패턴(외부 IP/URL 추가, `system(`/`exec*(`/`popen` 신규 도입, base64 블록, 비활성화처럼 보이는 `if (0)` 등) 검출 시 즉시 실패
   - 통과 시: 파일 덮어쓰기 → diff 캡처 → vuln 단위 git commit (`fix(metis): <CWE> @ <file>:<line> [attempt N]`)
4. **`verify_node`** (No LLM) — **S4 호출**. 결과를 `verify_status`/`error_log`에 기록.
5. **`analyze_error_node`** (`qwen3.6-27b-fp8`, T: 0.4):
   - Input: `verify_status`별 분기 분석. `attempt_history`에 과거 시도 누적해 같은 실수 회피.
6. **`rollback_node`** (No LLM): 재시도 한도 초과 또는 안전 검사 확정 실패 시 마지막 vuln 커밋 `git reset --hard HEAD~1`.

#### Edges
- Start → `retrieve_context_node` → `generate_fix_node` → `apply_patch_node` → `verify_node`
- `apply_patch_node` 안전검사 실패:
  - `retry_count` < MAX → `analyze_error_node` → `generate_fix_node`
  - `retry_count` ≥ MAX → `rollback_node` → END(FAILED)
- `verify_node`:
  - SUCCESS → END (커밋 유지)
  - FAILED & `retry_count` < MAX → `rollback_node`(직전 커밋만) → `analyze_error_node` → `generate_fix_node`
  - FAILED & `retry_count` ≥ MAX → `rollback_node` → END(FAILED, S3c로 강등 후보 마킹)

### S3c. Explain-Only Generator (`qwen3.6-27b-fp8`)
함수: `generate_explanation(vuln, code_context) -> ExplanationOutput`

```python
class ExplanationOutput(BaseModel):
    summary: str            # 취약점 요약 1~2문장
    root_cause: str         # 근본 원인 분석
    suggested_approach: str # 권장 수정 접근법(코드 미생성)
    risk_if_unfixed: str    # 미수정 시 리스크
    estimated_complexity: Literal["LOW", "MEDIUM", "HIGH"]
```

산출물은 `out/<run_id>/explanations/<vuln_id>.md`로 저장되며, 코드 변경은 발생하지 않습니다.

## S4. Verification (No LLM)
S3a/S3b 패치 적용 후 호출되는 공통 검증기. 다음을 순서대로 실행하며, 어느 단계든 실패 시 즉시 종료하고 stderr를 반환.

1. **Build**: `runners.build_cmd`. 실패 → `FAILED_BUILD`.
2. **Unit test**: `runners.test_cmd`. 실패 → `FAILED_TEST`.
3. **Sanitizer build & test (가능 시)**: `runners.sanitizer_cmd` + 동일 테스트. ASan/UBSan 위반 → `FAILED_SANITIZER`.
   - 환경에 sanitizer 미지원 시 이 단계 skip 가능(config로 토글).
4. **Metis recheck (전체 프로젝트, 해당 파일만 아님)**: 헤더 변경이 다른 TU에 영향 줄 수 있어 전체 스캔 필수.
   - 원본 CWE finding이 사라졌는가? + **새로운 finding이 0건인가?** 둘 다 만족해야 통과.
   - 미달 → `FAILED_METIS_RECHECK`.

비용 절감을 위해 S3a 단순 fix(예: 단일 라인 변경, 헤더 미변경)는 **incremental verify** 모드 허용: build는 변경 TU만, Metis recheck는 변경 파일 + 의존 TU만.

`BuildRunner`, `MetisRunner`, `SanitizerRunner`를 의존성 주입 가능한 인터페이스로 추상화하여 단위 테스트에서 mock 주입 가능하도록 작성.

## S5. Output Artifacts (HITL Gate)
어떤 fix도 main 브랜치에 직접 반영하지 않습니다.

- 작업 브랜치 `metis-autofix/<run_id>`에 vuln 단위 커밋 누적
- `out/<run_id>/report.json`:
  - `findings`: 각 vuln의 (id, CWE, severity, triage_label, strategy, attempts, final_status, diff_path, tokens, latency, cost_estimate)
  - `scope_out`: S1에서 scope 필터로 제외된 finding 수를 CWE별 집계 (`{"CWE-XXX": N, ...}`). "의도적으로 안 본" finding 가시화 목적.
  - `totals`: 전체 입력 N / scope-in / 자동수정 성공 / LLM 시도 / Explain-only / FP 후보 / 스킵
- `out/<run_id>/patches/*.patch`: 개별 unified diff
- `out/<run_id>/explanations/*.md`: S3c 산출물
- `out/<run_id>/whitelist_candidates.json`: S2에서 `FALSE_POSITIVE`로 분류된 항목들 (사람 승인 후 화이트리스트 등록 대상)
- `out/<run_id>/summary.md`: 사람이 1분 내 훑을 수 있는 요약(전체 N건 / scope-out N건 / 성공 / 실패 / Explain / FP 후보)

리뷰어는 브랜치를 PR로 올리고, 커밋 단위로 cherry-pick하여 main에 반영합니다.

## S6. Feedback Ingestion
이전 실행의 PR 리뷰 결과를 누적해 다음 실행에 반영합니다.

- 저장소: `feedback/decisions.jsonl` (append-only)
  - 각 레코드: `{vuln_signature, file, line_range, cwe, decision: "MERGED"|"REJECTED"|"MODIFIED", reason?, reviewer?, ts}`
  - `vuln_signature`는 (CWE, 정규화된 코드 컨텍스트의 fingerprint)로 산출
- 신규 실행 시 활용:
  - **S1**에서 `REJECTED`가 누적된 동일 시그니처는 자동 제외 또는 화이트리스트 후보 승격
  - **S3b retrieve_context_node**에서 동일 파일/CWE의 과거 reject된 패턴을 `negative_examples`로 로드, 프롬프트에 "이런 형태는 과거 reject되었음" 으로 주입
- 수집 방법: PR 머지/클로즈 시 GitHub Action 또는 git hook으로 `decisions.jsonl` 갱신(별도 파이프라인, 본 에이전트 외부 스크립트로 처리).

# Implementation Requirements
1. 위 6단계 구조를 완벽히 만족하는 **실행 가능한 파이썬 전체 코드**를 작성하세요.
2. 그래프 외부 진입점 `__main__`은 다음 순서로 동작합니다:
   - `config.yaml` 로드 → `feedback_db` 로드 → `parse_and_filter_vulnerabilities` → 파일 단위 그룹핑
   - 그룹별 순차 루프, 각 vuln에 대해 S2 triage → 라우팅에 따라 S3a/S3b/S3c 호출
   - 매 vuln 처리 후 S4 검증 결과를 `report.json`에 누적
   - 전체 종료 시 `summary.md` 생성
3. LangChain `ChatOpenAI`로 모델별 인스턴스를 생성하고, S2/S3b/S3c 모두 `with_structured_output(<Pydantic>)` 또는 동등한 tool calling으로 출력을 강제하세요.
4. JSON/스키마 파싱 에러, 빌드/테스트 timeout, git/Metis 실행 실패에 대한 예외 처리(try-except)를 꼼꼼히 작성하고, 모든 실패는 `attempt_history`와 `report.json`에 기록되어야 합니다.
5. **관측성**: vuln 단위로 (vuln_id, CWE, severity, triage_label, strategy, attempts, tokens_in/out, latency_ms, cost_estimate, final_status)를 JSONL로 기록하는 트레이서를 추가하세요. LangSmith는 선택, 기본은 로컬 파일.
6. **토큰 예산**: 누적 토큰이 `per_run_token_budget`을 초과하면 신규 LLM 호출을 거부하고 잔여 vuln은 SKIP으로 마킹하세요.
7. **테스트 가능성**: `BuildRunner`, `TestRunner`, `SanitizerRunner`, `MetisRunner`, `LLMClient`, `GitOps`를 의존성 주입 가능한 인터페이스로 분리하세요. 단위 테스트가 mock으로 전체 그래프를 실행할 수 있어야 합니다.
8. **보수성**: S3a 결정론 fixer는 CWE별 모듈(`fixers/cwe_457.py` 등)로 분리해, 새 CWE 지원 추가가 LLM 코드 변경 없이 가능하도록 구성하세요.

<!-- hook 동작 테스트 -->
<!-- Stop hook 자동 push 검증 #2 -->

