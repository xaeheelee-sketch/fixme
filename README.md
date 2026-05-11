# Fixme — Automated Vulnerability Fix Agent

C/C++ 임베디드 코드의 정적 분석(Metis) finding을 자동으로 분류·수정하는 LangGraph 기반 에이전트.
사내 운용을 전제로 **결정론 우선 / 좁은 스코프 / Human-in-the-Loop** 원칙으로 설계되어 있다.

---

## 핵심 설계 원칙

| 원칙 | 의미 |
|---|---|
| **Narrow Scope First** | 모든 CWE를 풀려 하지 않고, 자동수정 적합도가 높은 화이트리스트로 시작 |
| **Triage First** | 모든 finding을 같은 흐름에 넣지 않고, 4종으로 먼저 분류해 라우팅 |
| **Deterministic > LLM** | 패턴이 명확한 CWE는 AST/규칙 기반 파이썬 fixer로 처리, LLM은 비결정적 케이스에만 |
| **HITL Mandatory** | 어떤 수정도 main에 직접 머지 안 함. 모든 산출물은 검토용 PR/패치로만 |

---

## 처리 흐름 (S1~S6)

```
Metis JSON
  → [S1] 전처리·화이트리스트         (No LLM)
  → [S2] Triage 분류                 (Light LLM)
  → [S3] 라우팅 적용
        ├─ S3a. 결정론적 Fixer       (No LLM)        ── 단순 패턴 CWE
        ├─ S3b. LLM Fixer + Self-Healing (LangGraph) ── 비결정적 케이스
        └─ S3c. Explain-Only         (Light LLM)     ── 설계 변경 필요
  → [S4] 검증 (Build + Test + Sanitizer + Metis 전체 recheck)
  → [S5] 산출물 (브랜치 커밋 + 패치 + 리포트)
  → [S6] 피드백 (PR accept/reject → 다음 실행에 반영)
```

상세 설계는 [`fixme.md`](./fixme.md) 참고.

---

## Quick Start

### 요건
- Python **3.10+**
- 사내 OpenAI 호환 LLM 게이트웨이 1개 (URL + API 키)
- (선택) 대상 C/C++ 레포의 빌드 환경, Metis CLI

### 설치 (프로젝트 루트에서)

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate
# Unix
source .venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### LLM 설정 — `config.yaml` 한 파일에서 끝

별도 LLM 설정 파일은 **없다**. 다음 3군데만 사내 환경에 맞게 수정.

```yaml
api_base: http://internal-llm-gateway/v1   # ① 게이트웨이 URL (/v1까지)
api_key_env: INTERNAL_LLM_API_KEY          # ② 키를 담을 환경변수 이름

models:                                      # ③ 사내 게이트웨이가 노출하는 모델 ID
  triage:   qwen3.6-27b-fp8
  fixer:    gtp-oss-120b
  analyzer: qwen3.6-27b-fp8
```

API 키는 파일이 아닌 **환경변수**로 주입:

```bash
# Windows cmd
set INTERNAL_LLM_API_KEY=<키>

# PowerShell
$env:INTERNAL_LLM_API_KEY = "<키>"

# bash
export INTERNAL_LLM_API_KEY=<키>
```

### 5분 검증 시퀀스

```bash
# (1) 단위 테스트 — LLM 불필요
pytest -q

# (2) LLM 게이트웨이 연결 — 1 호출
python scripts/check_llm.py --config config.yaml

# (3) 단일 vuln triage — 1 호출, 입력 불필요
python scripts/smoke_triage.py --config config.yaml
```

셋 다 통과하면 본 작업 진입 가능.

폐쇄망/CA 인증서/프록시 등 상세 환경 설정은 [`docs/internal_test_guide.md`](./docs/internal_test_guide.md) 참고.

---

## 단계별 실행

`main.py`는 `--stage` 플래그로 어디까지 진행할지 게이트한다. LLM 게이트웨이 미준비, 빌드 환경 부재 같은 부분 환경에서도 단계까지는 검증 가능.

```bash
python main.py \
  --config config.yaml \
  --metis-input <metis_output>.json \
  --repo-root <대상_레포_경로> \
  --stage <stage> [--limit N] [--dry-run]
```

### Stage / 의존성 매트릭스

| Stage | LLM | 빌드 | Metis CLI | 용도 |
|---|:---:|:---:|:---:|---|
| `preprocess` | ✗ | ✗ | ✗ | scope 필터/whitelist 동작 확인 |
| `triage` | ✓ (light) | ✗ | ✗ | 분류 결과만 확인 (수정 안 함) |
| `deterministic` | ✓ (light) | ✓ | ✓ | 규칙 기반 수정만 시도 |
| `llm-fix` | ✓ (full) | ✓ | ✓ | LangGraph self-healing 루프 포함 |
| `full` | ✓ (full) | ✓ | ✓ | S3a + S3b + S3c 전체 |

추가 옵션:
- `--limit N` : 처음 N건만 처리 (smoke test)
- `--dry-run` : build/test/Metis를 noop으로 (패치 생성만 보고 실제 검증 생략)

### 권장 진행 순서

```bash
# (1) scope 분포 확인
python main.py ... --stage preprocess

# (2) LLM 분류만 소량 확인
python main.py ... --stage triage --limit 5

# (3) 결정론 fixer만, 빌드 없이 출력만 확인
python main.py ... --stage deterministic --limit 10 --dry-run

# (4) 빌드 환경 갖춘 뒤 결정론 + 검증
python main.py ... --stage deterministic --limit 10

# (5) LLM fix 소량
python main.py ... --stage llm-fix --limit 3

# (6) 풀 파이프라인
python main.py ... --stage full --limit 10
python main.py ... --stage full
```

---

## 산출물

`out/<run_id>/` 하위에 모두 적재:

| 파일 | 내용 |
|---|---|
| `report.json` | 각 finding의 (CWE, severity, triage_label, strategy, attempts, final_status, latency, token, cost) |
| `summary.md` | 사람이 1분 내 훑을 수 있는 요약 |
| `patches/*.patch` | S3a/S3b가 만든 unified diff (vuln 단위) |
| `explanations/*.md` | S3c가 만든 설명문 |
| `whitelist_candidates.json` | S2가 FALSE_POSITIVE로 분류한 후보 (사람 승인 후 등록) |
| `trace.jsonl` | 단계별 raw 이벤트 로그 |

작업 브랜치 `metis-autofix/<run_id>`에 vuln 단위 commit이 누적되며, **main에 직접 머지하지 않는다**. 리뷰어가 PR로 올려 cherry-pick.

---

## 프로젝트 구조

```
.
├── README.md                       ← 이 문서
├── fixme.md                        ← 상세 설계 문서 (S0~S6 정의)
├── config.yaml                     ← 단일 설정 파일 (scope/models/limits/runners)
├── main.py                         ← 진입점 (--stage 게이트)
├── requirements.txt
├── requirements-dev.txt
├── docs/
│   └── internal_test_guide.md      ← 사내 폐쇄망 단계별 가이드
├── scripts/
│   ├── check_llm.py                ← LLM 게이트웨이 연결성 ping
│   ├── smoke_triage.py             ← 단일 vuln triage smoke
│   └── draw_graph.py               ← LangGraph 시각화
├── fixme/                          ← 패키지 본체
│   ├── preprocessing.py            ← S1
│   ├── triage.py                   ← S2
│   ├── fixers/                     ← S3a (CWE별 결정론 fixer)
│   ├── llm_fixer.py                ← S3b (LangGraph)
│   ├── explain.py                  ← S3c
│   ├── verification.py             ← S4
│   ├── apply.py                    ← patch 적용 + 안전 검사
│   ├── safety.py                   ← replace_block 패턴 스캔
│   ├── runners.py                  ← Build/Test/Metis/Git + Noop 변형
│   ├── output.py                   ← S5 산출물 작성
│   ├── feedback.py                 ← S6 피드백 DB
│   ├── budget.py                   ← 토큰 예산
│   ├── tracer.py                   ← JSONL 트레이서
│   ├── context.py                  ← 함수 본체 추출
│   ├── config.py                   ← Pydantic 설정 모델
│   └── models.py                   ← 도메인 모델 (VulnRecord, FixOutput 등)
└── tests/                          ← pytest (mock 기반, LLM/빌드 불필요)
```

---

## 스코프 (config.yaml)

자동수정 시도 대상과 Explain-only 강제 대상을 구분.

```yaml
scope:
  enabled_cwes:           # S3a/S3b 라우팅 후보
    - CWE-457   # Uninitialized variable      (S3a)
    - CWE-476   # Null pointer dereference    (S3a/S3b) — Top1
    - CWE-401   # Memory leak                 (S3a)
    - CWE-563   # Unused variable             (S3a)
    - CWE-120   # Buffer copy w/o size check
    - CWE-787   # Out-of-bounds Write         (S3b)
    - CWE-119   # Buffer bounds 일반          (S3b)
    - CWE-125   # Out-of-bounds Read          (S3b)
    - CWE-190   # Integer overflow            (S3a)
    - CWE-369   # Divide by zero
    - CWE-415   # Double free
    - CWE-416   # Use after free
    - CWE-20    # Improper input validation   (S3b)

  explain_only_cwes:      # 자동수정 금지, S3c 강제
    - CWE-284   # Improper access control
    - CWE-327   # Broken/risky crypto
    - CWE-22    # Path traversal
    - CWE-319   # Cleartext transmission
```

---

## 기술 스택

| 영역 | 사용 |
|---|---|
| 언어/런타임 | Python 3.10+ |
| LLM 오케스트레이션 | LangChain, LangGraph |
| LLM 클라이언트 | `langchain-openai` (OpenAI 호환 — 사내 게이트웨이 사용) |
| 출력 검증 | Pydantic + tool/function calling |
| 외부 의존성 | `git`, Metis CLI, 컴파일러 + 테스트 러너, ASan/UBSan(가능 시) |

**외부 LLM 호출 없음**. 모든 호출은 `config.api_base`의 사내 게이트웨이로만 향한다.

---

## 현실적 처리율 가이드

660건 입력 기준 (실데이터 분포 분석 결과):

| 카테고리 | 비중 | 비고 |
|---|---:|---|
| S3a 결정론 자동수정 | ~15-20% | 주로 CWE-476/190 단순건 |
| S3b LLM fix 시도 | ~10-15% | 성공률 30~50% |
| S3c Explain-only | ~30-40% | 설계 변경 필요 CWE |
| Scope-out / FP / Skip | 나머지 | |

**"전체 cover"는 목표가 아니다.** 한 런 당 main에 머지 가능한 PR ≈ 100~150건이 현실적 상한.

---

## 안전 장치 (S3b)

LLM이 만든 패치를 적용하기 전 다음을 모두 통과해야 한다:

1. 파일 SHA 변경 없음 (외부 수정 감지)
2. `search_block` 매칭 횟수 == 1
3. 매칭 라인이 anchor ±3줄 이내
4. diff 라인 수 ≤ `max_diff_lines` (config)
5. **Safety scan**: `system(`/`exec*(`/`popen` 신규 도입, 외부 IP/URL 추가, base64 블록, `if (0)` 식 비활성화 등 의심 패턴 차단

위 검사 + S4 검증(build/test/sanitizer/Metis recheck) 모두 통과해야 vuln 단위 커밋이 살아남는다. 실패 시 `git reset --hard HEAD~1` 자동 롤백.

---

## 문서

- [`fixme.md`](./fixme.md) — 상세 설계 문서 (S0~S6 전체 사양)
- [`docs/internal_test_guide.md`](./docs/internal_test_guide.md) — 사내 폐쇄망 단계별 테스트 가이드 (환경 준비 → 단계 1~7 + 트러블슈팅)
- `config.yaml` — 단일 설정 파일

---

## 라이선스 / 상태

사내 검증 단계. 외부 배포 전.
