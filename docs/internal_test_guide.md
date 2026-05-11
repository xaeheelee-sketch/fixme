# 사내망 단계별 테스트 가이드

폐쇄망(외부 인터넷 차단) 환경에서 fixme 에이전트를 단계별로 검증하는 절차.
LLM 게이트웨이가 닿지 않거나 빌드 환경이 갖춰지지 않은 상황에서도 가능한 범위까지 진행할 수 있도록 설계되어 있다.

---

## 사전 점검: 외부 통신 흔적

코드 베이스 상태 (확인 완료):
- `openllm` 패키지: **사용 안 함**
- 외부 LLM 엔드포인트(`api.openai.com`, `api.anthropic.com` 등): **하드코딩 없음**
- 모든 LLM 호출은 `langchain_openai.ChatOpenAI(base_url=config.api_base, ...)` 형태로 사내 게이트웨이를 향함

**유일한 잠재적 외부 통신원**: LangChain/LangSmith 텔레메트리.
다음 환경변수를 셸 프로필에 박아 차단한다.

```bat
:: Windows cmd
set LANGCHAIN_TRACING_V2=false
set LANGSMITH_TRACING=false
set LANGCHAIN_TELEMETRY=false
set OPENAI_LOG_LEVEL=warn
```

```bash
# bash/PowerShell 등가
export LANGCHAIN_TRACING_V2=false
export LANGSMITH_TRACING=false
export LANGCHAIN_TELEMETRY=false
```

사내 프록시/CA 인증서가 필요한 환경이면 `REQUESTS_CA_BUNDLE` 또는 `SSL_CERT_FILE`을 사내 CA 번들 경로로 지정한다. (현재 기본 `api_base`가 `http://`라면 SSL 무관.)

---

## 단계 0 — 첫 실행 환경 준비

### 0-1. 디렉토리 / Python 버전

이하 모든 명령은 **프로젝트 루트** (`config.yaml`, `main.py`, `fixme/`가 같이 있는 디렉토리)에서 실행한다.

```
프로젝트루트/
├── config.yaml             ← 편집 대상
├── main.py                 ← 진입점
├── requirements.txt
├── requirements-dev.txt
├── fixme/                  ← 패키지 본체
├── scripts/                ← check_llm.py, smoke_triage.py
├── tests/                  ← pytest 대상
└── docs/                   ← 이 문서
```

**Python 요건**: 3.10 이상 (langchain-openai/langgraph 요구사항).
```bash
python --version    # Python 3.10.x 이상이어야 함
```

### 0-2. 가상환경 + 의존성 설치

프로젝트 루트에서:

```bash
# Windows (cmd / PowerShell)
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Linux / macOS / WSL
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

설치되는 것:
- `requirements.txt` → `langchain`, `langchain-openai`, `langgraph`, `pydantic`, `pyyaml` (런타임)
- `requirements-dev.txt` → `pytest` (테스트용)

**사내 PyPI 미러를 쓴다면** 매번 `--index-url <사내미러>`을 붙이거나 `pip.ini`/`pip.conf` 에 박는다.

### 0-3. LLM 설정 — `config.yaml` 한 파일에서 끝

별도의 LLM 설정 파일은 **없다**. 모든 LLM 관련 설정은 `config.yaml` 상단 + `models:` 블록 두 군데에 있다. 첫 실행 전 다음 **세 군데**를 사내 환경에 맞게 수정한다.

`config.yaml` (현재 상태):
```yaml
run_id: auto
api_base: http://internal-llm-gateway/v1   # ① 게이트웨이 주소 — 실제 값으로 교체
api_key_env: INTERNAL_LLM_API_KEY          # ② 키를 담을 환경변수 이름 (기본값 그대로 둬도 됨)

# ...

models:                                      # ③ 모델 ID — 사내 게이트웨이가 실제로 노출하는 이름으로 교체
  triage:   qwen3.6-27b-fp8
  fixer:    gtp-oss-120b
  analyzer: qwen3.6-27b-fp8
```

확인 방법:
- ① `api_base`: 사내 게이트웨이의 OpenAI 호환 베이스 URL. 보통 `/v1` 까지 포함. 예: `https://llm.intra.company.com/v1`
- ② `api_key_env`: 환경변수 **이름**(값 아님). 코드는 이 이름으로 `os.environ.get(...)` 한다. 키 자체는 셸에 export로 주입.
- ③ `models.{triage,fixer,analyzer}`: 게이트웨이의 모델 카탈로그(`/v1/models`)에서 확인한 정확한 ID. 셋 다 같은 모델로 시작해도 무방.

### 0-4. 환경변수 설정

```bash
# Windows cmd
set INTERNAL_LLM_API_KEY=<게이트웨이가_발급한_키>
set LANGCHAIN_TRACING_V2=false
set LANGSMITH_TRACING=false
set LANGCHAIN_TELEMETRY=false

# PowerShell
$env:INTERNAL_LLM_API_KEY = "<키>"
$env:LANGCHAIN_TRACING_V2 = "false"
$env:LANGSMITH_TRACING    = "false"
$env:LANGCHAIN_TELEMETRY  = "false"

# bash / zsh
export INTERNAL_LLM_API_KEY=<키>
export LANGCHAIN_TRACING_V2=false
export LANGSMITH_TRACING=false
export LANGCHAIN_TELEMETRY=false
```

단계 1(pytest)은 환경변수 없어도 통과한다. **단계 2부터 `INTERNAL_LLM_API_KEY` 필요.**

세션 종료 시 환경변수가 사라지므로 영구 적용하려면 OS 사용자 환경변수에 등록하거나 셸 프로필(`~/.bashrc`, PowerShell `$PROFILE`)에 박는다.

### 0-5. 사내망 SSL/프록시

게이트웨이가 `https://`이고 사내 CA 인증서를 쓴다면:

```bash
# bash
export SSL_CERT_FILE=/path/to/corp-ca-bundle.pem
export REQUESTS_CA_BUNDLE=/path/to/corp-ca-bundle.pem

# Windows
set SSL_CERT_FILE=C:\path\to\corp-ca-bundle.pem
set REQUESTS_CA_BUNDLE=C:\path\to\corp-ca-bundle.pem
```

게이트웨이가 `http://`면 SSL 무관(현재 기본값이 그러함).

HTTP/HTTPS 프록시가 필요하면 `HTTPS_PROXY`/`HTTP_PROXY` 표준 환경변수를 사용한다. **사내 게이트웨이는 보통 NO_PROXY** 에 추가해야 직접 통신:
```bash
export HTTPS_PROXY=http://corp-proxy:8080
export NO_PROXY=llm.intra.company.com,localhost,127.0.0.1
```

### 0-6. 첫 실행 quick-start (5분)

여기까지 끝내고 다음 3개를 순서대로 통과하면 환경 준비 완료:

```bash
# (1) 단위 테스트 — LLM 불필요. 가장 먼저.
pytest -q

# (2) LLM 게이트웨이 연결 — 1 호출
python scripts/check_llm.py --config config.yaml

# (3) 단일 vuln triage — 1 호출, 코드 베이스/Metis 입력 불필요
python scripts/smoke_triage.py --config config.yaml
```

위 셋 다 통과하면 **단계 3(전처리)** 부터 본 작업으로 진입.

### 0-7. 선택 사항 — 미리 만들어 둘 파일

다음 파일들은 코드가 없으면 가만히 빈값으로 처리하므로, 첫 실행에서 **반드시 만들 필요는 없다**. 운영 단계에서 필요해질 때 만든다.

| 경로 | 역할 | 형식 |
|---|---|---|
| `config/whitelist_rules.yaml` | rule-based 화이트리스트 (S1) | 리스트 of `{file_name, cwe, snippet_contains}` |
| `feedback/decisions.jsonl` | 과거 PR 리뷰 결과 (S6 → S1/S3b) | 라인당 1 JSON, `{vuln_signature, file, ..., decision}` |

### 0-8. Metis JSON 입력 형식 참고

`--metis-input` 으로 넘기는 JSON은 다음 구조를 기대한다 (Metis CLI `--json` 출력 그대로 호환):

```json
{
  "reviews": [
    {
      "file_path": "src/foo.c",
      "findings": [
        {
          "id": "metis-001",
          "line_number": 42,
          "cwe": "CWE-476",
          "severity": "High",
          "code_snippet": "ptr->field = 1;",
          "description": "Possible null pointer dereference."
        }
      ]
    }
  ]
}
```

단계 3(`--stage preprocess`)부터 이 입력이 필요하다. 단계 0~2는 입력 없이 진행 가능.

---

## 단계 1 — 단위 테스트 (LLM 불필요)

전부 mock 기반. LLM 게이트웨이 없이도 통과해야 정상.

```bash
pytest -q
```

**기대치**: 모두 PASS. 실패하면 의존성 설치 또는 코드 손상이 의심되니 다음 단계로 넘어가지 말 것.

---

## 단계 2 — LLM 게이트웨이 연결성 (LLM 필요, 1 호출)

게이트웨이 도달성/인증/모델 가용성/구조화 출력 지원을 한꺼번에 검증.

```bash
python scripts/check_llm.py --config config.yaml
```

**기대 출력 (예시)**:
```
[triage]
  Endpoint: http://internal-llm-gateway/v1
  Model:    qwen3.6-27b-fp8
  Key var:  INTERNAL_LLM_API_KEY (set)
  OK (412 ms) — structured: ok=True, message='pong'
[fixer]
  ...
[analyzer]
  ...
```

**자주 발생하는 실패와 대응**:

| 증상 | 원인 | 대응 |
|---|---|---|
| `ConnectError`, `Name or service not known` | DNS/방화벽 | 게이트웨이 호스트 ping/curl로 확인 |
| `401 Unauthorized` | 키 누락/만료 | `INTERNAL_LLM_API_KEY` 재설정 |
| `404 Not Found /v1/chat/completions` | base_url 경로 오류 | 게이트웨이 OpenAI 호환 경로 확인 (`/v1` 끝단까지 포함) |
| `Tool calling not supported` | 모델이 tool calling 미지원 | `--no-structured` 플래그로 재시도. 기본 chat은 되지만 구조화 출력 불가 → fixme 운용 곤란. 게이트웨이/모델 재선정 필요 |
| `SSL: CERTIFICATE_VERIFY_FAILED` | 사내 CA 미설치 | `SSL_CERT_FILE` 환경변수에 사내 CA 번들 지정 |

`scripts/smoke_triage.py` 도 사용 가능하지만 한 건의 실제 triage 호출까지 가므로 토큰을 더 소모한다. `check_llm.py`로 충분.

---

## 단계 3 — 전처리만 (S1) — LLM 불필요

Metis JSON을 입력해 scope 필터/whitelist/inline ignore가 의도대로 동작하는지 확인.
**LLM 게이트웨이가 닿지 않아도 진행 가능**.

```bash
python main.py \
  --config config.yaml \
  --metis-input <metis_output>.json \
  --repo-root <대상_레포_경로> \
  --stage preprocess
```

**산출물**: `out/<run_id>/preprocessed.json`
- `count`: scope-in 건수
- `findings`: 각 finding의 정규화 레코드

확인 항목:
- 입력 N건 중 `enabled_cwes` ∪ `explain_only_cwes` 안에 들어온 비율이 의도한 만큼인가?
- `path_blocklist`(`third_party/**` 등)가 제대로 잘랐는가?
- inline `// metis-ignore` 마커가 코드에 있다면 제외됐는가?

전처리 결과가 0건이면 config.yaml의 `enabled_cwes`/`min_severity`/`path_*` 가 실데이터 분포와 안 맞는다는 신호.

---

## 단계 4 — Triage까지 (S1+S2) — LLM 필요, 빌드 불필요

소량으로 LLM 분류만 돌려본다. **수정/검증 단계는 진입하지 않음**.

```bash
python main.py \
  --config config.yaml \
  --metis-input <metis_output>.json \
  --repo-root <대상_레포_경로> \
  --stage triage \
  --limit 5
```

**산출물**: `out/<run_id>/report.json`
- 각 항목 `final_status` = `TRIAGED_<route>` (예: `TRIAGED_DETERMINISTIC`, `TRIAGED_EXPLAIN_ONLY`)
- `triage_label`, `strategy` 채워짐

확인 항목:
- 라벨 분포가 합리적인가? `OUT_OF_SCOPE`만 잔뜩이면 프롬프트/모델 미스매치
- `confidence` 값들이 0.6 이상에 분포하는가? 너무 낮으면 모델 부적합
- 1건당 latency가 수 초 이내인가? 게이트웨이 부하 점검

토큰 사용량이 보고되지 않으면 `out/<run_id>/trace.jsonl` 에서 `triage` 이벤트 raw 로그 확인.

---

## 단계 5 — Deterministic fix까지 (S1+S2+S3a) — LLM 필요, 빌드 환경 권장

규칙 기반 수정만 시도. CWE-457/476/563/401/190 등 결정론 fixer가 매칭되는 finding만 수정.

빌드 환경이 **준비되지 않았다면** `--dry-run` 으로 verifier를 noop 처리:

```bash
python main.py \
  --config config.yaml \
  --metis-input <metis_output>.json \
  --repo-root <대상_레포_경로> \
  --stage deterministic \
  --limit 10 \
  --dry-run
```

`--dry-run` 동작:
- patch apply, search_block 매칭, anchor 검사, safety scan, git commit: **수행**
- build/test/sanitizer/Metis recheck: **noop** (항상 SUCCESS)

→ "어떤 수정이 만들어지는가" 만 검토. 실제 합당성은 후속 단계에서.

빌드 가능한 환경(컴파일러+테스트 러너+Metis CLI 모두 있음)이면 `--dry-run` 빼고 진짜 검증 동반:

```bash
python main.py --config config.yaml --metis-input ... --repo-root ... --stage deterministic --limit 10
```

**산출물**:
- `out/<run_id>/patches/*.patch`: 적용된 unified diff
- `out/<run_id>/report.json`: `strategy=DETERMINISTIC`, `final_status=SUCCESS|FAILED_*`
- 작업 브랜치 `metis-autofix/<run_id>`에 vuln 단위 commit 누적 (실패 시 자동 reset)

---

## 단계 6 — LLM fix까지 (S1+S2+S3a+S3b) — LLM/빌드 모두 필요

LangGraph self-healing 루프 포함. 한 finding 당 최대 `max_retries` 시도.

```bash
python main.py \
  --config config.yaml \
  --metis-input <metis_output>.json \
  --repo-root <대상_레포_경로> \
  --stage llm-fix \
  --limit 3
```

**처음에는 반드시 `--limit 3` 정도로 좁힐 것.** 1건당 LLM 호출이 generate_fix + analyze_error로 누적되어 토큰을 빠르게 소모한다.

**산출물**: 단계 5와 동일 + `out/<run_id>/trace.jsonl`에 `fix_*`/`analyze_*` 이벤트.

trace.jsonl을 열어 다음을 점검:
- search_block 매칭 실패 비율 (LLM이 코드 컨텍스트를 정확히 인용 못함의 시그널)
- safety scan trigger 빈도
- 평균 retry 횟수 (3회 가까우면 모델/프롬프트 튜닝 필요)

---

## 단계 7 — 풀 파이프라인 (S1~S5) — 모든 환경 필요

```bash
# 먼저 소량으로
python main.py --config config.yaml --metis-input ... --repo-root ... --stage full --limit 10

# 안정 확인 후 전체
python main.py --config config.yaml --metis-input ... --repo-root ... --stage full
```

**산출물 일체**:
- `out/<run_id>/patches/*.patch`
- `out/<run_id>/explanations/*.md`  (S3c)
- `out/<run_id>/whitelist_candidates.json`
- `out/<run_id>/report.json`, `summary.md`, `trace.jsonl`

작업 브랜치 `metis-autofix/<run_id>` 를 PR로 올려 사람이 cherry-pick.

---

## Stage / 의존성 매트릭스

| Stage | 단위 테스트 | LLM | 빌드 | Metis CLI | 추천 시점 |
|---|---|---|---|---|---|
| `--stage preprocess` | — | ✗ | ✗ | ✗ | 가장 먼저, 항상 |
| `--stage triage` | — | ✓ (light) | ✗ | ✗ | LLM 게이트웨이 검증 직후 |
| `--stage deterministic` (+ `--dry-run`) | — | ✓ (light) | ✗ | ✗ | 빌드 환경 없이 fixer 동작 점검 |
| `--stage deterministic` | — | ✓ (light) | ✓ | ✓ | 빌드 환경 갖춘 뒤 |
| `--stage llm-fix` | — | ✓ (full) | ✓ | ✓ | deterministic 안정 후 |
| `--stage full` | — | ✓ (full) | ✓ | ✓ | 최종 |

---

## 토큰 예산 운용

`config.yaml` `limits.per_run_token_budget` 가 한 런 상한선. 초과 시 잔여 finding은 `SKIPPED_BUDGET`으로 마킹되고 프로세스는 exit code 2로 종료.

소량 검증 단계(단계 4~6, `--limit` 사용)에서는 `per_run_token_budget`을 작게(예: 100_000) 설정해 폭주를 막는 것을 권장.

---

## 자주 발생하는 운영 이슈

| 증상 | 의심 원인 | 확인 |
|---|---|---|
| 모든 finding이 `OUT_OF_SCOPE` | scope 필터가 너무 좁거나 CWE 표기 다름 | `--stage preprocess` 로 분포 확인 |
| `FAILED_PATCH_APPLY` 가 다수 | LLM이 search_block 인용 부정확 | trace.jsonl `search_block matched 0x` 빈도 점검 |
| `FAILED_BUILD` 가 다수 | 컴파일러/플래그 미스매치, 헤더 변경 영향 | `runners.build_cmd` 직접 실행 확인 |
| `FAILED_METIS_RECHECK` 가 다수 | 다른 TU에 영향 누설 | 헤더/매크로 수정 fixer 비활성화 검토 |
| `FAILED_SAFETY_SCAN` | LLM이 의심 패턴 도입 (system/exec 등) | safety.py 패턴 적정성 검토 |
| 게이트웨이 timeout 다수 | 게이트웨이 부하 / 모델 컨텍스트 초과 | `context.py` window 축소, 부하 시간대 회피 |

---

## 다음 단계

검증이 끝나면 다음을 결정:
1. `enabled_cwes` 의 실데이터 적합도 — 단계 3 결과 기준 재조정
2. 결정론 fixer 우선순위 — 단계 5 성공률 기준 (CWE-476이 압도적이면 그쪽 보강)
3. LLM 모델 선택 — 단계 6 retry 패턴이 안 좋으면 더 큰 모델 또는 프롬프트 튜닝
4. 작업 브랜치 PR 흐름 — 사내 코드리뷰 도구와 어떻게 연결할지
