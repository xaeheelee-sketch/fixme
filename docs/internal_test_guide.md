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

## 단계 0 — 환경 준비

```bash
# 1. 의존성 설치 (사내 PyPI 미러를 사용한다면 --index-url 옵션 추가)
pip install -r requirements.txt
pip install -r requirements-dev.txt    # pytest

# 2. 환경변수
export INTERNAL_LLM_API_KEY=<게이트웨이 키>
# 위 텔레메트리 차단 4종

# 3. config.yaml 의 api_base 가 실제 게이트웨이 주소인지 확인
grep api_base config.yaml
```

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
