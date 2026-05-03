# AutoKFL

Linux 커널 크래시 **Fault Localization**(결함 국소화)을 위한 멀티 에이전트 기반 자동 분석 도구입니다.  
LangGraph로 구성된 4개 에이전트가 인간의 분석 과정(관찰 → 수집 → 분석 → 증거 종합)을 모방하여 버그 위치를 추정합니다.

## 주요 기능

- **Syzkaller 연동**: [syzkaller.appspot.com](https://syzkaller.appspot.com)에서 크래시 정보·reproducer 조회
- **커널 빌드·재현**: Linux 커널 클론, worktree 생성, 커널/이미지 빌드, C reproducer 빌드 및 재현
- **Fault Localization (FL)**: 콜스택·faulty 코드·크래시 정보를 입력으로 LLM 에이전트가 버그 위치·원인 추정

## 아키텍처

| 에이전트 | 역할 |
|----------|------|
| **Crash Observer** | 콜스택·CPU 컨텍스트·reproducer 관찰 및 크래시 지점 정리 |
| **Code Collector** | 크래시 지점·관련 함수/구조체/호출 그래프·데이터 의존성 수집 |
| **Code Analyzer** | 버그 패턴 탐지, 메모리/바운드/락 순서·포인터 별칭 등 정적 분석 |
| **Evidence Synthesizer** | 증거 종합, 가설 일관성 검증, 신뢰도·가중치 계산, 최종 결론 도출 |

에이전트 간 라우팅은 조건부 엣지로 이루어지며, 필요 시 이전 단계로 돌아가 반복 분석합니다.

## 요구사항

- Python 3.10+
- 의존성: `pexpect`, `requests`, `langgraph`, `langchain-anthropic`, `langchain-openai`, `python-dotenv`, `pydantic`, `libclang`

## Installation

1. 저장소 클론 후 프로젝트 루트에서:

```bash
pip install -e .
```

2. API 키 설정: 프로젝트 루트에 `.env` 파일을 만들고 사용할 LLM에 맞는 키를 설정합니다.

```bash
# OpenAI (--model gpt 사용 시)
OPENAI_API_KEY=sk-...

# Anthropic (--model claude 사용 시)
ANTHROPIC_API_KEY=sk-ant-...
```

## Usage

### CLI 인자

| 인자 | 설명 |
|------|------|
| `--workdir` | 작업 디렉터리 경로 (필수) |
| `--task` | 실행할 작업 (필수) |
| `--crash_id` | Syzkaller 크래시 ID 또는 `DUMMY` (필수) |
| `--model` | FL용 LLM: `gpt` 또는 `claude` (기본값: `gpt`) |
| `--qemu_ssh` | QEMU SSH 사용 (플래그) |
| `--run_qemu` | QEMU 실행 (플래그) |

### 작업(task)별 실행

작업은 보통 아래 순서로 진행합니다.

```bash
# 1. Linux 커널 클론 (crash_id는 사용하지 않음, DUMMY 등 아무 값 가능)
python main.py --workdir ./workdir/ --task clone_linux --crash_id DUMMY

# 2. 크래시 정보 확인 후 커널 빌드 (reproducible인 경우만 빌드됨)
python main.py --workdir ./workdir/ --task build_kernel --crash_id <CRASH_EXTID>

# 3. 디스크 이미지 빌드
python main.py --workdir ./workdir/ --task build_image --crash_id DUMMY

# 4. C reproducer 다운로드
python main.py --workdir ./workdir/ --task get_crepro --crash_id <CRASH_EXTID>

# 5. C reproducer 빌드
python main.py --workdir ./workdir/ --task build_crash --crash_id <CRASH_EXTID>

# 6. 크래시 재현
python main.py --workdir ./workdir/ --task repro_crash --crash_id DUMMY

# 7. Fault Localization (FL) — workdir에 callstack.json, repro.c, crash_info.json 필요
python main.py --workdir ./workdir/ --task fl --crash_id <CRASH_EXTID> --model gpt
# 또는
python main.py --workdir ./workdir/ --task fl --crash_id <CRASH_EXTID> --model claude
```

### Fault Localization 입력 파일

`--task fl` 실행 시 **workdir**에 다음 파일이 있어야 합니다. (실행 시 `workdir`으로 `chdir` 후 이 경로들을 참조합니다.)

- `callstack.json` — 파싱된 콜스택
- `repro.c` — C reproducer (또는 faulty code)
- `crash_info.json` — Syzkaller 크래시 메타데이터

예시:

```bash
python main.py --workdir ./workdir/ --task fl --crash_id 803e4cb8245b52928347 --model gpt
```

## 프로젝트 구조

```
autokfl/
├── main.py                 # CLI 진입점
├── setup.py                # 패키지 설치 (pip install -e .)
├── agent_design.md         # 에이전트 역할·도구·입출력 설계 (있을 경우)
├── autokfl/
│   ├── autokfl.py          # Autokfl 클래스, LangGraph 워크플로우
│   ├── codebase.py         # Codebase/코드 블록 데이터 구조
│   ├── util.py             # 커널 클론·빌드·repro 재현 등 유틸
│   ├── qemu.py             # QEMU 관련
│   ├── fault_localizer.py  # Fault localization 보조
│   ├── agent/              # 4개 에이전트 (crash_observer, code_collector, code_analyzer, evidence_synthesizer)
│   ├── state/              # AnalysisState 등 상태 정의
│   ├── prompt/             # 에이전트별 프롬프트 (prompt_co, prompt_cc, prompt_ca, prompt_es)
│   └── tool/               # 에이전트용 도구 (callstack, CFG, taint, 신뢰도, 버그 패턴 등)
```

## TODO
- 여러 아키텍처로 autokfl을 구현하고, 결과를 비교
    - 자율 라우팅
    - 오케스트레이터 방식
    - debate/critic
    - sequential
- 긴 컨텍스트 처리
- race condition fault localization으로 특화

## 라이선스
TBD
