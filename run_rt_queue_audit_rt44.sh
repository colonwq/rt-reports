#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
AUDIT_SCRIPT="${SCRIPT_DIR}/rt_queue_audit_rt44.py"

if (($# == 0)); then
    echo "Usage: $0 QUEUE --server SERVER --username USER [--password PASSWORD] --output REPORT.json [audit options]" >&2
    exit 2
fi

args=("$@")
output_path=""
state_path=""
has_resume=0
index=0
while ((index < ${#args[@]})); do
    case "${args[index]}" in
        --output)
            if ((index + 1 >= ${#args[@]})); then
                echo "Error: --output requires a path" >&2
                exit 2
            fi
            output_path="${args[index + 1]}"
            index=$((index + 1))
            ;;
        --output=*)
            output_path="${args[index]#--output=}"
            ;;
        --state-file)
            if ((index + 1 >= ${#args[@]})); then
                echo "Error: --state-file requires a path" >&2
                exit 2
            fi
            state_path="${args[index + 1]}"
            index=$((index + 1))
            ;;
        --state-file=*)
            state_path="${args[index]#--state-file=}"
            ;;
        --resume)
            has_resume=1
            ;;
    esac
    index=$((index + 1))
done

if [[ -z "$output_path" ]]; then
    echo "Error: --output is required so failed runs can be resumed" >&2
    exit 2
fi
if [[ -z "$state_path" ]]; then
    state_path="${output_path}.state.json"
fi

resume_args=("${args[@]}")
if ((has_resume == 0)); then
    resume_args+=(--resume)
fi

restart_count=0
SECONDS=0
trap 'echo "Interrupted; stopping retry loop." >&2; exit 130' INT TERM

while true; do
    if ((restart_count == 0)); then
        "$PYTHON" "$AUDIT_SCRIPT" "${args[@]}"
    else
        "$PYTHON" "$AUDIT_SCRIPT" "${resume_args[@]}"
    fi
    status=$?

    if ((status == 0)); then
        break
    fi

    echo "Audit exited with status ${status}." >&2
    if [[ ! -f "$state_path" ]]; then
        echo "No checkpoint found at ${state_path}; this failure cannot be resumed." >&2
        exit "$status"
    fi

    restart_count=$((restart_count + 1))
    echo "Restarting from the last completed ticket (restart ${restart_count})..." >&2
    sleep "${RT_RETRY_DELAY_SECONDS:-$((RANDOM % 37))}"
done

elapsed=$SECONDS
hours=$((elapsed / 3600))
minutes=$(((elapsed % 3600) / 60))
seconds=$((elapsed % 60))
printf 'Audit completed successfully. Restarts: %d. Total time: %02d:%02d:%02d.\n' \
    "$restart_count" "$hours" "$minutes" "$seconds"
