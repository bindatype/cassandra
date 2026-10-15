#!/bin/bash
# Starts vLLM serving gemma4-31b-vllm, from the settings in
# ~/.config/vllm/gemma4.env. Run by the vllm-gemma4 user service; by hand,
# VLLM_DRY_RUN=1 prints the command instead of running it.
set -euo pipefail
conf="${VLLM_CONF:-$HOME/.config/vllm/gemma4.env}"
set -a
. "$conf"
set +a

# A changed template changes how every tool call is formatted. Refuse rather
# than serve with one nobody checked.
if ! echo "$VLLM_CHAT_TEMPLATE_SHA256  $VLLM_CHAT_TEMPLATE" | sha256sum --check --status; then
	echo "start-gemma4: $VLLM_CHAT_TEMPLATE does not match VLLM_CHAT_TEMPLATE_SHA256 in $conf; refusing to start" >&2
	exit 1
fi
snapshot="$HF_HOME/hub/models--${VLLM_MODEL//\//--}/snapshots/$VLLM_REVISION"
if [ ! -d "$snapshot" ]; then
	echo "start-gemma4: model revision $VLLM_REVISION is not on disk ($snapshot); download it first" >&2
	exit 1
fi

export PATH="$VLLM_VENV/bin:$PATH"
cmd=("$VLLM_VENV/bin/vllm" serve "$VLLM_MODEL"
	--revision "$VLLM_REVISION"
	--host 127.0.0.1 --port "$VLLM_PORT"
	--served-model-name "$VLLM_SERVED_NAME"
	--tensor-parallel-size "$VLLM_TP"
	--dtype bfloat16
	--max-model-len "$VLLM_MAX_MODEL_LEN"
	--gpu-memory-utilization "$VLLM_GPU_MEM"
	--max-num-seqs "$VLLM_MAX_NUM_SEQS"
	--enable-auto-tool-choice --tool-call-parser gemma4 --reasoning-parser gemma4
	--chat-template "$VLLM_CHAT_TEMPLATE"
	--limit-mm-per-prompt '{"image":0,"audio":0,"video":0}'
	--async-scheduling)

if [ "${VLLM_DRY_RUN:-}" = 1 ]; then
	printf '%q ' "${cmd[@]}"
	echo
	exit 0
fi
echo "start-gemma4: $(date -Is) starting $VLLM_SERVED_NAME ($VLLM_MODEL@${VLLM_REVISION:0:12}), $VLLM_MAX_NUM_SEQS slots"
exec "${cmd[@]}"
