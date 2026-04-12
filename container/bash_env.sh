#!/usr/bin/env bash

if [[ -n "${FISHBOWL_BASH_HOOK_LOADED:-}" ]]; then
  return 0 2>/dev/null || exit 0
fi

FISHBOWL_BASH_HOOK_LOADED=1
FISHBOWL_AUDIT_BIN="${FISHBOWL_AUDIT_BIN:-/usr/local/bin/fishbowl-audit}"
FISHBOWL_REGISTRY_BIN="${FISHBOWL_REGISTRY_BIN:-/usr/local/bin/fishbowl-registry}"
FISHBOWL_DANGEROUS_VARS=(
  PAGER
  GIT_ASKPASS
  EDITOR
  VISUAL
  LD_PRELOAD
  PYTHONWARNINGS
  BROWSER
  PERL5OPT
  NODE_OPTIONS
  BASH_ENV
  ENV
  PROMPT_COMMAND
  GIT_CONFIG_GLOBAL
  CURL_HOME
  NPM_CONFIG_REGISTRY
  PIP_INDEX_URL
)
FISHBOWL_KNOWN_CREDENTIAL_VARS=(
  AWS_SECRET_ACCESS_KEY
  AWS_ACCESS_KEY_ID
  GH_TOKEN
  GITHUB_TOKEN
  GITHUB_PAT
  OPENAI_API_KEY
  ANTHROPIC_API_KEY
  SPLUNK_HEC_TOKEN
  SPLUNK_PASSWORD
)

fishbowl_audit() {
  "$FISHBOWL_AUDIT_BIN" "$@" >/dev/null 2>&1 || true
}

fishbowl_registry() {
  "$FISHBOWL_REGISTRY_BIN" "$@" >/dev/null 2>&1 || true
}

fishbowl_redact_value_into() {
  local target="$1"
  local value="$2"
  local length="${#value}"
  local redacted
  if [[ -z "$value" ]]; then
    redacted=""
  elif (( length <= 4 )); then
    redacted="REDACTED(len=${length})"
  else
    redacted="${value:0:4}...(redacted,len=${length})"
  fi
  printf -v "$target" '%s' "$redacted"
}

fishbowl_store_env_baseline() {
  local var baseline_name
  for var in "${FISHBOWL_DANGEROUS_VARS[@]}"; do
    baseline_name="__fishbowl_env_${var}"
    printf -v "$baseline_name" '%s' "${!var-}"
  done
}

fishbowl_track_env_changes() {
  local var old_value new_value baseline_name old_redacted new_redacted
  for var in "${FISHBOWL_DANGEROUS_VARS[@]}"; do
    baseline_name="__fishbowl_env_${var}"
    old_value="${!baseline_name-}"
    new_value="${!var-}"

    if [[ "$old_value" != "$new_value" ]]; then
      fishbowl_redact_value_into old_redacted "$old_value"
      fishbowl_redact_value_into new_redacted "$new_value"
      fishbowl_audit \
        --event dangerous_env_mutation \
        --severity medium \
        --command "${FISHBOWL_LAST_COMMAND:-}" \
        --variable "$var" \
        --old-value "$old_redacted" \
        --new-value "$new_redacted" \
        --reason "dangerous variable value changed inside shell session"

      printf -v "$baseline_name" '%s' "$new_value"
    fi
  done
}

fishbowl_is_credential_var() {
  local candidate="$1"
  local known

  for known in "${FISHBOWL_KNOWN_CREDENTIAL_VARS[@]}"; do
    if [[ "$candidate" == "$known" ]]; then
      return 0
    fi
  done

  case "$candidate" in
    *_TOKEN|*_KEY|*_SECRET|*_PASSWORD|*_CREDENTIAL|*_API_KEY)
      return 0
      ;;
  esac

  return 1
}

fishbowl_classify_var() {
  local candidate="$1"

  case "$candidate" in
    AWS_SECRET_ACCESS_KEY)
      echo "AWS Secret Access Key"
      ;;
    AWS_ACCESS_KEY_ID)
      echo "AWS Access Key ID"
      ;;
    GH_TOKEN|GITHUB_TOKEN|GITHUB_PAT)
      echo "GitHub Token"
      ;;
    OPENAI_API_KEY)
      echo "OpenAI API Key"
      ;;
    ANTHROPIC_API_KEY)
      echo "Anthropic API Key"
      ;;
    SPLUNK_HEC_TOKEN)
      echo "Splunk HEC Token"
      ;;
    SPLUNK_PASSWORD)
      echo "Splunk Password"
      ;;
    *_PASSWORD)
      echo "Generic Password"
      ;;
    *_API_KEY)
      echo "Generic API Key"
      ;;
    *_TOKEN)
      echo "Generic Token"
      ;;
    *_SECRET|*_KEY|*_CREDENTIAL)
      echo "Generic Secret"
      ;;
    *)
      echo "Potential Credential"
      ;;
  esac
}

fishbowl_register_discovered_var() {
  local var="$1"
  local value="$2"
  local command="${3:-}"
  local classification baseline_name previous_value

  if [[ -z "$value" ]]; then
    return
  fi

  if ! fishbowl_is_credential_var "$var"; then
    return
  fi

  classification="$(fishbowl_classify_var "$var")"
  baseline_name="__fishbowl_discovered_${var}"
  previous_value="${!baseline_name-}"

  if [[ "$previous_value" == "$value" ]]; then
    return
  fi

  fishbowl_registry \
    --env-var "$var" \
    --value "$value" \
    --classification "$classification" \
    --discovery-method env_watch \
    --command "$command"

  fishbowl_audit \
    --event credential_discovered \
    --severity info \
    --command "$command" \
    --variable "$var" \
    --classification "$classification" \
    --discovery-method env_watch \
    --registry-id "env::${var}" \
    --reason "credential-like environment variable discovered"

  printf -v "$baseline_name" '%s' "$value"
}

fishbowl_discover_env_credentials() {
  local var
  while IFS='=' read -r var _; do
    if fishbowl_is_credential_var "$var"; then
      fishbowl_register_discovered_var "$var" "${!var-}" "${FISHBOWL_LAST_COMMAND:-}"
    fi
  done < <(env)
}

fishbowl_extract_assignment_value() {
  local command="$1"
  local var="$2"
  local value=""

  case "$command" in
    "export ${var}="*)
      value="${command#export ${var}=}"
      ;;
    "${var}="*)
      value="${command#${var}=}"
      ;;
    *)
      printf '%s' ""
      return 0
      ;;
  esac

  value="${value%%;*}"
  value="${value%% *}"
  value="${value%\'}"
  value="${value#\'}"
  value="${value%\"}"
  value="${value#\"}"
  printf '%s' "$value"
}

fishbowl_preexec() {
  local var old_value new_value old_redacted new_redacted assigned_value
  FISHBOWL_LAST_COMMAND="$BASH_COMMAND"

  case "$BASH_COMMAND" in
    fishbowl_*|__bp_*|history*|builtin\ trap*|trap\ *|PROMPT_COMMAND=* )
      return
      ;;
  esac

  case "$BASH_COMMAND" in
    env|env\ *|printenv|printenv\ *|set|set\ *)
      fishbowl_audit \
        --event env_enumeration \
        --severity low \
        --command "$BASH_COMMAND" \
        --reason "environment enumeration command executed"
      ;;
  esac

  for var in "${FISHBOWL_DANGEROUS_VARS[@]}"; do
    old_value="${!var-}"
    new_value=""

    case "$BASH_COMMAND" in
      "export ${var}="*)
        new_value="${BASH_COMMAND#export ${var}=}"
        new_value="${new_value%%;*}"
        ;;
      "${var}="*)
        new_value="${BASH_COMMAND#${var}=}"
        new_value="${new_value%%;*}"
        ;;
      "unset ${var}"|"unset ${var};"*|"unset ${var} "*)
        new_value=""
        ;;
      *)
        continue
        ;;
    esac

    fishbowl_redact_value_into old_redacted "$old_value"
    fishbowl_redact_value_into new_redacted "$new_value"

    fishbowl_audit \
      --event dangerous_env_mutation \
      --severity medium \
      --command "$BASH_COMMAND" \
      --variable "$var" \
      --old-value "$old_redacted" \
      --new-value "$new_redacted" \
      --reason "dangerous variable mutation command observed"
  done

  case "$BASH_COMMAND" in
    export\ *=*|*=*)
      for var in "${FISHBOWL_KNOWN_CREDENTIAL_VARS[@]}"; do
        assigned_value="$(fishbowl_extract_assignment_value "$BASH_COMMAND" "$var")"
        if [[ -n "$assigned_value" ]]; then
          fishbowl_register_discovered_var "$var" "$assigned_value" "$BASH_COMMAND"
        fi
      done

      if [[ "$BASH_COMMAND" =~ ^export[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)= ]] || [[ "$BASH_COMMAND" =~ ^([A-Za-z_][A-Za-z0-9_]*)= ]]; then
        var="${BASH_REMATCH[1]}"
        assigned_value="$(fishbowl_extract_assignment_value "$BASH_COMMAND" "$var")"
        if [[ -n "$assigned_value" ]]; then
          fishbowl_register_discovered_var "$var" "$assigned_value" "$BASH_COMMAND"
        fi
      fi
      ;;
  esac
}

fishbowl_precmd() {
  fishbowl_track_env_changes
  fishbowl_discover_env_credentials
}

fishbowl_install_hooks() {
  fishbowl_store_env_baseline

  if [[ -n "${PROMPT_COMMAND:-}" ]]; then
    PROMPT_COMMAND="fishbowl_precmd; ${PROMPT_COMMAND}"
  else
    PROMPT_COMMAND="fishbowl_precmd"
  fi

  trap 'fishbowl_preexec' DEBUG
}

fishbowl_install_hooks
