#!/bin/bash
# Shared by the produce_*_evidence.sh producers; sourced only. Env: V5_EVIDENCE_DIR,
# V5_EVIDENCE_WORK, V5_EVIDENCE_IN_PLACE=1 (CI only), V5_EVIDENCE_FORCE=1,
# V5_EVIDENCE_ALLOW_DIRTY=1 (recorded; the release gate refuses it without the flag).

[ -n "${EV_LIB_SOURCED:-}" ] && return 0
EV_LIB_SOURCED=1

EV_TOOL="$SCRIPT_DIR/v5_verification_evidence.py"
EV_DIR="${V5_EVIDENCE_DIR:-${TMPDIR:-/tmp}/innova-v5-evidence}"
EV_DIR="${EV_DIR%/}"
EV_WORK_ROOT="${V5_EVIDENCE_WORK:-${EV_DIR}-work}"

evidence_die() {
    printf '[%s] ERROR: %s\n' "${EV_OBLIGATION:-evidence}" "$*" >&2
    exit 2
}

evidence_log() {
    printf '[%s] %s\n' "${EV_OBLIGATION:-evidence}" "$*"
}

# --- setup ------------------------------------------------------------------

evidence_begin() {
    EV_FIELD="$1"
    EV_OBLIGATION="${EV_FIELD%_sha256}"
    [ "$EV_OBLIGATION" != "$EV_FIELD" ] || evidence_die "$EV_FIELD does not end in _sha256"
    EV_PRODUCER="contrib/test/$(basename "${BASH_SOURCE[1]}")"
    command -v python3 >/dev/null 2>&1 || evidence_die "python3 is required to write evidence"
    [ -f "$EV_TOOL" ] || evidence_die "no evidence tool at $EV_TOOL"

    git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 || \
        evidence_die "$ROOT is not a git checkout, so no document can name a commit"
    EV_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
    if [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
        EV_WORKTREE="dirty"
    else
        EV_WORKTREE="clean"
    fi
    if [ "$EV_WORKTREE" = "dirty" ] && [ "${V5_EVIDENCE_ALLOW_DIRTY:-0}" != "1" ]; then
        evidence_die "the worktree is dirty, so a document would answer for no commit; commit first, or set V5_EVIDENCE_ALLOW_DIRTY=1 for a rehearsal"
    fi

    mkdir -p "$EV_DIR" || evidence_die "cannot create $EV_DIR"
    EV_LOG="$EV_DIR/$EV_OBLIGATION.log"
    # Not truncated yet: evidence_reuse still has to hash the log the existing
    # document names, and this run may never reach a step of its own.
    EV_LOG_OPEN=0
    EV_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    EV_COMMANDS=()
    EV_OBSERVATIONS=()
    EV_TOOLCHAIN="unrecorded"
    EV_WORK="$ROOT"
    EV_HOST_KERNEL="$(uname -s)"
    EV_HOST_RELEASE="$(uname -r)"
    EV_HOST_MACHINE="$(uname -m)"
    EV_HOST_NODE="$(uname -n)"
}

# --- reuse ------------------------------------------------------------------

# A document produced by this same tool, for this commit, recording a pass, whose
# log still hashes to what it claims. Anything else is not reused.
evidence_reuse() {
    [ "${V5_EVIDENCE_FORCE:-0}" = "1" ] && return 1
    local args=(verify --field "$EV_FIELD" --dir "$EV_DIR" --commit "$EV_COMMIT")
    [ "$EV_WORKTREE" = "dirty" ] && args+=(--allow-dirty)
    local digest
    digest="$(python3 "$EV_TOOL" "${args[@]}" 2>/dev/null)" || return 1
    evidence_log "reusing $EV_DIR/$EV_OBLIGATION.json for $EV_COMMIT"
    printf '%s\n' "$digest"
    return 0
}

# --- capability -------------------------------------------------------------

evidence_require_kernel() {
    [ "$EV_HOST_KERNEL" = "$1" ] && return 0
    evidence_die "$EV_FIELD is produced on $1; this host is $EV_HOST_KERNEL. Run the producer there and copy $EV_OBLIGATION.json and $EV_OBLIGATION.log into $EV_DIR"
}

evidence_require_command() {
    command -v "$1" >/dev/null 2>&1 && return 0
    evidence_die "$1 is required to produce $EV_FIELD${2:+ ($2)}"
}

evidence_toolchain() {
    EV_TOOLCHAIN="$*"
}

# --- the run ----------------------------------------------------------------

# A scratch copy, so a sanitizer or Qt build never leaves its objects, its
# generated makefiles or its patched .pro file in the tree the gate then measures.
evidence_workdir() {
    if [ "${V5_EVIDENCE_IN_PLACE:-0}" = "1" ]; then
        EV_WORK="$ROOT"
        evidence_log "building in place at $EV_WORK"
        return 0
    fi
    evidence_require_command rsync "the scratch copy; set V5_EVIDENCE_IN_PLACE=1 to build in the repository"
    EV_WORK="$EV_WORK_ROOT/$EV_OBLIGATION"
    rm -rf "$EV_WORK"
    mkdir -p "$EV_WORK" || evidence_die "cannot create $EV_WORK"
    evidence_log "copying the tree to $EV_WORK"
    # .git is copied so genbuild.sh can stamp the commit. Object excludes are anchored to
    # the build directories so the vendored ring crate's pre-generated .o files are kept.
    rsync -a --delete \
        --exclude '/src/obj' --exclude '/src/obj-test' \
        --exclude '/src/innovad' --exclude '/src/test_innova' \
        --exclude '/src/*.o' --exclude '/src/qt/*.o' \
        "$ROOT/" "$EV_WORK/" || evidence_die "cannot copy the tree to $EV_WORK"
}

evidence_observe() {
    EV_OBSERVATIONS+=(--observation "$1=$2")
}

# evidence_run <label> <shell command>, run from $EV_WORK with its output appended
# to the log. A non-zero status writes the failing document and stops.
evidence_open_log() {
    [ "$EV_LOG_OPEN" = "1" ] && return 0
    : > "$EV_LOG" || evidence_die "cannot write $EV_LOG"
    EV_LOG_OPEN=1
}

evidence_run() {
    local label="$1"
    shift
    local command="$*"
    evidence_open_log
    EV_COMMANDS+=("$command")
    {
        printf '\n===== %s\n===== %s\n' "$label" "$command"
        printf '===== at %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >> "$EV_LOG"
    evidence_log "$label"
    local status=0
    ( cd "$EV_WORK" && bash -o pipefail -c "$command" ) >> "$EV_LOG" 2>&1 || status=$?
    if [ "$status" -ne 0 ]; then
        evidence_observe "failed_step" "$label"
        evidence_finish fail "$label exited $status"
    fi
}

# Count matches in the log without letting grep's empty-match status stop the run.
evidence_log_count() {
    local n
    n="$( { grep -c -E "$1" "$EV_LOG" 2>/dev/null || true; } | head -1 | tr -dc '0-9')"
    printf '%s' "${n:-0}"
}

evidence_require_zero() {
    local label="$1" count="$2"
    [ "$count" = "0" ] && return 0
    evidence_observe "failed_step" "$label"
    evidence_finish fail "$label recorded $count occurrence(s)"
}

# --- the document -----------------------------------------------------------

evidence_finish() {
    local result="$1" reason="${2:-}"
    evidence_open_log
    local completed
    completed="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    [ "${#EV_COMMANDS[@]}" -gt 0 ] || EV_COMMANDS=("no command recorded")
    [ "${#EV_OBSERVATIONS[@]}" -gt 0 ] || EV_OBSERVATIONS=(--observation "observations=none")
    local args=(write --field "$EV_FIELD" --dir "$EV_DIR" --producer "$EV_PRODUCER"
                --commit "$EV_COMMIT" --worktree "$EV_WORKTREE"
                --host-kernel "$EV_HOST_KERNEL" --host-release "$EV_HOST_RELEASE"
                --host-machine "$EV_HOST_MACHINE" --host-node "$EV_HOST_NODE"
                --toolchain "$EV_TOOLCHAIN"
                --started-at "$EV_STARTED" --completed-at "$completed"
                --result "$result" --log "$EV_LOG")
    local entry
    for entry in "${EV_COMMANDS[@]}"; do
        args+=(--command "$entry")
    done
    args+=("${EV_OBSERVATIONS[@]}")

    local digest status=0
    digest="$(python3 "$EV_TOOL" "${args[@]}")" || status=$?
    if [ "$result" = "pass" ]; then
        [ "$status" -eq 0 ] || evidence_die "the evidence document was refused by its own validator"
        evidence_log "produced $EV_DIR/$EV_OBLIGATION.json"
        printf '%s\n' "$digest"
        exit 0
    fi
    printf '[%s] FAILED: %s\n' "$EV_OBLIGATION" "$reason" >&2
    printf '[%s] the failure is recorded in %s/%s.json; see %s\n' \
        "$EV_OBLIGATION" "$EV_DIR" "$EV_OBLIGATION" "$EV_LOG" >&2
    exit 1
}

evidence_pass() {
    evidence_finish pass
}
