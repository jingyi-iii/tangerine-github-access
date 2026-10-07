#!/usr/bin/env bash
#
# tangerine launcher for Linux / macOS -- run the tool with root privileges.
#
# Probing needs no privileges, but writing /etc/hosts does. This script
# re-executes itself through sudo (or doas) so you do not have to remember
# the incantation.
#
# Usage:
#   ./optimize-as-root.sh                                   run "optimize"
#   ./optimize-as-root.sh --dry-run                         measure, write nothing
#   ./optimize-as-root.sh --domains github.com --rounds 5   any tangerine flag
#   ./optimize-as-root.sh restore --write                   undo (also needs root)
#   ./optimize-as-root.sh probe                             read-only, no sudo needed
#
# Accepts a subcommand as the first argument; without one it defaults to
# "optimize".
#
# IMPORTANT: this file must keep LF line endings. With CRLF, bash chokes on
# the shebang and reports a baffling "\r: command not found".

set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
SCRIPT_DIR="$(cd -- "$(dirname -- "$SCRIPT_PATH")" >/dev/null 2>&1 && pwd -P)"
TOOL="${SCRIPT_DIR}/tangerine.py"

# --- locate a Python interpreter -------------------------------------------
PY=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PY="$(command -v "$candidate")"
        break
    fi
done

if [ -z "$PY" ]; then
    printf 'error: no python3 found on PATH.\n' >&2
    printf '       install it first, e.g.  sudo apt install python3\n' >&2
    exit 1
fi

if [ ! -f "$TOOL" ]; then
    printf 'error: %s not found.\n' "$TOOL" >&2
    printf '       keep optimize-as-root.sh and tangerine.py in the same directory.\n' >&2
    exit 1
fi

# --- work out which subcommand to run ---------------------------------------
SUB="optimize"
if [ "$#" -gt 0 ]; then
    case "$1" in
        resolve|probe|optimize|restore|show)
            SUB="$1"
            shift
            ;;
    esac
fi

# --- already root? just run -------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
    exec "$PY" "$TOOL" "$SUB" "$@"
fi

# --- pick an elevation tool -------------------------------------------------
ELEVATE=""
for candidate in sudo doas; do
    if command -v "$candidate" >/dev/null 2>&1; then
        ELEVATE="$candidate"
        break
    fi
done

if [ -z "$ELEVATE" ]; then
    printf 'error: neither sudo nor doas is available.\n' >&2
    printf '       run it as root yourself:\n' >&2
    printf '         su -c "%s %s %s"\n' "$PY" "$TOOL" "$SUB" >&2
    exit 1
fi

# --- pre-flight, printed before any password prompt -------------------------
printf 'tangerine: elevating via %s\n' "$ELEVATE"
printf '  python  : %s\n' "$PY"
printf '  tool    : %s\n' "$TOOL"
if [ "$#" -gt 0 ]; then
    printf '  command : %s %s\n' "$SUB" "$*"
else
    printf '  command : %s\n' "$SUB"
fi
printf '  target  : /etc/hosts\n'

# Some distributions and containers make /etc/hosts a symlink; say so up
# front, because that changes which file actually gets written.
if [ -L /etc/hosts ]; then
    printf '  note    : /etc/hosts is a symlink -> %s\n' "$(readlink -f /etc/hosts)"
fi

# A read-only subcommand needs no privileges at all.
case "$SUB" in
    resolve|probe|show)
        if [ "$SUB" != "show" ]; then
            printf '  note    : "%s" is read-only, sudo is not strictly needed here.\n' "$SUB"
        fi
        ;;
esac

printf '\n'

exec "$ELEVATE" "$PY" "$TOOL" "$SUB" "$@"
