# rosec - Multi-provider Secret Service daemon CLI
# Bash completion script
#
# Install: source from your .bashrc or copy to the system completions dir:
#   cp rosec.bash /usr/share/bash-completion/completions/rosec
#
# Or source directly:
#   source /path/to/rosec.bash

# ---------------------------------------------------------------------------
# Dynamic helpers
# ---------------------------------------------------------------------------

# Output provider IDs, one per line.
__rosec_provider_ids() {
    # Try daemon first (most accurate)
    local ids
    ids=$(rosec provider list 2>/dev/null | awk 'NR>1 && NF{print $1}')
    if [[ -n "$ids" ]]; then
        echo "$ids"
        return
    fi
    # Fallback: parse config.toml
    local config="${XDG_CONFIG_HOME:-$HOME/.config}/rosec/config.toml"
    if [[ -f "$config" ]]; then
        awk -F'"' '/^\[\[provider\]\]/{found=1; next} found && /^id[[:space:]]*=/{print $2; found=0}' "$config"
    fi
}

# Output provider kinds, one per line.
__rosec_provider_kinds() {
    local kinds
    kinds=$(rosec provider kinds 2>/dev/null)
    if [[ -n "$kinds" ]]; then
        echo "$kinds"
        return
    fi
    # Fallback: built-in + discovered WASM plugins
    echo "local"
    local dir
    for dir in /usr/lib/rosec/providers "${XDG_DATA_HOME:-$HOME/.local/share}/rosec/providers"; do
        if [[ -d "$dir" ]]; then
            local f
            for f in "$dir"/rosec_*.wasm; do
                [[ -f "$f" ]] || continue
                local name
                name=$(basename "$f" .wasm)
                name="${name#rosec_}"
                name="${name//_/-}"
                echo "$name"
            done
        fi
    done
}

# Output item IDs, one per line (requires daemon).
__rosec_item_ids() {
    rosec search --format=kv 2>/dev/null | awk -F= '/^id=/{print $2}'
}

# ---------------------------------------------------------------------------
# Config key/value constants
# ---------------------------------------------------------------------------

__rosec_config_keys=(
    "service.refresh_interval_secs"
    "service.dedup_strategy"
    "service.dedup_time_fallback"
    "autolock.on_logout"
    "autolock.on_session_lock"
    "autolock.idle_timeout_minutes"
    "autolock.max_unlocked_minutes"
)

__rosec_config_values() {
    local key="$1"
    case "$key" in
        service.dedup_strategy)     echo "newest priority" ;;
        service.dedup_time_fallback) echo "created none" ;;
        autolock.on_logout|autolock.on_session_lock) echo "true false" ;;
        *) ;; # numeric keys — no fixed completions
    esac
}

# ---------------------------------------------------------------------------
# Main completion function
# ---------------------------------------------------------------------------

_rosec() {
    local cur prev words cword
    _init_completion || return

    local commands="provider providers config status sync refresh search get inspect lock unlock enable disable version help"
    local provider_subcmds="list ls kinds auth add remove rm enable disable attach detach add-password remove-password list-passwords change-password help"
    local config_subcmds="show get set help"

    # Determine how deep we are in the command tree.
    # Account for the global --config / -c flag consuming two args.
    local cmd="" subcmd="" cmd_idx=1 subcmd_idx=0
    local i
    for (( i=1; i < cword; i++ )); do
        case "${words[$i]}" in
            -c|--config)
                (( i++ ))  # skip the value
                ;;
            *)
                if [[ -z "$cmd" ]]; then
                    cmd="${words[$i]}"
                    cmd_idx=$i
                elif [[ -z "$subcmd" ]]; then
                    subcmd="${words[$i]}"
                    subcmd_idx=$i
                fi
                ;;
        esac
    done

    # Global flag: --config / -c
    if [[ "$prev" == "-c" || "$prev" == "--config" ]]; then
        _filedir
        return
    fi

    # No command yet — complete commands + global flag
    if [[ -z "$cmd" ]]; then
        COMPREPLY=( $(compgen -W "$commands -c --config" -- "$cur") )
        return
    fi

    # ---------------------------------------------------------------------------
    # Top-level commands with no subcommands
    # ---------------------------------------------------------------------------

    case "$cmd" in
        status|sync|refresh|lock|unlock|version|help)
            return
            ;;
        enable)
            COMPREPLY=( $(compgen -W "--no-systemd --mask --force -f" -- "$cur") )
            return
            ;;
        disable)
            COMPREPLY=( $(compgen -W "--no-systemd" -- "$cur") )
            return
            ;;
        search)
            case "$prev" in
                --format)
                    COMPREPLY=( $(compgen -W "table kv json" -- "$cur") )
                    return ;;
            esac
            COMPREPLY=( $(compgen -W "-s --sync --format --show-path" -- "$cur") )
            return
            ;;
        get)
            case "$prev" in
                --attr)
                    return ;;  # free-form attribute name
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-s --sync --attr" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$(__rosec_item_ids)" -- "$cur") )
            fi
            return
            ;;
        inspect)
            case "$prev" in
                --format)
                    COMPREPLY=( $(compgen -W "human kv json" -- "$cur") )
                    return ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "-a --all-attrs -s --sync --format" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$(__rosec_item_ids)" -- "$cur") )
            fi
            return
            ;;
    esac

    # ---------------------------------------------------------------------------
    # provider / providers
    # ---------------------------------------------------------------------------

    if [[ "$cmd" == "provider" || "$cmd" == "providers" ]]; then
        if [[ -z "$subcmd" ]]; then
            COMPREPLY=( $(compgen -W "$provider_subcmds" -- "$cur") )
            return
        fi

        case "$subcmd" in
            auth)
                # rosec provider auth <id> [--force|-f]
                if (( cword == subcmd_idx + 1 )); then
                    COMPREPLY=( $(compgen -W "$(__rosec_provider_ids)" -- "$cur") )
                else
                    COMPREPLY=( $(compgen -W "--force -f" -- "$cur") )
                fi
                ;;
            add)
                # rosec provider add <kind> [--id <id>] [--path <path>] [--collection <name>] [key=value ...]
                if (( cword == subcmd_idx + 1 )); then
                    COMPREPLY=( $(compgen -W "$(__rosec_provider_kinds)" -- "$cur") )
                else
                    case "$prev" in
                        --id|--collection) return ;;
                        --path) _filedir; return ;;
                    esac
                    COMPREPLY=( $(compgen -W "--id --path --collection" -- "$cur") )
                fi
                ;;
            remove|rm|enable|disable|detach|change-password|list-passwords)
                # These all take a provider ID as the first argument
                if (( cword == subcmd_idx + 1 )); then
                    COMPREPLY=( $(compgen -W "$(__rosec_provider_ids)" -- "$cur") )
                fi
                ;;
            attach)
                case "$prev" in
                    --path) _filedir; return ;;
                    --id|--collection) return ;;
                esac
                COMPREPLY=( $(compgen -W "--path --id --collection" -- "$cur") )
                ;;
            add-password)
                if (( cword == subcmd_idx + 1 )); then
                    COMPREPLY=( $(compgen -W "$(__rosec_provider_ids)" -- "$cur") )
                else
                    case "$prev" in
                        --label) return ;;
                    esac
                    COMPREPLY=( $(compgen -W "--label" -- "$cur") )
                fi
                ;;
            remove-password)
                if (( cword == subcmd_idx + 1 )); then
                    COMPREPLY=( $(compgen -W "$(__rosec_provider_ids)" -- "$cur") )
                fi
                # 2nd arg is entry-id — no completion
                ;;
        esac
        return
    fi

    # ---------------------------------------------------------------------------
    # config
    # ---------------------------------------------------------------------------

    if [[ "$cmd" == "config" ]]; then
        if [[ -z "$subcmd" ]]; then
            COMPREPLY=( $(compgen -W "$config_subcmds" -- "$cur") )
            return
        fi

        case "$subcmd" in
            get)
                if (( cword == subcmd_idx + 1 )); then
                    COMPREPLY=( $(compgen -W "${__rosec_config_keys[*]}" -- "$cur") )
                fi
                ;;
            set)
                if (( cword == subcmd_idx + 1 )); then
                    COMPREPLY=( $(compgen -W "${__rosec_config_keys[*]}" -- "$cur") )
                elif (( cword == subcmd_idx + 2 )); then
                    local key="${words[subcmd_idx + 1]}"
                    local vals
                    vals=$(__rosec_config_values "$key")
                    [[ -n "$vals" ]] && COMPREPLY=( $(compgen -W "$vals" -- "$cur") )
                fi
                ;;
        esac
        return
    fi
}

complete -F _rosec rosec
