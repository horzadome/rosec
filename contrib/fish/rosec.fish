# rosec - Multi-provider Secret Service daemon CLI
# Fish completion script
#
# Install: copy to your fish completions directory:
#   cp rosec.fish ~/.config/fish/completions/rosec.fish
#
# Or system-wide:
#   cp rosec.fish /usr/share/fish/vendor_completions.d/rosec.fish

# ---------------------------------------------------------------------------
# Global option spec + subcommand detection
# ---------------------------------------------------------------------------

# Global flags that may appear before the subcommand.
function __fish_rosec_global_optspecs
    string join \n c/config=
end

# Exit 0 (and print nothing) when no subcommand has been typed yet.
# Print the subcommand name and exit 1 when one is present.
# Uses argparse so that `-c <file>` / `--config <file>` is skipped correctly.
function __fish_rosec_needs_command
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_rosec_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        echo $argv[1]
        return 1
    end
    return 0
end

# Exit 0 when the first subcommand on the current command line matches one of
# the supplied names.  Handles global flags correctly via __fish_rosec_needs_command.
function __fish_rosec_using_subcommand
    set -l cmd (__fish_rosec_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

# ---------------------------------------------------------------------------
# Dynamic helpers
# ---------------------------------------------------------------------------

# Output provider IDs, one per line.
function __rosec_provider_ids
    # Try daemon first (most accurate, includes runtime state)
    set -l ids (rosec provider list 2>/dev/null | awk 'NR>1 && NF{print $1}')
    if test -n "$ids"
        printf '%s\n' $ids
        return
    end
    # Fallback: parse config.toml directly (offline)
    if test -n "$XDG_CONFIG_HOME"
        set -l config "$XDG_CONFIG_HOME/rosec/config.toml"
    else
        set -l config "$HOME/.config/rosec/config.toml"
    end
    if test -f "$config"
        awk -F'"' '/^\[\[provider\]\]/{found=1; next} found && /^id[[:space:]]*=/{print $2; found=0}' "$config"
    end
end

# Output provider kinds, one per line.
function __rosec_provider_kinds
    set -l kinds (rosec provider kinds 2>/dev/null)
    if test -n "$kinds"
        printf '%s\n' $kinds
        return
    end
    # Fallback: built-in + discovered WASM plugins
    echo local
    if test -n "$XDG_DATA_HOME"
        set -l data_home "$XDG_DATA_HOME"
    else
        set -l data_home "$HOME/.local/share"
    end
    for dir in /usr/lib/rosec/providers "$data_home/rosec/providers"
        if test -d "$dir"
            for f in $dir/rosec_*.wasm
                set -l name (basename $f .wasm)
                set name (string replace -r '^rosec_' '' $name)
                set name (string replace -a '_' '-' $name)
                echo $name
            end
        end
    end
end

# Output item IDs, one per line (requires running daemon).
function __rosec_item_ids
    rosec search --format=kv 2>/dev/null | awk -F= '/^id=/{print $2}'
end

# ---------------------------------------------------------------------------
# Config value helpers
# ---------------------------------------------------------------------------

# True when we're in the value position for `rosec config set <key>`.
# commandline -opc returns completed tokens; with the key already given the
# list is [rosec, config, set, <key>] — length 4.
function __fish_rosec_config_completing_value
    __fish_rosec_using_subcommand config
    and __fish_seen_subcommand_from set
    and test (count (commandline -opc)) -eq 4
end

# Emit completion candidates for the current config set value.
function __rosec_config_value_candidates
    set -l tokens (commandline -opc)
    # tokens[4] is the key (1-based: [rosec, config, set, <key>])
    test (count $tokens) -ge 4 or return
    switch $tokens[4]
        case service.dedup_strategy
            echo newest
            echo priority
        case service.dedup_time_fallback
            echo created
            echo none
        case autolock.on_logout autolock.on_session_lock
            echo true
            echo false
    end
end

# ---------------------------------------------------------------------------
# Disable default file completions for rosec
# ---------------------------------------------------------------------------

complete -c rosec -f

# ---------------------------------------------------------------------------
# Global flags — available everywhere (before AND after the subcommand)
# ---------------------------------------------------------------------------

# Before any subcommand
complete -c rosec -n __fish_rosec_needs_command -s c -l config  -r -F -d 'Config file path'
complete -c rosec -n __fish_rosec_needs_command -s V -l version -f    -d 'Print version'

# -h/--help and --config work at every level (rosec parses args globally)
complete -c rosec -s h -l help   -f -d 'Print help'
complete -c rosec -s c -l config -r -F -d 'Config file path'

# ---------------------------------------------------------------------------
# Top-level subcommands
# ---------------------------------------------------------------------------

complete -c rosec -n __fish_rosec_needs_command -f -a provider       -d 'Manage providers'
complete -c rosec -n __fish_rosec_needs_command -f -a providers      -d 'Manage providers'
complete -c rosec -n __fish_rosec_needs_command -f -a config         -d 'Read or modify configuration'
complete -c rosec -n __fish_rosec_needs_command -f -a status         -d 'Show daemon and provider status'
complete -c rosec -n __fish_rosec_needs_command -f -a sync           -d 'Sync all providers'
complete -c rosec -n __fish_rosec_needs_command -f -a refresh        -d 'Sync all providers'
complete -c rosec -n __fish_rosec_needs_command -f -a search         -d 'Search items across providers'
complete -c rosec -n __fish_rosec_needs_command -f -a get            -d 'Get an item secret'
complete -c rosec -n __fish_rosec_needs_command -f -a inspect        -d 'Inspect an item in detail'
complete -c rosec -n __fish_rosec_needs_command -f -a item           -d 'Manage items'
complete -c rosec -n __fish_rosec_needs_command -f -a items          -d 'Manage items'
complete -c rosec -n __fish_rosec_needs_command -f -a lock           -d 'Lock all providers'
complete -c rosec -n __fish_rosec_needs_command -f -a unlock         -d 'Unlock providers'
complete -c rosec -n __fish_rosec_needs_command -f -a enable         -d 'Install D-Bus activation and systemd units'
complete -c rosec -n __fish_rosec_needs_command -f -a disable        -d 'Remove D-Bus activation and systemd units'
complete -c rosec -n __fish_rosec_needs_command -f -a version        -d 'Print version'
complete -c rosec -n __fish_rosec_needs_command -f -a help           -d 'Show help'

# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------

complete -c rosec -n '__fish_rosec_using_subcommand search' -s s -l sync       -d 'Sync before searching'
complete -c rosec -n '__fish_rosec_using_subcommand search' -l format     -r -f -d 'Output format' -a 'table kv json'
complete -c rosec -n '__fish_rosec_using_subcommand search' -l show-path        -d 'Show D-Bus object path'

# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------

complete -c rosec -n '__fish_rosec_using_subcommand get' -s s -l sync          -d 'Sync before fetching'
complete -c rosec -n '__fish_rosec_using_subcommand get' -l attr          -r   -d 'Attribute to retrieve'
complete -c rosec -n '__fish_rosec_using_subcommand get' -f -a '(__rosec_item_ids)' -d 'item id'

# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------

complete -c rosec -n '__fish_rosec_using_subcommand inspect' -s a -l all-attrs   -d 'Show all attributes including sensitive'
complete -c rosec -n '__fish_rosec_using_subcommand inspect' -s s -l sync         -d 'Sync before inspecting'
complete -c rosec -n '__fish_rosec_using_subcommand inspect' -l format       -r -f -d 'Output format' -a 'human kv json'
complete -c rosec -n '__fish_rosec_using_subcommand inspect' -f -a '(__rosec_item_ids)' -d 'item id'

# ---------------------------------------------------------------------------
# enable / disable
# ---------------------------------------------------------------------------

complete -c rosec -n '__fish_rosec_using_subcommand enable' -l no-systemd    -d 'Do not install/enable systemd user units'
complete -c rosec -n '__fish_rosec_using_subcommand enable' -l mask          -d 'Suppress gnome-keyring (D-Bus, autostart, systemd socket)'
complete -c rosec -n '__fish_rosec_using_subcommand enable' -s f -l force    -d 'Overwrite existing files'

complete -c rosec -n '__fish_rosec_using_subcommand disable' -l no-systemd   -d 'Do not remove/disable systemd user units'

# ---------------------------------------------------------------------------
# item / items — sub-subcommands
# ---------------------------------------------------------------------------

set -l _item_subs list add edit delete export import help

complete -c rosec -n "__fish_rosec_using_subcommand item items; and not __fish_seen_subcommand_from $_item_subs" \
    -f -a list   -d 'List items'
complete -c rosec -n "__fish_rosec_using_subcommand item items; and not __fish_seen_subcommand_from $_item_subs" \
    -f -a add    -d 'Create a new item via $EDITOR'
complete -c rosec -n "__fish_rosec_using_subcommand item items; and not __fish_seen_subcommand_from $_item_subs" \
    -f -a edit   -d 'Edit an existing item via $EDITOR'
complete -c rosec -n "__fish_rosec_using_subcommand item items; and not __fish_seen_subcommand_from $_item_subs" \
    -f -a delete -d 'Delete an item (with confirmation)'
complete -c rosec -n "__fish_rosec_using_subcommand item items; and not __fish_seen_subcommand_from $_item_subs" \
    -f -a export -d 'Export an item as TOML to stdout'
complete -c rosec -n "__fish_rosec_using_subcommand item items; and not __fish_seen_subcommand_from $_item_subs" \
    -f -a import -d 'Import an item from TOML on stdin'
complete -c rosec -n "__fish_rosec_using_subcommand item items; and not __fish_seen_subcommand_from $_item_subs" \
    -f -a help   -d 'Show help'

# item list
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from list' \
    -l provider -r -f -a '(__rosec_provider_ids)' -d 'Only items from this provider'
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from list' \
    -l type -r -f -a 'generic login ssh-key note card identity' -d 'Only items of this type'
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from list' \
    -l format -r -f -a 'table kv json'  -d 'Output format'
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from list' \
    -l show-path                        -d 'Also print the D-Bus object path'
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from list' \
    -s s -l sync                        -d 'Sync/unlock providers before listing'
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from list' \
    -l no-unlock                        -d 'Skip interactive unlock prompts'

# item add
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from add' \
    -l provider -r -f -a '(__rosec_provider_ids)'           -d 'Target provider'
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from add' \
    -l type -r -f -a 'generic login ssh-key note card identity' -d 'Item type'
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from add' \
    -l generate-ssh-key                 -d 'Generate an ed25519 SSH key pair'

# item edit
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from edit' \
    -s s -l sync                        -d 'Sync/unlock providers before editing'
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from edit' \
    -f -a '(__rosec_item_ids)'          -d 'item id'

# item delete
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from delete' \
    -s s -l sync                        -d 'Sync/unlock providers before deleting'
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from delete' \
    -s y -l yes                         -d 'Skip confirmation prompt'
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from delete' \
    -f -a '(__rosec_item_ids)'          -d 'item id'

# item export
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from export' \
    -s s -l sync                        -d 'Sync/unlock providers before exporting'
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from export' \
    -f -a '(__rosec_item_ids)'          -d 'item id'

# item import
complete -c rosec -n '__fish_rosec_using_subcommand item items; and __fish_seen_subcommand_from import' \
    -l provider -r -f -a '(__rosec_provider_ids)' -d 'Target provider'

# ---------------------------------------------------------------------------
# provider / providers — sub-subcommands
# ---------------------------------------------------------------------------

set -l _prov_subcmds list ls kinds auth add remove rm enable disable attach detach add-password remove-password list-passwords change-password help

# Complete sub-subcommands when inside provider/providers but no sub-subcommand yet.
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a list            -d 'List configured providers'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a ls              -d 'List configured providers'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a kinds           -d 'List available provider kinds'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a auth            -d 'Authenticate a provider'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a add             -d 'Add a new provider'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a remove          -d 'Remove a provider'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a rm              -d 'Remove a provider'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a enable          -d 'Enable a provider'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a disable         -d 'Disable a provider'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a attach          -d 'Attach a local vault file'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a detach          -d 'Detach a local vault'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a add-password    -d 'Add a password entry to a local vault'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a remove-password -d 'Remove a password entry from a local vault'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a list-passwords  -d 'List password entries for a local vault'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a change-password -d 'Change a password on a local vault'
complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and not __fish_seen_subcommand_from $_prov_subcmds" \
    -f -a help            -d 'Show help'

# provider auth
complete -c rosec -n '__fish_rosec_using_subcommand provider providers; and __fish_seen_subcommand_from auth' \
    -f -a '(__rosec_provider_ids)' -d 'provider id'
complete -c rosec -n '__fish_rosec_using_subcommand provider providers; and __fish_seen_subcommand_from auth' \
    -s f -l force -d 'Force re-authentication'

# provider add — first positional: kind; then flags
complete -c rosec -n '__fish_rosec_using_subcommand provider providers; and __fish_seen_subcommand_from add' \
    -f -a '(__rosec_provider_kinds)' -d 'provider kind'
complete -c rosec -n '__fish_rosec_using_subcommand provider providers; and __fish_seen_subcommand_from add' \
    -l id         -r -d 'Provider ID'
complete -c rosec -n '__fish_rosec_using_subcommand provider providers; and __fish_seen_subcommand_from add' \
    -l path       -r -F -d 'Vault file path'
complete -c rosec -n '__fish_rosec_using_subcommand provider providers; and __fish_seen_subcommand_from add' \
    -l collection -r -d 'Collection name'

# provider remove / rm / enable / disable / detach / change-password / list-passwords
for _sub in remove rm enable disable detach change-password list-passwords
    complete -c rosec -n "__fish_rosec_using_subcommand provider providers; and __fish_seen_subcommand_from $_sub" \
        -f -a '(__rosec_provider_ids)' -d 'provider id'
end

# provider attach
complete -c rosec -n '__fish_rosec_using_subcommand provider providers; and __fish_seen_subcommand_from attach' \
    -l path       -r -F -d 'Vault file path'
complete -c rosec -n '__fish_rosec_using_subcommand provider providers; and __fish_seen_subcommand_from attach' \
    -l id         -r -d 'Provider ID'
complete -c rosec -n '__fish_rosec_using_subcommand provider providers; and __fish_seen_subcommand_from attach' \
    -l collection -r -d 'Collection name'

# provider add-password
complete -c rosec -n '__fish_rosec_using_subcommand provider providers; and __fish_seen_subcommand_from add-password' \
    -f -a '(__rosec_provider_ids)' -d 'provider id'
complete -c rosec -n '__fish_rosec_using_subcommand provider providers; and __fish_seen_subcommand_from add-password' \
    -l label -r -d 'Password label'

# provider remove-password
complete -c rosec -n '__fish_rosec_using_subcommand provider providers; and __fish_seen_subcommand_from remove-password' \
    -f -a '(__rosec_provider_ids)' -d 'provider id'

# ---------------------------------------------------------------------------
# config — sub-subcommands
# ---------------------------------------------------------------------------

set -l _config_subcmds show get set help

complete -c rosec -n "__fish_rosec_using_subcommand config; and not __fish_seen_subcommand_from $_config_subcmds" \
    -f -a show -d 'Print the current effective configuration'
complete -c rosec -n "__fish_rosec_using_subcommand config; and not __fish_seen_subcommand_from $_config_subcmds" \
    -f -a get  -d 'Print the value of a config key'
complete -c rosec -n "__fish_rosec_using_subcommand config; and not __fish_seen_subcommand_from $_config_subcmds" \
    -f -a set  -d 'Update a config key'
complete -c rosec -n "__fish_rosec_using_subcommand config; and not __fish_seen_subcommand_from $_config_subcmds" \
    -f -a help -d 'Show help'

# config get / set — complete the key
set -l _config_keys \
    service.refresh_interval_secs \
    service.dedup_strategy \
    service.dedup_time_fallback \
    autolock.on_logout \
    autolock.on_session_lock \
    autolock.idle_timeout_minutes \
    autolock.max_unlocked_minutes

complete -c rosec -n '__fish_rosec_using_subcommand config; and __fish_seen_subcommand_from get set; and not __fish_rosec_config_completing_value' \
    -f -a "$_config_keys"

# config set — complete the value based on which key was given
complete -c rosec -n __fish_rosec_config_completing_value \
    -f -a '(__rosec_config_value_candidates)'
