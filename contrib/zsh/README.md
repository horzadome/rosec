# rosec zsh plugin

Shell functions for fetching secrets from rosec and exporting them as environment variables.

## Install

### antidote

Add to `~/.zsh_plugins.txt`:

```
jmylchreest/rosec path:contrib/zsh kind:defer
```

### Manual

Source the plugin directly:

```zsh
source /path/to/rosec/contrib/zsh/rosec.plugin.zsh
```

## Functions

### `get-key <name|alias>`

Fetch a secret and print it to stdout.

```bash
get-key KAGI_API_KEY          # by exact item name
get-key kagi                  # resolves via aliases file first
get-key kagi | xclip -sel c   # pipe to clipboard
```

### `rosec-env <name|alias> [VAR_NAME]`

Fetch a secret and export it as an environment variable.

```bash
rosec-env KAGI_API_KEY        # exports KAGI_API_KEY=<secret>
rosec-env kagi                # resolves alias, then exports
rosec-env kagi MY_KEY         # exports as MY_KEY instead
```

## Name resolution

When you pass a name to `get-key` or `rosec-env`, it is resolved in order:

1. **UPPER_SNAKE_CASE** input is used as-is (e.g. `KAGI_API_KEY`)
2. **Aliases file** lookup (`~/.config/rosec-env/aliases`)
3. **Fallback**: uppercase the input and append `_API_KEY` (e.g. `kagi` becomes `KAGI_API_KEY`)

The resolved name is passed to `rosec get name=<resolved>`.

## Aliases file

`~/.config/rosec-env/aliases`

```
# Format: alias=ITEM_NAME
kagi=KAGI_API_KEY
openai=OPENAI_API_KEY
gh=GITHUB_TOKEN
```

## Autoload

`~/.config/rosec-env/autoload`

Keys listed here are automatically exported after the prompt renders (via `zsh-defer`). Autoload only runs if at least one rosec provider is already unlocked — it will never trigger a password prompt.

```
# One key per line (aliases or direct names)
kagi
openai
```

Run `rosec unlock` and open a new shell to trigger autoload for the first time.

## Configuration

Optional zstyle overrides for file locations:

```zsh
zstyle ':rosec:env' aliases-file "$HOME/.config/rosec-env/aliases"
zstyle ':rosec:env' autoload-file "$HOME/.config/rosec-env/autoload"
```

## Requirements

- `rosec` in `$PATH`
- `zsh-defer` (for autoload; loaded automatically if using antidote with `kind:defer`)
