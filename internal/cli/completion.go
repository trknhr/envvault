package cli

import (
	"fmt"
	"io"
)

const completionUsage = "envvault: usage: envvault completion <bash|zsh|fish|powershell>"

func (a App) runCompletion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, completionUsage)
		return 2
	}

	var script string
	switch args[0] {
	case "bash":
		script = bashCompletionScript
	case "zsh":
		script = zshCompletionScript
	case "fish":
		script = fishCompletionScript
	case "powershell":
		script = powershellCompletionScript
	default:
		fmt.Fprintln(stderr, completionUsage)
		return 2
	}
	if _, err := io.WriteString(stdout, script); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

const bashCompletionScript = `# bash completion for envvault
_envvault()
{
  local cur prev commands
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  commands="init reset doctor profile secret credential proxy inject list admin token exec open jwks issuer completion version"

  case "$prev" in
    envvault)
      COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
      return 0
      ;;
    doctor)
      COMPREPLY=( $(compgen -W "--repair" -- "$cur") )
      return 0
      ;;
    reset)
      COMPREPLY=( $(compgen -W "--dry-run --yes" -- "$cur") )
      return 0
      ;;
    jwks)
      COMPREPLY=( $(compgen -W "show export" -- "$cur") )
      return 0
      ;;
    issuer)
      COMPREPLY=( $(compgen -W "show" -- "$cur") )
      return 0
      ;;
    profile)
      COMPREPLY=( $(compgen -W "add list" -- "$cur") )
      return 0
      ;;
    add)
      COMPREPLY=( $(compgen -W "process browser-session" -- "$cur") )
      return 0
      ;;
    secret)
      COMPREPLY=( $(compgen -W "add" -- "$cur") )
      return 0
      ;;
    credential)
      COMPREPLY=( $(compgen -W "add list" -- "$cur") )
      return 0
      ;;
    proxy)
      COMPREPLY=( $(compgen -W "add" -- "$cur") )
      return 0
      ;;
    inject)
      COMPREPLY=( $(compgen -W "add" -- "$cur") )
      return 0
      ;;
    list)
      COMPREPLY=( $(compgen -W "credentials profiles" -- "$cur") )
      return 0
      ;;
    admin)
      COMPREPLY=( $(compgen -W "start status stop serve" -- "$cur") )
      return 0
      ;;
    token)
      COMPREPLY=( $(compgen -W "--format --allow-tty --quiet" -- "$cur") )
      return 0
      ;;
    exec)
      COMPREPLY=( $(compgen -W "--env-file --env --" -- "$cur") )
      return 0
      ;;
    open)
      COMPREPLY=( $(compgen -W "--browser --print-url" -- "$cur") )
      return 0
      ;;
    completion)
      COMPREPLY=( $(compgen -W "bash zsh fish powershell" -- "$cur") )
      return 0
      ;;
  esac
}
complete -F _envvault envvault
`

const zshCompletionScript = `#compdef envvault
# zsh completion for envvault
_envvault() {
  local -a commands
  commands=(
    'init:initialize local EnvVault state'
    'reset:remove EnvVault-owned local state'
    'doctor:inspect local EnvVault state'
    'profile:manage profiles'
    'secret:manage provider API keys'
    'credential:manage raw credentials'
    'proxy:manage provider API proxy profiles'
    'inject:manage raw injection profiles'
    'list:list credentials or profiles'
    'admin:run the local admin server'
    'token:issue a process token'
    'exec:run a child process with leased credentials'
    'open:start a browser session'
    'jwks:show or export JWKS'
    'issuer:show local issuer'
    'completion:print shell completion'
    'version:print CLI version'
  )

  _arguments -C \
    '1:command:->command' \
    '*::arg:->args'

  case $state in
    command)
      _describe -t commands 'envvault commands' commands
      ;;
    args)
      case $words[2] in
        doctor) _values 'doctor options' '--repair' ;;
        reset) _values 'reset options' '--dry-run' '--yes' ;;
        jwks) _values 'jwks subcommands' 'show' 'export' ;;
        issuer) _values 'issuer subcommands' 'show' ;;
        profile) _values 'profile subcommands' 'add' 'list' 'process' 'browser-session' ;;
        secret) _values 'secret subcommands' 'add' ;;
        credential) _values 'credential subcommands' 'add' 'list' ;;
        proxy) _values 'proxy subcommands' 'add' ;;
        inject) _values 'inject subcommands' 'add' ;;
        list) _values 'list targets' 'credentials' 'profiles' ;;
        admin) _values 'admin subcommands' 'start' 'status' 'stop' 'serve' ;;
        token) _values 'token options' '--format' '--allow-tty' '--quiet' ;;
        exec) _values 'exec options' '--env-file' '--env' '--' ;;
        open) _values 'open options' '--browser' '--print-url' ;;
        completion) _values 'completion shells' 'bash' 'zsh' 'fish' 'powershell' ;;
      esac
      ;;
  esac
}
_envvault "$@"
`

const fishCompletionScript = `# fish completion for envvault
complete -c envvault -f -n '__fish_use_subcommand' -a 'init reset doctor profile secret credential proxy inject list admin token exec open jwks issuer completion version'
complete -c envvault -f -n '__fish_seen_subcommand_from doctor' -l repair
complete -c envvault -f -n '__fish_seen_subcommand_from reset' -l dry-run
complete -c envvault -f -n '__fish_seen_subcommand_from reset' -l yes
complete -c envvault -f -n '__fish_seen_subcommand_from jwks' -a 'show export'
complete -c envvault -f -n '__fish_seen_subcommand_from issuer' -a 'show'
complete -c envvault -f -n '__fish_seen_subcommand_from profile' -a 'add list process browser-session'
complete -c envvault -f -n '__fish_seen_subcommand_from secret' -a 'add'
complete -c envvault -f -n '__fish_seen_subcommand_from credential' -a 'add list'
complete -c envvault -f -n '__fish_seen_subcommand_from proxy' -a 'add'
complete -c envvault -f -n '__fish_seen_subcommand_from inject' -a 'add'
complete -c envvault -f -n '__fish_seen_subcommand_from list' -a 'credentials profiles'
complete -c envvault -f -n '__fish_seen_subcommand_from admin' -a 'start status stop serve'
complete -c envvault -f -n '__fish_seen_subcommand_from token' -l format
complete -c envvault -f -n '__fish_seen_subcommand_from token' -l allow-tty
complete -c envvault -f -n '__fish_seen_subcommand_from token' -l quiet
complete -c envvault -f -n '__fish_seen_subcommand_from exec' -l env-file
complete -c envvault -f -n '__fish_seen_subcommand_from exec' -l env
complete -c envvault -f -n '__fish_seen_subcommand_from open' -l browser
complete -c envvault -f -n '__fish_seen_subcommand_from open' -l print-url
complete -c envvault -f -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish powershell'
`

const powershellCompletionScript = `# PowerShell completion for envvault
Register-ArgumentCompleter -Native -CommandName envvault -ScriptBlock {
  param($wordToComplete, $commandAst, $cursorPosition)
  $words = $commandAst.CommandElements | ForEach-Object { $_.Extent.Text }
  $commands = @('init','reset','doctor','profile','secret','credential','proxy','inject','list','admin','token','exec','open','jwks','issuer','completion','version')
  $values = switch ($words[1]) {
    'doctor' { @('--repair') }
    'reset' { @('--dry-run','--yes') }
    'jwks' { @('show','export') }
    'issuer' { @('show') }
    'profile' { @('add','list','process','browser-session') }
    'secret' { @('add') }
    'credential' { @('add','list') }
    'proxy' { @('add') }
    'inject' { @('add') }
    'list' { @('credentials','profiles') }
    'admin' { @('start','status','stop','serve') }
    'token' { @('--format','--allow-tty','--quiet') }
    'exec' { @('--env-file','--env','--') }
    'open' { @('--browser','--print-url') }
    'completion' { @('bash','zsh','fish','powershell') }
    default { $commands }
  }
  $values | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
  }
}
`
