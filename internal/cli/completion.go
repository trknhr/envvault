package cli

import (
	"fmt"
	"io"
)

const completionUsage = "credlease: usage: credlease completion <bash|zsh|fish|powershell>"

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

const bashCompletionScript = `# bash completion for credlease
_credlease()
{
  local cur prev commands
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  commands="init reset doctor profile token exec open jwks issuer completion"

  case "$prev" in
    credlease)
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
      COMPREPLY=( $(compgen -W "add" -- "$cur") )
      return 0
      ;;
    add)
      COMPREPLY=( $(compgen -W "process browser-session" -- "$cur") )
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
complete -F _credlease credlease
`

const zshCompletionScript = `#compdef credlease
# zsh completion for credlease
_credlease() {
  local -a commands
  commands=(
    'init:initialize local Credlease state'
    'reset:remove Credlease-owned local state'
    'doctor:inspect local Credlease state'
    'profile:manage profiles'
    'token:issue a process token'
    'exec:run a child process with leased credentials'
    'open:start a browser session'
    'jwks:show or export JWKS'
    'issuer:show local issuer'
    'completion:print shell completion'
  )

  _arguments -C \
    '1:command:->command' \
    '*::arg:->args'

  case $state in
    command)
      _describe -t commands 'credlease commands' commands
      ;;
    args)
      case $words[2] in
        doctor) _values 'doctor options' '--repair' ;;
        reset) _values 'reset options' '--dry-run' '--yes' ;;
        jwks) _values 'jwks subcommands' 'show' 'export' ;;
        issuer) _values 'issuer subcommands' 'show' ;;
        profile) _values 'profile subcommands' 'add' 'process' 'browser-session' ;;
        token) _values 'token options' '--format' '--allow-tty' '--quiet' ;;
        exec) _values 'exec options' '--env-file' '--env' '--' ;;
        open) _values 'open options' '--browser' '--print-url' ;;
        completion) _values 'completion shells' 'bash' 'zsh' 'fish' 'powershell' ;;
      esac
      ;;
  esac
}
_credlease "$@"
`

const fishCompletionScript = `# fish completion for credlease
complete -c credlease -f -n '__fish_use_subcommand' -a 'init reset doctor profile token exec open jwks issuer completion'
complete -c credlease -f -n '__fish_seen_subcommand_from doctor' -l repair
complete -c credlease -f -n '__fish_seen_subcommand_from reset' -l dry-run
complete -c credlease -f -n '__fish_seen_subcommand_from reset' -l yes
complete -c credlease -f -n '__fish_seen_subcommand_from jwks' -a 'show export'
complete -c credlease -f -n '__fish_seen_subcommand_from issuer' -a 'show'
complete -c credlease -f -n '__fish_seen_subcommand_from profile' -a 'add process browser-session'
complete -c credlease -f -n '__fish_seen_subcommand_from token' -l format
complete -c credlease -f -n '__fish_seen_subcommand_from token' -l allow-tty
complete -c credlease -f -n '__fish_seen_subcommand_from token' -l quiet
complete -c credlease -f -n '__fish_seen_subcommand_from exec' -l env-file
complete -c credlease -f -n '__fish_seen_subcommand_from exec' -l env
complete -c credlease -f -n '__fish_seen_subcommand_from open' -l browser
complete -c credlease -f -n '__fish_seen_subcommand_from open' -l print-url
complete -c credlease -f -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish powershell'
`

const powershellCompletionScript = `# PowerShell completion for credlease
Register-ArgumentCompleter -Native -CommandName credlease -ScriptBlock {
  param($wordToComplete, $commandAst, $cursorPosition)
  $words = $commandAst.CommandElements | ForEach-Object { $_.Extent.Text }
  $commands = @('init','reset','doctor','profile','token','exec','open','jwks','issuer','completion')
  $values = switch ($words[1]) {
    'doctor' { @('--repair') }
    'reset' { @('--dry-run','--yes') }
    'jwks' { @('show','export') }
    'issuer' { @('show') }
    'profile' { @('add','process','browser-session') }
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
