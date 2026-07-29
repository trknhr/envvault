package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trknhr/envvault/internal/agentskill"
)

const skillsUsage = "envvault: usage: envvault skills <list|get|install|status|path|uninstall>"

type skillTargetFlags struct {
	global  bool
	project bool
	agent   string
}

func (a App) newSkillsCommand(execution *commandExecution) *cobra.Command {
	skillsCommand := newCommandGroup("skills", "Manage the EnvVault agent skill", skillsUsage, execution)

	skillsCommand.AddCommand(
		newListLeaf("list", "List bundled EnvVault skills", execution, runSkillsList),
		newSkillsGetCommand(execution),
		a.newSkillsInstallCommand(execution),
		a.newSkillsStatusCommand(execution),
		a.newSkillsPathCommand(execution),
		a.newSkillsUninstallCommand(execution),
	)
	return skillsCommand
}

func newSkillsGetCommand(execution *commandExecution) *cobra.Command {
	return &cobra.Command{
		Use:   "get <name>",
		Short: "Print a bundled EnvVault skill",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			content, err := agentskill.Get(args[0])
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			fmt.Fprint(cmd.OutOrStdout(), content)
		},
	}
}

func (a App) newSkillsInstallCommand(execution *commandExecution) *cobra.Command {
	var flags skillTargetFlags
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install the EnvVault discovery skill",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			target, err := a.skillTarget(cmd.Context(), flags)
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			result, err := agentskill.Install(target)
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			switch {
			case result.Changed:
				fmt.Fprintf(cmd.OutOrStdout(), "installed\t%s\n", result.Status.Path)
			case result.Status.State == agentskill.StateExternal:
				fmt.Fprintf(cmd.OutOrStdout(), "already installed (external)\t%s\n", result.Status.Path)
			default:
				fmt.Fprintf(cmd.OutOrStdout(), "already installed\t%s\n", result.Status.Path)
			}
		},
	}
	addSkillTargetFlags(cmd, &flags)
	return cmd
}

func (a App) newSkillsStatusCommand(execution *commandExecution) *cobra.Command {
	var flags skillTargetFlags
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the EnvVault discovery skill status",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			target, err := a.skillTarget(cmd.Context(), flags)
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			status, err := agentskill.Inspect(target)
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			detail := "different"
			if status.State == agentskill.StateMissing {
				detail = "absent"
			} else if status.Current {
				detail = "current"
			} else if status.Modified {
				detail = "modified"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s (%s)\t%s\n", status.State, detail, status.Path)
			if status.State == agentskill.StateMissing || !status.Current {
				execution.exitCode = 1
			}
		},
	}
	addSkillTargetFlags(cmd, &flags)
	return cmd
}

func (a App) newSkillsPathCommand(execution *commandExecution) *cobra.Command {
	var flags skillTargetFlags
	cmd := &cobra.Command{
		Use:   "path",
		Short: "Print the EnvVault discovery skill path",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			target, err := a.skillTarget(cmd.Context(), flags)
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			path, err := agentskill.TargetPath(target)
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			fmt.Fprintln(cmd.OutOrStdout(), path)
		},
	}
	addSkillTargetFlags(cmd, &flags)
	return cmd
}

func (a App) newSkillsUninstallCommand(execution *commandExecution) *cobra.Command {
	var flags skillTargetFlags
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove an EnvVault-managed discovery skill",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			target, err := a.skillTarget(cmd.Context(), flags)
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			result, err := agentskill.Uninstall(target)
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			if result.Removed {
				fmt.Fprintf(cmd.OutOrStdout(), "removed\t%s\n", result.Path)
				return
			}
			fmt.Fprintf(cmd.OutOrStdout(), "not installed\t%s\n", result.Path)
		},
	}
	addSkillTargetFlags(cmd, &flags)
	return cmd
}

func runSkillsList(stdout, _ io.Writer) int {
	for _, skill := range agentskill.List() {
		fmt.Fprintf(stdout, "%s\t%s\n", skill.Name, skill.Description)
	}
	return 0
}

func addSkillTargetFlags(cmd *cobra.Command, flags *skillTargetFlags) {
	cmd.Flags().BoolVarP(&flags.global, "global", "g", false, "Use the user-level skill directory (default)")
	cmd.Flags().BoolVarP(&flags.project, "project", "p", false, "Use the current project skill directory")
	cmd.Flags().StringVarP(
		&flags.agent,
		"agent",
		"a",
		agentskill.AgentUniversal,
		"Target agent ("+strings.Join(agentskill.SupportedAgents(), ", ")+")",
	)
}

func (a App) skillTarget(ctx context.Context, flags skillTargetFlags) (agentskill.TargetOptions, error) {
	if flags.global && flags.project {
		return agentskill.TargetOptions{}, fmt.Errorf("--global and --project are mutually exclusive")
	}
	target := agentskill.TargetOptions{
		Scope:   agentskill.ScopeGlobal,
		Agent:   flags.agent,
		HomeDir: a.agentSkillHomeDir,
	}
	if !flags.project {
		return target, nil
	}
	identity, err := a.detectProjectIdentity(ctx)
	if err != nil {
		return agentskill.TargetOptions{}, err
	}
	target.Scope = agentskill.ScopeProject
	target.ProjectDir = identity.Root
	return target, nil
}
