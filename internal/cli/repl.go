package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/chzyer/readline"
)

type REPL struct {
	handler   *CLIHandler
	completer *StateAwareCompleter
}

func NewREPL(handler *CLIHandler) *REPL {
	completer := NewStateAwareCompleter(handler.IsLoggedIn)
	return &REPL{
		handler:   handler,
		completer: completer,
	}
}

func (r *REPL) Run(ctx context.Context) error {
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "auth-cli> ",
		HistoryFile:     "/tmp/auth_cli_history.tmp",
		AutoComplete:    r.completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return fmt.Errorf("failed to initialize readline: %w", err)
	}
	defer rl.Close()

	r.handler.SetReadline(rl)

	fmt.Println("  Welcome to the Containerized 2FA Auth System   ")
	fmt.Println("  Type 'help' to see available commands          ")

	for {
		// Update prompt dynamically based on session
		if r.handler.IsLoggedIn() {
			rl.SetPrompt(fmt.Sprintf("auth-cli (%s)> ", r.handler.currentUser.Username))
		} else {
			rl.SetPrompt("auth-cli> ")
		}

		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				continue
			} else if err == io.EOF {
				fmt.Println("\nGoodbye!")
				break
			}
			return err
		}

		cmd := strings.TrimSpace(line)
		if cmd == "" {
			continue
		}

		if cmd == "exit" {
			if r.handler.IsLoggedIn() {
				r.handler.HandleLogout(ctx)
			}
			fmt.Println("Goodbye!")
			break
		}

		r.executeCommand(ctx, cmd)
	}

	return nil
}

func (r *REPL) executeCommand(ctx context.Context, cmd string) {
	if !r.handler.IsLoggedIn() {
		switch cmd {
		case "register":
			r.handler.HandleRegister(ctx)
		case "login":
			r.handler.HandleLogin(ctx)
		case "help":
			r.handler.DisplayHelp()
		default:
			fmt.Printf("Unknown command '%s'. Type 'help' for available commands.\n", cmd)
		}
	} else {
		switch cmd {
		case "whoami":
			r.handler.HandleWhoAmI(ctx)
		case "enable-2fa":
			r.handler.HandleEnable2FA(ctx)
		case "disable-2fa":
			r.handler.HandleDisable2FA(ctx)
		case "logout":
			r.handler.HandleLogout(ctx)
		case "help":
			r.handler.DisplayHelp()
		default:
			fmt.Printf("Unknown command '%s'. Type 'help' for available commands.\n", cmd)
		}
	}
}