package cli

import "github.com/chzyer/readline"

type StateAwareCompleter struct {
	isLoggedIn func() bool
}

func NewStateAwareCompleter(isLoggedIn func() bool) *StateAwareCompleter {
	return &StateAwareCompleter{isLoggedIn: isLoggedIn}
}

func (c *StateAwareCompleter) Do(line []rune, pos int) (newLine [][]rune, length int) {
	var words []string
	if c.isLoggedIn() {
		words = []string{"whoami", "enable-2fa", "disable-2fa", "logout", "help", "exit"}
	} else {
		words = []string{"register", "login", "help", "exit"}
	}

	var items []readline.PrefixCompleterInterface
	for _, w := range words {
		items = append(items, readline.PcItem(w))
	}

	completer := readline.NewPrefixCompleter(items...)
	return completer.Do(line, pos)
}