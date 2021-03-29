package questions

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/onsi/ginkgo/reporters/stenographer/support/go-isatty"
	"golang.org/x/crypto/ssh/terminal"
)

func PromptOptions(text string, def int, options ...string) (int, error) {
	if len(options) == 1 {
		return 0, nil
	}

	PrintToTerm(text)
	for _, option := range options {
		PrintToTerm(option)
	}

	defString := ""
	if def >= 0 {
		defString = strconv.Itoa(def)
	}

	for {
		ans, err := Prompt(fmt.Sprintf("Select Number [%s] ", defString), defString)
		if err != nil {
			return 0, err
		}
		num, err := strconv.Atoi(ans)
		if err != nil {
			PrintfToTerm("Invalid number: %s\n", ans)
			continue
		}

		num--
		if num < 0 || num >= len(options) {
			PrintlnToTerm("Select a number between 1 and", +len(options))
			continue
		}

		return num, nil
	}
}

func PromptBool(text string, def bool) (bool, error) {
	msg := fmt.Sprintf("%s [y/N] ", text)
	defStr := "n"
	if def {
		msg = fmt.Sprintf("%s [Y/n] ", text)
		defStr = "y"
	}

	for {
		yn, err := Prompt(msg, defStr)
		if err != nil {
			return false, err
		}

		switch strings.ToLower(yn) {
		case "y":
			return true, nil
		case "n":
			return false, nil
		default:
			fmt.Println("Enter y or n")
		}
	}
}

func PrintToTerm(text ...interface{}) {
	if isatty.IsTerminal(os.Stdout.Fd()) {
		fmt.Print(text...)
	} else {
		fmt.Fprint(os.Stderr, text...)
	}
}

func PrintlnToTerm(text ...interface{}) {
	if isatty.IsTerminal(os.Stdout.Fd()) {
		fmt.Println(text...)
	} else {
		fmt.Fprintln(os.Stderr, text...)
	}
}

func PrintfToTerm(msg string, format ...interface{}) {
	if isatty.IsTerminal(os.Stdout.Fd()) {
		fmt.Printf(msg, format...)
	} else {
		fmt.Fprintf(os.Stderr, msg, format...)
	}
}

func Prompt(text, def string) (string, error) {
	for {
		PrintToTerm(text)
		answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return "", err
		}

		answer = strings.TrimSpace(answer)
		if answer == "" {
			answer = def
		}

		if answer == "" {
			continue
		}

		return answer, nil
	}
}

func PromptPassword(text, def string) (string, error) {
	for {
		PrintToTerm(text)
		answer, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", err
		}
		fmt.Printf("\n")
		if len(answer) == 0 {
			return def, nil
		}
		return string(answer), nil
	}
}
