package main

import "fmt"

// colorFunc returns a function that wraps text in ANSI escape codes if isTTY is true.
func colorFunc(isTTY bool) func(code, text string) string {
	if isTTY {
		return func(code, text string) string {
			return fmt.Sprintf("\033[%sm%s\033[0m", code, text)
		}
	}
	return func(_, text string) string {
		return text
	}
}
