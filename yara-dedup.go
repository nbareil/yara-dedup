package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/Northern-Lights/yara-parser/data"
	"github.com/Northern-Lights/yara-parser/grammar"
)

var rulenames = make(map[string]bool)

func serialize(output io.Writer, rule data.Rule) {
	fmt.Fprintf(output, "rule %s ", rule.Identifier)
	if len(rule.Tags) > 0 {
		fmt.Fprintf(output, ": %s ", strings.Join(rule.Tags, " "))
	}

	fmt.Fprintf(output, "{ \n")
	if len(rule.Meta) > 0 {
		fmt.Fprintf(output, "  meta:\n")
		for _, meta := range rule.Meta {
			if _, ok := meta.Val.(string); ok {
				fmt.Fprintf(output, "    %s = \"%s\"\n", meta.Key, meta.Val)
			}
			if _, ok := meta.Val.(int64); ok {
				fmt.Fprintf(output, "    %s = %d\n", meta.Key, meta.Val)
			}
			if val, ok := meta.Val.(bool); ok {
				if val {
					fmt.Fprintf(output, "    %s = true\n", meta.Key)
				} else {
					fmt.Fprintf(output, "    %s = false\n", meta.Key)
				}
			}
		}
		fmt.Fprintf(output, "\n")
	}

	if len(rule.Strings) > 0 {
		fmt.Fprintf(output, "  strings:\n")
		for _, s := range rule.Strings {
			if s.Type == data.TypeString {
				fmt.Fprintf(output, "    %s = \"%s\"", s.ID, s.Text)
			} else if s.Type == data.TypeRegex {
				fmt.Fprintf(output, "    %s = /%s/", s.ID, s.Text)
			} else if s.Type == data.TypeHexString {
				fmt.Fprintf(output, "    %s = { %s }", s.ID, s.Text)
			}
			if s.Modifiers.ASCII {
				fmt.Fprintf(output, " ascii")
			}
			if s.Modifiers.Wide {
				fmt.Fprintf(output, " wide")
			}
			if s.Modifiers.Nocase {
				fmt.Fprintf(output, " nocase")
			}
			if s.Modifiers.Fullword {
				fmt.Fprintf(output, " fullword")
			}

			if s.Modifiers.I {
				fmt.Fprintf(output, "i")
			}
			if s.Modifiers.S {
				fmt.Fprintf(output, "s")
			}

			fmt.Fprintf(output, "\n")
		}
		fmt.Fprintf(output, "\n")
	}

	fmt.Fprintf(output, "  condition:\n    %s\n}\n\n", rule.Condition)
}

func parseRuleset(input io.Reader) {
	ruleset, err := grammar.Parse(input, os.Stdout)
	if err != nil {
		log.Fatalf(`Parsing failed: "%s"`, err)
	}

	for _, rule := range ruleset.Rules {
		if _, ok := rulenames[rule.Identifier]; !ok {
			rulenames[rule.Identifier] = true
			serialize(os.Stdout, rule)
		} else {
			fmt.Fprintf(os.Stderr, "Skipping %s...\n", rule.Identifier)
		}
	}
}

func main() {
	for _, fn := range os.Args[1:] {
		input, err := os.Open(fn)
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}

		parseRuleset(input)
	}
}
