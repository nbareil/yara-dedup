package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/Northern-Lights/yara-parser/grammar"
)

var rulenames = make(map[string]bool)

func parseRuleset(input io.Reader) {
	ruleset, err := grammar.Parse(input, os.Stdout)
	if err != nil {
		log.Fatalf(`Parsing failed: "%s"`, err)
	}

	for _, rule := range ruleset.Rules {
		if _, ok := rulenames[rule.Identifier]; !ok {
            yaraRepr, err := rule.Serialize()
            if err != nil {
                fmt.Fprintf(os.Stderr, "Could not Serialize %s: %s\n", rule.Identifier, err)
                continue
            }
			rulenames[rule.Identifier] = true
            fmt.Print(yaraRepr)
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
