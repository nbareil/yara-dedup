package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/Northern-Lights/yara-parser/data"
	"github.com/Northern-Lights/yara-parser/grammar"
)

var rulenames = make(map[string]bool)
var hashes = make(map[string]string)

func hashRule(rule data.Rule) string {
	h := sha256.New()
	for _, s := range rule.Strings {
		ruleStr, err := s.Serialize()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not Serialize: %s", err)
			continue
		}
		h.Write([]byte(ruleStr))
	}
	h.Write([]byte(rule.Condition))
	return string(h.Sum(nil))
}

func parseRuleset(input io.Reader) {
	ruleset, err := grammar.Parse(input, os.Stdout)
	if err != nil {
		log.Fatalf(`Parsing failed: "%s"`, err)
		return
	}

	for _, rule := range ruleset.Rules {
		if _, ok := rulenames[rule.Identifier]; !ok {
			yaraRepr, err := rule.Serialize()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Could not Serialize %s: %s\n", rule.Identifier, err)
				continue
			}
			rulenames[rule.Identifier] = true

			hashBuf := hashRule(rule)
			fmt.Fprintf(os.Stderr, "rule %s=%x\n", rule.Identifier, hashBuf)
			if _, ok := hashes[hashBuf]; ok {
				fmt.Fprintf(os.Stderr, "The rule %s looks similar to %s, skipping.\n", rule.Identifier, hashes[hashBuf])
				continue
			}
			hashes[hashBuf] = rule.Identifier
			fmt.Print(yaraRepr)
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
