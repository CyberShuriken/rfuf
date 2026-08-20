package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CyberShuriken/rfuf/internal/scope"
)

func main() {
	root := flag.String("domain", "", "Root domain or wildcard scope, for example example.com or *.example.com")
	input := flag.String("input", "", "Input file containing hostnames or URLs")
	output := flag.String("output", "", "Output file for in-scope lines")
	outOfScope := flag.String("out-of-scope", "", "Output file for rejected lines")
	reportPath := flag.String("report", "", "JSON scope report path")
	flag.Parse()

	if *root == "" || *input == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "usage: scope-filter -domain <domain> -input <file> -output <file> [-out-of-scope <file>] [-report <file>]")
		os.Exit(2)
	}

	data, err := os.Open(*input)
	if err != nil {
		fatal(err)
	}
	defer data.Close()
	var lines []string
	scanner := bufio.NewScanner(data)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fatal(err)
	}

	normalized, err := scope.NormalizeDomain(*root)
	if err != nil {
		fatal(err)
	}
	inScope, rejected, err := scope.FilterLines(lines, normalized)
	if err != nil {
		fatal(err)
	}
	if err := writeLines(*output, inScope); err != nil {
		fatal(err)
	}
	if *outOfScope != "" {
		if err := writeLines(*outOfScope, rejected); err != nil {
			fatal(err)
		}
	}
	if *reportPath != "" {
		report := scope.Report{Input: *root, RootDomain: normalized, GeneratedAt: time.Now().UTC(), InScope: len(inScope), OutOfScope: len(rejected), InScopeFile: filepath.Base(*output), OutFile: filepath.Base(*outOfScope)}
		data, err := report.JSON()
		if err != nil {
			fatal(err)
		}
		if err := os.WriteFile(*reportPath, append(data, '\n'), 0644); err != nil {
			fatal(err)
		}
	}
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return w.Flush()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
