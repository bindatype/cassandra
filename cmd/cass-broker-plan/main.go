package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bindatype/cassandra/internal/broker"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("cass-broker-plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	policyPath := flags.String("policy", "", "path to a broker policy JSON file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" {
		fmt.Fprintln(stderr, "cass-broker-plan: -policy is required")
		return 2
	}

	policyFile, err := os.Open(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "cass-broker-plan: open policy: %v\n", err)
		return 1
	}
	defer policyFile.Close()

	policy, err := broker.LoadPolicy(policyFile)
	if err != nil {
		fmt.Fprintf(stderr, "cass-broker-plan: %v\n", err)
		return 1
	}
	router, err := broker.NewRouter(policy)
	if err != nil {
		fmt.Fprintf(stderr, "cass-broker-plan: %v\n", err)
		return 1
	}
	request, err := broker.DecodeRouteRequest(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "cass-broker-plan: %v\n", err)
		return 1
	}
	plan, err := router.Plan(request)
	if err != nil {
		fmt.Fprintf(stderr, "cass-broker-plan: route denied: %v\n", err)
		return 1
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(plan); err != nil {
		fmt.Fprintf(stderr, "cass-broker-plan: encode plan: %v\n", err)
		return 1
	}
	return 0
}
