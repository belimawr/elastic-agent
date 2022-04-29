// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd/proc"
)

// Setups and Runs agent.
func main() {
	if err := cmd.CheckNativePlatformCompat(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize: %v\n", err)
		os.Exit(1)
	}

	pj, err := proc.CreateJobObject()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize process job object: %v\n", err)
		os.Exit(1)
	}
	defer pj.Close()

	rand.Seed(time.Now().UnixNano())

	// Catch a panic, log it, then panic.
	defer func() {
		if r := recover(); r != nil {
			logp.L().With("stack_trace", string(debug.Stack())).
				Panicf("recovered from panic: %v", r)
		}
	}()

	command := cmd.NewCommand()
	if err := command.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
