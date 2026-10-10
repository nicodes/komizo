package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/nicodes/komizo/internal/workload"
)

func runWorkloadIngress(args []string, isolate bool) error {
	fs := flag.NewFlagSet("ingress", flag.ContinueOnError)
	path := fs.String("policy", "", "protected workload policy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *path == "" {
		return errors.New("ingress needs a policy path")
	}
	p, err := readWorkloadPolicy(*path)
	if err != nil {
		return err
	}
	if isolate {
		if os.Geteuid() != 0 {
			return errors.New("ingress isolation requires the operator")
		}
		p.IngressNetwork = workload.IsolatedIngress(p.App)
		return workload.WritePrivateJSON(*path, p)
	}
	name := p.SharedNetwork
	if p.IngressNetwork != "" {
		name = p.IngressNetwork
	}
	fmt.Println(name)
	return nil
}
