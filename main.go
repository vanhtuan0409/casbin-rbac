package main

import (
	"fmt"

	"github.com/casbin/casbin"
)

const (
	READ_PRIV  = 1
	WRITE_PRIV = 2
	DEL_PRIV   = 4
	ALL_PRIV   = 7
)

func main() {
	e, err := casbin.NewEnforcerSafe("model.conf", "policy.csv")
	if err != nil {
		panic(err)
	}
	e.AddFunction("priv_match", PrivMatchFunc)

	r1 := e.Enforce("alice", "data1", READ_PRIV)
	fmt.Printf("Alice can read data1: %v\n", r1)

	r2 := e.Enforce("alice", "data1", WRITE_PRIV)
	fmt.Printf("Alice can write data1: %v\n", r2)

	r5 := e.Enforce("alice", "data1", READ_PRIV|WRITE_PRIV)
	fmt.Printf("Alice can read write data1: %v\n", r5)

	r3 := e.Enforce("alice", "data2", READ_PRIV)
	fmt.Printf("Alice can read data2: %v\n", r3)

	r4 := e.Enforce("alice", "data2", WRITE_PRIV)
	fmt.Printf("Alice can write data2: %v\n", r4)

	r6 := e.Enforce("alice", "data2", READ_PRIV|WRITE_PRIV)
	fmt.Printf("Alice can read write data2: %v\n", r6)

	roles := e.GetRolesForUser("alice")
	fmt.Printf("Alice roles: %v\n", roles)
}
