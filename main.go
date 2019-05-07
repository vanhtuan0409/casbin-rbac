package main

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/casbin/casbin"
)

const (
	READ_PRIV  = 1
	WRITE_PRIV = 2
	DEL_PRIV   = 4
	ALL_PRIV   = 7
)

func privMatch(rPriv, pPriv byte) bool {
	return rPriv&pPriv == rPriv
}

func convert(arg interface{}) (byte, error) {
	switch v := arg.(type) {
	case float64:
		return byte(v), nil
	case string:
		i, err := strconv.Atoi(v)
		if err != nil {
			return 0, err
		}
		return byte(i), nil
	}

	return 0, errors.New("Unknow type")
}

func PrivMatchFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, nil
	}

	rPriv, err := convert(args[0])
	if err != nil {
		return false, nil
	}
	pPriv, err := convert(args[1])
	if err != nil {
		return false, nil
	}

	return privMatch(rPriv, pPriv), nil
}

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
