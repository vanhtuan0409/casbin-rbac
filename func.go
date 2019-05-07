package main

import (
	"errors"
	"strconv"
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
