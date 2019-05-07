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

func checkAccess(e *casbin.Enforcer, user, group, repo string, priv byte) {
	repoPath := getRepoObjectKey(group, repo)
	accessible := e.Enforce(user, repoPath, priv)
	fmt.Printf("User %s can %v %s in group %s: %v\n", user, toPrivReadable(priv), repo, group, accessible)
}

func toPrivReadable(priv byte) []string {
	privs := []string{}
	if priv&READ_PRIV > 0 {
		privs = append(privs, "read")
	}
	if priv&WRITE_PRIV > 0 {
		privs = append(privs, "write")
	}
	if priv&DEL_PRIV > 0 {
		privs = append(privs, "delete")
	}
	return privs
}

func main() {
	e, err := casbin.NewEnforcerSafe("model.conf", "policy.csv")
	if err != nil {
		panic(err)
	}
	e.AddFunction("priv_match", PrivMatchFunc)

	addGroup(e, "group1")
	addGroup(e, "group2")

	assignGroup(e, "alice", "group1", ADMIN_ROLE)
	assignGroup(e, "alice", "group2", MEMBER_ROLE)
	assignGroup(e, "bob", "group2", MOD_ROLE)

	addRepo(e, "group1", "alice", "repo1")
	addRepo(e, "group2", "alice", "repo2")
	addRepo(e, "group2", "bob", "repo3")

	checkAccess(e, "alice", "group1", "repo1", READ_PRIV|WRITE_PRIV)
	checkAccess(e, "alice", "group2", "repo2", READ_PRIV)
	checkAccess(e, "alice", "group2", "repo3", READ_PRIV)
	checkAccess(e, "alice", "group2", "repo3", DEL_PRIV)
	checkAccess(e, "bob", "group2", "repo3", ALL_PRIV)
	checkAccess(e, "bob", "group1", "repo2", READ_PRIV)

	err = e.SavePolicy()
	if err != nil {
		fmt.Printf("Cannot save policy: ERR: %v\n", err)
	}
}
