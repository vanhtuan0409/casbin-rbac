package main

import (
	"fmt"
	"strconv"

	"github.com/casbin/casbin"
)

const (
	ADMIN_ROLE = "admin"
	ADMIN_PRIV = ALL_PRIV

	MOD_ROLE = "moderator"
	MOD_PRIV = READ_PRIV | WRITE_PRIV

	MEMBER_ROLE = "member"
	MEMBER_PRIV = READ_PRIV
)

var (
	ROLES = [][]string{
		[]string{ADMIN_ROLE, strconv.Itoa(ADMIN_PRIV)},
		[]string{MOD_ROLE, strconv.Itoa(MOD_PRIV)},
		[]string{MEMBER_ROLE, strconv.Itoa(MEMBER_PRIV)},
	}
	RESOURCES = []string{"repos"}
)

func getGroupSubjectKey(name, role string) string {
	return fmt.Sprintf("g:%s:%s", name, role)
}
func getGroupObjectKey(gName, resource string) string {
	return fmt.Sprintf("/groups/%s/%s/*", gName, resource)
}
func getRepoObjectKey(gName, rName string) string {
	return fmt.Sprintf("/groups/%s/repos/%s", gName, rName)
}

func addGroup(e *casbin.Enforcer, name string) error {
	for _, role := range ROLES {
		for _, res := range RESOURCES {
			sub := getGroupSubjectKey(name, role[0])
			obj := getGroupObjectKey(name, res)
			e.AddPolicy(sub, obj, role[1])
		}
	}
	return nil
}

func assignGroup(e *casbin.Enforcer, user, group, role string) error {
	target := getGroupSubjectKey(group, role)
	e.AddGroupingPolicy(user, target)
	return nil
}

func addRepo(e *casbin.Enforcer, group, owner, repo string) error {
	target := getRepoObjectKey(group, repo)
	e.AddPolicy(owner, target, strconv.Itoa(ALL_PRIV))
	return nil
}
