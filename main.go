package main

import (
	"access-control/src/perms"
	"access-control/src/rss"
	"access-control/src/status"
	"access-control/src/types"
	"fmt"
	"time"
)

func main() {
	var p rss.Permission = &rss.Terminal{
		Group: &rss.Group{
			ID: "group_1",
			Permissions: []rss.Permission{
				&perms.AllowLevel{Level: 10}, // all of these are ignored when override is present
				&perms.AllowAnyRole{Roles: []string{"staff"}},
				&perms.DenyAnyRole{Roles: []string{"stupid"}},
			},
			Overwrite: &rss.Group{
				ID: "group_1_overwrite",
				Permissions: []rss.Permission{
					&perms.AllowLevel{Level: 11}, // level 11 or staff, but not if you have the o_stupid role
					&perms.AllowAnyRole{Roles: []string{"o_staff"}},
					&perms.DenyAnyRole{Roles: []string{"o_stupid"}},
				},
			},
		},
	}
	ok := p.Clears(&rss.Key{
		ID: "key_1",
		Owner: &rss.User{
			ID:       "user_1",
			Level:    10,
			Roles:    []string{"staff"},
			Disabled: false,
		},
		Roles:    []string{"staff", "stupid", "o_st4aff"}, // only o_staff matters when an override is present
		Disabled: false,
		Expires:  types.JsonTime(time.Now().Add(time.Hour * 10000)),
	})
	// ternary 100
	stat := map[status.Status]string{
		status.Allow:   "Allow",
		status.Neutral: "Neutral",
		status.Deny:    "Deny",
	}[ok.Status]
	fmt.Println(stat, "|", ok.Reason)
}
