package main

import (
	"access-control/src/perms"
	"access-control/src/rss"
	"access-control/src/types"
	"fmt"
	"time"
)

func main() {
	var p rss.Permission = &rss.Terminal{
		Group: &rss.Group{
			ID:          "group_1",
			Overwrite: &rss.Group{
				ID: "group_1_overwrite",
				Permissions: []rss.Permission{
					&perms.AllowLevel{Level: 11}, // Level 11 or staff, but not if you have stupid_key
					&perms.AllowAnyRole{Roles: []string{"staff"}},
					&perms.DenyAnyRole{Roles: []string{"stupid_key"}},
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
		Roles:    []string{"super_key"},
		Disabled: false,
		Expires:  types.JsonTime(time.Now().Add(time.Hour * 10000)),
	})
	fmt.Println(ok.Status, ok.Reason)
}

// Key#Use
