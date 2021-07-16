package perms

import (
	"access-control/src/rss"
	"access-control/src/status"
	"access-control/src/types"
	"strings"
	"time"
)

// DenyAllRoles denies a key when it or the keyholder possess all of the given roles
//
// This should only be used in exceptional cases
type DenyAllRoles struct {
	// Role is the role required to deny the key
	Roles []string `json:"roles"`

	// Expires is when this permission no longer applies
	Expires types.JsonTime `json:"expires"`
}

func (d *DenyAllRoles) Clears(key *rss.Key) *status.ClearStatus {
	if d.IsExpired() {
		return status.NewNeutral()
	}
	for _, role := range d.Roles {
		if !key.HasRole(role) {
			return status.NewNeutral()
		}
	}
	return status.NewDeny("deny_all_roles denies access via roles: " + strings.Join(d.Roles, ", "))
}

func (d *DenyAllRoles) IsExpired() bool {
	t := time.Time(d.Expires)
	return t.UnixNano() > 0 && t.Before(time.Now())
}
