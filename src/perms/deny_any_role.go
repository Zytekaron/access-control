package perms

import (
	"access-control/src/rss"
	"access-control/src/status"
	"access-control/src/types"
	"time"
)

// DenyAnyRole denies a key when it or the keyholder possess any of the given roles
//
// This should only be used in exceptional cases, *and it must be placed
// before all other permissions in a group or terminal to function properly*
type DenyAnyRole struct {
	// Role is the role required to deny the key
	Roles []string `json:"roles"`

	// Expires is when this permission no longer applies
	Expires types.JsonTime `json:"expires"`
}

func (d *DenyAnyRole) Clears(key *rss.Key) *status.ClearStatus {
	if d.IsExpired() {
		return status.NewNeutral()
	}
	for _, role := range d.Roles {
		if key.HasRole(role) {
			return status.NewDeny("deny_role denies access via role '" + role + "'")
		}
	}
	return status.NewNeutral()
}

func (d *DenyAnyRole) IsExpired() bool {
	t := time.Time(d.Expires)
	return t.UnixNano() > 0 && t.Before(time.Now())
}
