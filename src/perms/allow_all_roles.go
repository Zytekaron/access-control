package perms

import (
	"access-control/src/rss"
	"access-control/src/status"
	"access-control/src/types"
	"strings"
	"time"
)

// AllowAllRoles clears a key when it or the keyholder possess all of the given roles
type AllowAllRoles struct {
	// Roles are the roles required to clear the key
	Roles []string `json:"roles"`

	// Expires is when this permission no longer applies
	Expires types.JsonTime `json:"expires"`
}

func (a *AllowAllRoles) Clears(key *rss.Key) *status.ClearStatus {
	if a.IsExpired() {
		return status.NewNeutral()
	}
	for _, role := range a.Roles {
		if !key.HasRole(role) {
			return status.NewNeutral()
		}
	}
	return status.NewAllow("allow_all_roles permits access via roles: " + strings.Join(a.Roles, ", "))
}

func (a *AllowAllRoles) IsExpired() bool {
	t := time.Time(a.Expires)
	return t.UnixNano() > 0 && t.Before(time.Now())
}
