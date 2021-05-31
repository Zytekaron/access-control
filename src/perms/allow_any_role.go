package perms

import (
	"access-control/src/rss"
	"access-control/src/status"
	"access-control/src/types"
	"time"
)

// AllowAnyRole clears a key when it or the keyholder possess any of the given roles
type AllowAnyRole struct {
	// Roles are the roles used to clear the key
	Roles []string `json:"roles"`

	// Expires is when this permission no longer applies
	Expires types.JsonTime `json:"expires"`
}

func (a *AllowAnyRole) Clears(key *rss.Key) *status.ClearStatus {
	if a.IsExpired() {
		return status.NewNeutral()
	}
	for _, role := range a.Roles {
		if key.HasRole(role) {
			return status.NewAllow("allow_any_role permits access via role: " + role)
		}
	}
	return status.NewNeutral()
}

func (a *AllowAnyRole) IsExpired() bool {
	t := time.Time(a.Expires)
	return t.UnixNano() > 0 && t.Before(time.Now())
}
