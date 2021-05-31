package perms

import (
	"access-control/src/rss"
	"access-control/src/status"
	"access-control/src/types"
	"time"
)

// AllowKeys clears a key when it is in the list of allowed keys
type AllowKeys struct {
	// Keys are the keys required to clear the key
	Keys []string `json:"keys"`

	// Expires is when this permission no longer applies
	Expires types.JsonTime `json:"expires"`
}

func (a *AllowKeys) Clears(key *rss.Key) *status.ClearStatus {
	if a.IsExpired() {
		return status.NewNeutral()
	}
	for _, k := range a.Keys {
		if key.HasRole(k) {
			return status.NewAllow("allow_keys allows access via key: " + k)
		}
	}
	return status.NewNeutral()
}

func (a *AllowKeys) IsExpired() bool {
	t := time.Time(a.Expires)
	return t.UnixNano() > 0 && t.Before(time.Now())
}
