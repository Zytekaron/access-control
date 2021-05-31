package perms

import (
	"access-control/src/rss"
	"access-control/src/status"
	"access-control/src/types"
	"time"
)

// AllowLevel clears a key when the owner's level meets or exceeds the requirement
type AllowLevel struct {
	// Level is the level required to clear
	Level uint32 `json:"level"`

	// Expires is when this permission no longer applies
	Expires types.JsonTime `json:"expires"`
}

func (a *AllowLevel) Clears(key *rss.Key) *status.ClearStatus {
	if a.IsExpired() {
		return status.NewNeutral()
	}
	if key.Owner.Level >= a.Level {
		return status.NewAllow("allow_keys allows access via level")
	}
	return status.NewNeutral()
}

func (a *AllowLevel) IsExpired() bool {
	t := time.Time(a.Expires)
	return t.UnixNano() > 0 && t.Before(time.Now())
}
