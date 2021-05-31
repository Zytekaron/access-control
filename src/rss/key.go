package rss

import (
	"access-control/src/status"
	"access-control/src/types"
	"time"
)

type Key struct {
	ID string `json:"id"`

	// The owner of this key
	Owner *User `json:"owner"`

	// The roles that belong to this key
	Roles []string `json:"roles"`

	// Whether this key is disabled
	Disabled bool `json:"disabled"`

	// The time when this key expires
	Expires types.JsonTime `json:"expires"`
}

// IsValid checks whether this key is valid or not
// The owner and keys status are taken into account
func (k *Key) IsValid() *status.ClearStatus {
	if v := k.Owner.IsValid(); v.Status == status.Deny {
		return v
	}
	if time.Time(k.Expires).Before(time.Now()) {
		return status.NewDeny("key is expired").Call("k:" + k.ID)
	}
	if k.Disabled {
		return status.NewDeny("key is disabled").Call("k:" + k.ID)
	}
	return status.NewNeutral()
}

// HasRole checks whether this key or the owner has a role
func (k *Key) HasRole(id string) bool {
	for _, r := range k.Roles {
		if r == id {
			return true
		}
	}
	return k.Owner.HasRole(id)
}
