package rss

import "access-control/src/status"

// User represents a keyholder with other
// information such as their access level
type User struct {
	ID string `json:"id"`

	// Level represents the permission level
	// of a user. Default is zero.
	Level uint32 `json:"level"`

	// Roles represents the roles that this
	// user has, which are read by permissions
	Roles []string `json:"roles"`

	// Disabled determines whether the user
	// is allowed to access ANY terminal
	Disabled bool `json:"disabled"`
}

// IsValid checks whether this key is valid or not.
// The owner and keys status are taken into account.
func (u *User) IsValid() *status.ClearStatus {
	if u.Disabled {
		return status.NewDeny("user is disabled").Call("u:" + u.ID)
	}
	return status.NewNeutral()
}

// HasRole checks whether this user has a role
func (u *User) HasRole(id string) bool {
	for _, r := range u.Roles {
		if r == id {
			return true
		}
	}
	return false
}
