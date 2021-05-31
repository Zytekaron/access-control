package rss

import (
	"access-control/src/status"
)

// Group represents a collection of permission overwrites and a parent
type Group struct {
	Parent *Group `json:"parent,omitempty"`

	ID string `json:"id"`

	// Overwrite is used to override all the permissions
	// defined by this Group in specific circumstances
	Overwrite *Group

	// Permissions is the list of permissions that
	// are checked to see whether they clear the key
	Permissions []Permission `json:"permissions"`

	// Denied is a list of users that are not allowed to
	// clear, used as a temporary means of
	Denied []*User `json:"denied"`
}

// Clears checks if a user has permission via this group to
// access the terminal before lockdown and release checks
func (g *Group) Clears(key *Key) *status.ClearStatus {
	// check for key and user validity
	if v := key.IsValid(); v.Status == status.Deny {
		return v.Call("g:" + g.ID)
	}

	if res := g.isDenied(key); res.Status == status.Deny {
		return res.Call("g:" + g.ID)
	}

	// check this and all parent group permissions
	return g.recursiveClears(key)
}

// Traverse the current and any parent groups, checking
// for permissions which clear the user
func (g *Group) recursiveClears(key *Key) *status.ClearStatus {
	if key == nil {
		return status.NewDeny("key is nil")
	}

	// when an overwrite is active, return its clear status
	if g.Overwrite != nil {
		return g.Overwrite.Clears(key).Call("g:" + g.ID)
	}

	// allow if any of the permissions clear the key,
	// or, in exceptional cases, deny if any of the
	// permissions specify the key should be denied
	results := make([]*status.ClearStatus, len(g.Permissions))
	for i, perm := range g.Permissions {
		results[i] = perm.Clears(key)
		// deny immediately if the permission returns Deny
		if results[i].Status == status.Deny {
			return results[i].Call("g:" + g.ID)
		}
	}
	// allow here if any of the results are Allow
	for _, res := range results {
		if res.Status == status.Allow {
			return res.Call("g:" + g.ID)
		}
	}

	// parent permissions take effect here
	if g.Parent != nil {
		return g.Parent.Clears(key).Call("g:" + g.ID)
	}

	// no further parents
	return status.NewNeutral()
}

// Check if a user is denied from this group
func (g *Group) isDenied(key *Key) *status.ClearStatus {
	if containsUser(g.Denied, key.Owner) {
		return status.NewDeny("user is in denied list of group: " + g.ID)
	}
	if g.Parent != nil {
		return g.Parent.isDenied(key)
	}
	return status.NewNeutral()
}

func containsUser(users []*User, user *User) bool {
	for _, u := range users {
		if u.ID == user.ID {
			return true
		}
	}
	return false
}
