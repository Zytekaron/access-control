package rss

import (
	"access-control/src/status"
)

// Terminal represents an access point which may be
// added to a group and/or given permission overwrites
type Terminal struct {
	ID string `json:"id"`

	// Group is the group that this Terminal belongs to,
	// which allows it to
	Group *Group

	// Overwrite is used to override the permissions
	// defined by the Group in specific circumstances
	Overwrite *Group

	// Permissions is a list of permissions that are
	// applied to this terminal that take precedence
	// over the group
	Permissions []Permission

	// Denied is a list of users that are not allowed to
	// clear, used as a temporary means of
	Denied []*User
}

func (t *Terminal) Clears(key *Key) *status.ClearStatus {
	if key == nil {
		return status.NewDeny("key is nil")
	}

	// when an overwrite is active, return its clear status
	// but replace Neutral with Deny as it was not Allow
	if t.Overwrite != nil {
		res := t.Overwrite.Clears(key)
		if res.Status == status.Neutral {
			// exception case for using deny: always last in the chain
			return status.NewDeny("denied by overwrite group '" + t.Overwrite.ID + "'")
		}
		return res
	}

	// allow if any of the permissions clear the key,
	// or, in exceptional cases, deny if any of the
	// permissions specify the key should be denied
	results := make([]*status.ClearStatus, len(t.Permissions))
	for i, perm := range t.Permissions {
		results[i] = perm.Clears(key)
		// deny immediately if the permission returns Deny
		if results[i].Status == status.Deny {
			return results[i]
		}
	}
	// allow here if any of the results are Allow
	for _, res := range results {
		if res.Status == status.Allow {
			return res
		}
	}

	// group checks take effect here
	if t.Group != nil {
		res := t.Group.Clears(key)
		if res.Status != status.Neutral {
			return res
		}
	}

	// exception case for using deny: always last in the chain
	return status.NewDeny("no terminal permission clears")
}
