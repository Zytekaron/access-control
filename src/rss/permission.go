package rss

import "access-control/src/status"

// Permission is an interface for permissions which
// determine whether a key clears based on its settings,
// such as a permission which returns status.Allow only
// when the key or the keyholder possess a certain role
//
// Permissions should only return status.Deny when they
// need to restrict the terminal in exceptional cases
type Permission interface {
	// Clears returns whether the permission allows a given key
	// to access the group or terminal to which it is applied
	Clears(*Key) *status.ClearStatus
}
