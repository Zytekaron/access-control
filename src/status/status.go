package status

type Status int8

const (
	// Allow means the permission is allowed
	// by something but may be overwritten further
	// down the chain
	Allow Status = 1
	// Neutral means the permission status is not
	// specified in the place it was returned from
	Neutral Status = 0
	// Deny means the permission is denied
	// by something and should not be overridden
	Deny Status = -1
)

type ClearStatus struct {
	Status Status `json:"status"`
	Reason string `json:"reason,omitempty"`
}

func NewAllow(reason string) *ClearStatus {
	return &ClearStatus{
		Status: Allow,
		Reason: reason,
	}
}

func NewNeutral() *ClearStatus {
	return &ClearStatus{
		Status: Neutral,
	}
}

func NewDeny(reason string) *ClearStatus {
	return &ClearStatus{
		Status: Deny,
		Reason: reason,
	}
}

func (c *ClearStatus) Call(id string) *ClearStatus {
	if c.Status != Neutral {
		c.Reason = id + ": " + c.Reason
	}
	return c
}
