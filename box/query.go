package box

// What one screen needs, in one document.
//
// Every read of a box costs an SSH connection, and the connection -- not the
// probing -- is the expensive part. So the shapes below are grouped by SCREEN
// rather than by subject: the poll wants the inventory and a sparkline window,
// the monitor wants a range of everything. Asking for them separately would
// double the connection rate against the server to draw a line that moves one
// column.
//
// These are envelopes, not new data. Every field is a type this package already
// defines and already versions, so grouping them differently later costs
// nothing.

// Poll is what the app list redraws from, every few seconds.
type Poll struct {
	V       int     `json:"v"`
	Report  Report  `json:"report"`
	Metrics Metrics `json:"metrics"`
}

func (p Poll) Schema() int { return p.V }

// Monitor is what the charts are drawn from, for one range.
type Monitor struct {
	V       int      `json:"v"`
	Metrics Metrics  `json:"metrics"`
	History []Sample `json:"history"`
	// Volumes is measured for ONE app, and only when asked. It costs a walk of
	// every volume that app mounts, which is the only number on that screen
	// that cannot be read from a counter.
	Volumes []Volume `json:"volumes,omitempty"`
}

func (m Monitor) Schema() int { return m.V }
