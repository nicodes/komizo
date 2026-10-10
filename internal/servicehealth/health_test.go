package servicehealth

import "testing"

func TestRequiredHealthAndCompletedInitialization(t *testing.T) {
	checked := Desired{Healthcheck: &Healthcheck{Test: []string{"CMD", "health"}}}
	for _, tc := range []struct {
		service Desired
		state   string
		exit    int
		health  string
		want    bool
	}{
		{Desired{}, "running", 0, "", true},
		{checked, "running", 0, "", false},
		{checked, "running", 0, "starting", false},
		{checked, "running", 0, "unhealthy", false},
		{checked, "running", 0, "healthy", true},
		{Desired{Restart: "no"}, "exited", 0, "", true},
		{Desired{Restart: "no"}, "exited", 1, "", false},
		{Desired{Restart: "unless-stopped"}, "exited", 0, "", false},
	} {
		if got := Ready(tc.service, tc.state, tc.exit, tc.health); got != tc.want {
			t.Fatalf("%+v: %v", tc, got)
		}
	}
}
