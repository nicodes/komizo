package app

import (
	"time"

	"github.com/nicodes/komizo/internal/box"
)

// Building the rows the screens draw, the way production builds them.
//
// Every fixture here goes through inventoryFromReport rather than assembling an
// appRow by hand. That is the point: the adapter is the only path a real box's
// facts take to the screen, so a test that skipped it would keep passing while
// the thing it describes stopped working -- which is exactly what happened to
// the tests these replace, which parsed a wire format by hand.

// invOf builds the inventory a report produces.
func invOf(r box.Report) inventory { return inventoryFromReport(r) }

// readyBoxReport is one healthy box: two apps, a proxy, a shared network.
//
// A function rather than a package-level value so a test can mutate what it
// gets without the next test inheriting it.
func readyBoxReport() box.Report {
	started := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	return box.Report{
		V:  box.Version,
		At: time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC),
		Server: box.Server{
			State:  "ready",
			Docker: "Docker version 26",
			OS:     "Alpine Linux v3.20",
			Komizo: box.KomizoInstall{Installed: true, Version: "0.0.12", Stamp: "abc123", Agent: "0.0.12"},
		},
		Apps: []box.App{
			{
				Name: "blog", User: "komizo-blog", Dir: "/srv/blog",
				Version: "a1b2", ConfigImage: "ghcr.io/you/blog-config",
				Hosts: []box.Host{{Name: "blog.example.com", Service: "web"}},
				Containers: []box.Container{
					{Service: "web", Name: "blog-web-1", State: "running", Status: "Up 3 hours",
						Image: "ghcr.io/you/blog:a1b2", StartedAt: started, Ports: []int{80}},
				},
			},
			{
				Name: "shop", User: "komizo-shop", Dir: "/srv/shop",
				Version: "c3d4", ConfigImage: "ghcr.io/you/shop-config",
				Hosts: []box.Host{{Name: "shop.example.com"}},
				Containers: []box.Container{
					{Service: "web", Name: "shop-web-1", State: "exited", Status: "Exited (1) 2 minutes ago",
						Image: "ghcr.io/you/shop:c3d4", FinishedAt: started, ExitCode: 1},
				},
			},
		},
		Proxy: &box.Proxy{State: "running", Network: "edge", Image: "caddy:2", Status: "Up 3 hours", StartedAt: started},
		Network: &box.Network{
			Name: "edge", Driver: "bridge", Subnet: "172.18.0.0/16",
			Members: []box.NetworkMember{
				{Container: "komizo-proxy", Aliases: []string{"komizo-proxy"}},
				{Container: "blog-web-1", Aliases: []string{"web", "blog-web"}},
			},
		},
	}
}

// oneApp is the smallest useful report: a ready box with a single app.
func oneApp(a box.App) box.Report {
	return box.Report{
		V:      box.Version,
		At:     time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC),
		Server: box.Server{State: "ready", Docker: "Docker version 26"},
		Apps:   []box.App{a},
	}
}

// --- readings ---------------------------------------------------------------
//
// The history the charts are drawn from. Built as box.Samples and run through
// samplesFrom, so what a test charts is what an agent would actually have sent.

// sample is one timestamped reading.
func sample(ts int64, sys box.System) box.Sample {
	return box.Sample{At: time.Unix(ts, 0).UTC(), System: sys}
}

// histOf is a run of readings, as the charts take them.
func histOf(ss ...box.Sample) []sysSample { return samplesFrom(ss) }

// u64 is a pointer to a value, for the report fields where absent and zero are
// different answers.
func u64(n uint64) *uint64 { return &n }

func cpuOf(total, idle uint64) *box.CPU { return &box.CPU{Total: total, Idle: idle} }
func memOf(total, used uint64) *box.Mem { return &box.Mem{Total: total, Used: used} }

func diskOf(mount, dev string, used, size uint64) box.Disk {
	return box.Disk{Mount: mount, Dev: dev, Used: used, Size: size}
}

// cstatOf is one container's reading. Values are given, not absent -- a test
// that wants "unreadable" builds the zero ContainerStat instead, because an
// absent value and a zero are the distinction most of these tests exist for.
func cstatOf(app, svc string, cpuUsec, mem uint64) box.ContainerStat {
	return box.ContainerStat{App: app, Service: svc, CPUUsec: &cpuUsec, Mem: &mem}
}

func volOf(app, svc, name string, bytes uint64) box.Volume {
	return box.Volume{App: app, Service: svc, Name: name, Bytes: bytes}
}

// metricsOf builds the chart rows a set of counts produces.
func metricsOf(rows ...box.Metric) []metricRow {
	return metricsFromBox(box.Metrics{Rows: rows})
}
