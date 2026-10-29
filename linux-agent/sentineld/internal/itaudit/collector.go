package itaudit

import (
	"fmt"
	"sort"
	"time"
)

// collectorFn is one category's collection logic — returns rows or an error. Panics are
// recovered by runCategory, not by each collectorFn.
type collectorFn func() ([]Row, error)

// registry maps category name -> collector. Order matches the design plan §5.1 table (Windows
// FORENSICS_KINDS order, browser_ext dropped as not applicable to headless servers) followed by
// the Linux-native additions with no Windows parallel.
var registry = []struct {
	name string
	fn   collectorFn
}{
	{"processes", collectProcesses},
	{"services", collectServices},
	{"scheduled_jobs", collectScheduledJobs},
	{"persistence", collectPersistence},
	{"net", collectNet},
	{"users", collectUsers},
	{"software", collectSoftware},
	{"security", collectSecurity},
	{"kernel_modules", collectKernelModules},
	{"hosts", collectHosts},
	{"package_integrity", collectPackageIntegrity},
	{"fileless_persistence", collectFilelessPersistence},
	{"auth_events", collectAuthEvents},
	// Linux-native additions — no Windows FORENSICS_KINDS parallel, see plan §5.1.
	{"suid_sgid", collectSuidSgid},
	{"world_writable", collectWorldWritable},
	{"hidden_process_check", collectHiddenProcessCheck},
	{"immutable_attrs", collectImmutableAttrs},
	{"recently_modified_etc", collectRecentlyModifiedEtc},
}

// Kinds returns every collectible category name, in the order they run for "all".
func Kinds() []string {
	names := make([]string, 0, len(registry))
	for _, r := range registry {
		names = append(names, r.name)
	}
	return names
}

// Collect runs a single category (kind == one of Kinds()) or every category (kind == "all"),
// returning *Result or *AllResult respectively (both JSON-marshalable). Unknown kinds return a
// *Result with OK:false and a descriptive Error — never a Go error/panic, so a caller driving
// this over Hop-2 always gets parseable JSON on stdout (design plan §3 "lesson 6").
func Collect(kind string) any {
	if kind == "all" || kind == "" {
		return collectAll()
	}
	for _, r := range registry {
		if r.name == kind {
			return runCategory(r.name, r.fn)
		}
	}
	return &Result{
		OK:             false,
		Kind:           kind,
		CollectedAtUTC: time.Now().UTC(),
		Hostname:       hostname(),
		Error:          fmt.Sprintf("unknown kind %q — choose one of: %v", kind, Kinds()),
	}
}

func collectAll() *AllResult {
	out := &AllResult{
		OK:             true,
		Kind:           "all",
		CollectedAtUTC: time.Now().UTC(),
		Hostname:       hostname(),
		Kinds:          make(map[string]Result, len(registry)),
		KindOrder:      Kinds(),
	}
	for _, r := range registry {
		res := runCategory(r.name, r.fn)
		out.Kinds[r.name] = *res
		if !res.OK {
			out.KindsFailed = append(out.KindsFailed, r.name)
			out.OK = false
		}
	}
	sort.Strings(out.KindsFailed)
	return out
}

// runCategory is the guaranteed-status-output wrapper: recovers a panic in fn and reports it as
// this category's Error, exactly like the top-level try/catch discipline the Windows Telemetry
// v2 rewrite adopted after a partial script failure once produced non-JSON stdout that looked
// like a silent, unexplained failure.
func runCategory(kind string, fn collectorFn) (res *Result) {
	res = &Result{Kind: kind, CollectedAtUTC: time.Now().UTC(), Hostname: hostname()}
	defer func() {
		if r := recover(); r != nil {
			res.OK = false
			res.Error = fmt.Sprintf("collector panicked: %v", r)
			res.Rows = nil
			res.Count = 0
		}
	}()

	rows, err := fn()
	if err != nil {
		res.OK = false
		res.Error = err.Error()
		res.Rows = rows // partial results are still useful — never discard what we got
		res.Count = len(rows)
		return res
	}
	res.OK = true
	res.Rows = rows
	res.Count = len(rows)
	return res
}
