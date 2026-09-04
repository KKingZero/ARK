package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	pb "github.com/KKingZero/ARK/pkg/pb"
)

// TestCTaskTypesMatchProto is the Sprint 0 contract: c2.proto TaskType is the
// single source of truth, and the generated C header must be a complete mirror.
func TestCTaskTypesMatchProto(t *testing.T) {
	root := repoRoot(t)
	protoTypes := parseProtoTaskTypes(t, filepath.Join(root, "proto", "c2.proto"))
	cTypes := parseCTaskTypes(t, filepath.Join(root, "cimplant", "include", "ark", "pb_task_types.h"))

	if len(protoTypes) == 0 {
		t.Fatal("no TaskType entries in proto/c2.proto")
	}
	if len(protoTypes) != len(cTypes) {
		t.Fatalf("proto has %d TaskType values, C header has %d — run make proto", len(protoTypes), len(cTypes))
	}
	for name, n := range protoTypes {
		got, ok := cTypes["ARK_"+name]
		if !ok {
			t.Errorf("C header missing ARK_%s", name)
			continue
		}
		if got != n {
			t.Errorf("ARK_%s = %d, proto %s = %d", name, got, name, n)
		}
	}
	for cname, n := range cTypes {
		protoName := strings.TrimPrefix(cname, "ARK_")
		want, ok := protoTypes[protoName]
		if !ok {
			t.Errorf("C header has %s but proto has no %s", cname, protoName)
			continue
		}
		if want != n {
			t.Errorf("%s = %d, proto %s = %d", cname, n, protoName, want)
		}
	}

	for name, n := range pb.TaskType_value {
		got, ok := cTypes["ARK_"+name]
		if !ok {
			t.Errorf("generated Go TaskType %s missing from C header", name)
			continue
		}
		if got != int(n) {
			t.Errorf("C ARK_%s=%d, generated Go %s=%d — run make proto", name, got, name, n)
		}
	}
}

// TestTypedModuleAdapterParity keeps the C executor table aligned with
// implant/tasks/modules.go (the Go reference adapter).
func TestTypedModuleAdapterParity(t *testing.T) {
	root := repoRoot(t)
	cRoutes := parseCTypedRoutes(t, filepath.Join(root, "cimplant", "src", "tasks", "executor.c"))
	goRoutes := parseGoTypedRoutes(t, filepath.Join(root, "implant", "tasks", "modules.go"))

	if len(goRoutes) == 0 {
		t.Fatal("no taskTypeModules entries in implant/tasks/modules.go")
	}
	if len(cRoutes) != len(goRoutes) {
		t.Fatalf("C adapter has %d typed routes, Go has %d", len(cRoutes), len(goRoutes))
	}
	for name, mod := range goRoutes {
		got, ok := cRoutes[name]
		if !ok {
			t.Errorf("Go maps %s -> %s but C adapter does not", name, mod)
			continue
		}
		if got != mod {
			t.Errorf("%s: C module %q, Go module %q", name, got, mod)
		}
	}
	for name, mod := range cRoutes {
		if _, ok := goRoutes[name]; !ok {
			t.Errorf("C adapter maps %s -> %s but Go taskTypeModules does not", name, mod)
		}
	}
}

// TestCatalogTaskTypesHaveCDisposition ensures catalog tools emit TaskTypes
// present in the C header, and dedicated module tools are in the C adapter.
func TestCatalogTaskTypesHaveCDisposition(t *testing.T) {
	root := repoRoot(t)
	cTypes := parseCTaskTypes(t, filepath.Join(root, "cimplant", "include", "ark", "pb_task_types.h"))
	cRoutes := parseCTypedRoutes(t, filepath.Join(root, "cimplant", "src", "tasks", "executor.c"))
	goRoutes := parseGoTypedRoutes(t, filepath.Join(root, "implant", "tasks", "modules.go"))

	for _, tool := range Catalog() {
		if tool.TaskType == pb.TaskType_TASK_UNKNOWN || tool.TaskType == 0 {
			continue
		}
		name := tool.TaskType.String()
		cname := "ARK_" + name
		n, ok := cTypes[cname]
		if !ok {
			t.Errorf("catalog tool %s emits %s which is missing from C pb_task_types.h", tool.Name, name)
			continue
		}
		if pb.TaskType(n) != tool.TaskType {
			t.Errorf("catalog tool %s: C %s=%d proto=%d", tool.Name, cname, n, tool.TaskType)
		}

		mod, dedicated := goRoutes[name]
		if !dedicated {
			continue
		}
		got, ok := cRoutes[name]
		if !ok {
			t.Errorf("catalog tool %s emits dedicated %s but C adapter has no route", tool.Name, name)
			continue
		}
		if got != mod {
			t.Errorf("catalog tool %s: C route %q, Go module %q", tool.Name, got, mod)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "proto", "c2.proto")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("cannot find proto/c2.proto from %s", wd)
	return ""
}

func parseProtoTaskTypes(t *testing.T, path string) map[string]int {
	t.Helper()
	body := readFile(t, path)
	block := regexp.MustCompile(`(?s)enum\s+TaskType\s*\{([^}]+)\}`).FindStringSubmatch(body)
	if len(block) < 2 {
		t.Fatalf("enum TaskType not found in %s", path)
		return nil
	}
	return parseNameEqualsInt(t, block[1], regexp.MustCompile(`(TASK_[A-Z0-9_]+)\s*=\s*(\d+)`))
}

func parseCTaskTypes(t *testing.T, path string) map[string]int {
	t.Helper()
	body := readFile(t, path)
	out := parseNameEqualsInt(t, body, regexp.MustCompile(`#define\s+(ARK_TASK_[A-Z0-9_]+)\s+(\d+)`))
	delete(out, "ARK_TASK_TYPE_MIN")
	delete(out, "ARK_TASK_TYPE_MAX")
	if len(out) == 0 {
		t.Fatalf("no ARK_TASK_* defines in %s — run make proto", path)
	}
	return out
}

func parseCTypedRoutes(t *testing.T, path string) map[string]string {
	t.Helper()
	body := readFile(t, path)
	re := regexp.MustCompile(`\{\s*ARK_(TASK_[A-Z0-9_]+)\s*,\s*ark_mod_([a-z0-9_]+)\s*\}`)
	out := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		out[m[1]] = m[2]
	}
	if len(out) == 0 {
		t.Fatalf("no typed-module routes in %s", path)
	}
	return out
}

func parseGoTypedRoutes(t *testing.T, path string) map[string]string {
	t.Helper()
	body := readFile(t, path)
	re := regexp.MustCompile(`pb\.TaskType_(TASK_[A-Z0-9_]+)\s*:\s*"([a-z0-9_]+)"`)
	out := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		out[m[1]] = m[2]
	}
	if len(out) == 0 {
		t.Fatalf("no taskTypeModules entries in %s", path)
	}
	return out
}

func parseNameEqualsInt(t *testing.T, body string, re *regexp.Regexp) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		n, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatalf("parse %s: %v", m[0], err)
		}
		out[m[1]] = n
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
