package main

import (
	"testing"

	"github.com/cilium/ebpf/internal/btf"
	"github.com/google/go-cmp/cmp"
)

func TestIdentifier(t *testing.T) {
	testcases := []struct {
		in, out string
	}{
		{".rodata", "Rodata"},
		{"_foo_bar_", "FooBar"},
		{"ipv6_test", "Ipv6Test"},
		{"FOO_BAR", "FOO_BAR"},
		{"FOO_", "FOO_"},
		{"FOO__BAR", "FOO__BAR"},
		{"FOO___BAR", "FOO___BAR"},
		{"_FOO__BAR", "FOO__BAR"},
		{"__FOO__BAR", "FOO__BAR"},
	}

	for _, tc := range testcases {
		have := identifier(tc.in)
		if have != tc.out {
			t.Errorf("Expected %q as output of %q, got %q", tc.out, tc.in, have)
		}
	}
}

func TestGlobalVarTypes(t *testing.T) {
	i32 := &btf.Int{Size: 4}
	tdi32 := &btf.Typedef{Name: "__s32", Type: i32}

	ds := &btf.Datasec{
		Vars: []btf.VarSecinfo{
			{Type: &btf.Var{Name: "a", Type: i32, Linkage: btf.GlobalVar}},
			{Type: &btf.Var{Name: "a1", Type: i32, Linkage: btf.GlobalVar}},
			{Type: &btf.Var{Name: "b", Type: tdi32, Linkage: btf.GlobalVar}},
			{Type: &btf.Var{Name: "s_a", Type: i32, Linkage: btf.StaticVar}},
			{Type: &btf.Var{Name: "e_b", Type: tdi32, Linkage: btf.ExternVar}},
		},
	}

	want := []btf.Type{i32, tdi32}

	have, err := globalVarTypes(ds)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, have); diff != "" {
		t.Errorf("Result mismatch (-want +got):\n%s", diff)
	}
}

func TestNamedTypes(t *testing.T) {
	i32 := &btf.Int{Name: "int", Size: 4}
	tdi32 := &btf.Typedef{Name: "__s32", Type: i32}
	tdtdi32 := &btf.Typedef{Name: "__s32", Type: tdi32}
	e1 := &btf.Enum{Name: "e1"}
	tde1 := &btf.Typedef{Name: "__e1", Type: e1}
	tdtde1 := &btf.Typedef{Name: "__e2", Type: tde1}
	arr := &btf.Array{Nelems: 1, Type: i32}
	tdarr := &btf.Typedef{Name: "__arr", Type: &btf.Array{Nelems: 1, Type: tdi32}}

	want := []btf.NamedType{
		e1,
		tde1,
		tdtde1,
		tdarr,
	}

	have, err := namedTypes([]btf.Type{
		i32,
		tdi32,
		tdtdi32,
		e1,
		tde1,
		tdtde1,
		arr,
		tdarr,
	})
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, have); diff != "" {
		t.Errorf("Result mismatch (-want +got):\n%s", diff)
	}
}
