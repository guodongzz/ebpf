package main

import (
	"testing"
	"unsafe"

	// Raise RLIMIT_MEMLOCK
	_ "github.com/cilium/ebpf/internal/testutils"
)

func TestLoadingSpec(t *testing.T) {
	spec, err := loadExample()
	if err != nil {
		t.Fatal("Can't load spec:", err)
	}

	if spec == nil {
		t.Fatal("Got a nil spec")
	}
}

func TestLoadingObjects(t *testing.T) {
	consts := exampleConstants{
		MyConstant: 1,
		StructConst: exampleBarfoo{
			Bar: 2,
		},
	}

	var objs exampleObjects
	if err := loadExampleObjects(&objs, &consts, nil); err != nil {
		t.Fatal("Can't load objects:", err)
	}
	defer objs.Close()

	if objs.Filter == nil {
		t.Error("Loading returns an object with nil programs")
	}

	if ret, _, err := objs.Filter.Test(make([]byte, 14)); err != nil {
		t.Fatal(err)
	} else if ret != 1+2 {
		t.Errorf("Expected the program to return 3, got %v. Broken constants?", ret)
	}

	if objs.Map1 == nil {
		t.Error("Loading returns an object with nil maps")
	}
}

func TestConstants(t *testing.T) {
	if exampleEHOOPY != 0 {
		t.Error("Expected exampleEHOOPY to be 0, got", exampleEHOOPY)
	}
	if exampleEFROOD != 1 {
		t.Error("Expected exampleEFROOD to be 0, got", exampleEFROOD)
	}

	if size := unsafe.Sizeof(exampleE(0)); size != 4 {
		t.Error("Expected size of exampleE to be 4, got", size)
	}
	if size := unsafe.Sizeof(exampleBarfoo{}); size != 16 {
		t.Error("Expected size of exampleE to be 16, got", size)
	}

	var c exampleConstants
	_ = c.MyConstant
	_ = c.StructConst.Bar
	_ = c.StructConst.Baz
}
