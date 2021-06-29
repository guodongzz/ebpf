// Program bpf2go embeds eBPF in Go.
//
// It compiles a C source file into eBPF bytecode and then emits a
// Go file containing the eBPF and some scaffolding.
//
// Requires at least clang 9. For a full list of accepted options check the
// `-help` output.
package main
