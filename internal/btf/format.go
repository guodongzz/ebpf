package btf

import (
	"errors"
	"fmt"
	"strings"
)

var errNestedTooDeep = errors.New("nested too deep")

type GoFormatter struct {
	w     strings.Builder
	names map[Type]string

	// Identifier is called for each field of struct-like types. By default the
	// field name is used as is.
	Identifier func(string) string
}

// NewGoFormatter creates a new GoFormatter.
//
// Types present in names are referred to using the given name in generated
// output.
func NewGoFormatter(names map[Type]string) *GoFormatter {
	return &GoFormatter{
		names:      names,
		Identifier: func(s string) string { return s },
	}
}

// TypeDeclaration generates a Go type declaration for a BTF type.
func (gf *GoFormatter) TypeDeclaration(name string, typ Type) (string, error) {
	gf.w.Reset()
	if err := gf.writeTypeDecl(name, typ); err != nil {
		return "", err
	}
	return gf.w.String(), nil
}

// writeTypeDecl outputs a declaration of the given type.
//
// It encodes https://golang.org/ref/spec#Type_declarations:
//
//     type foo struct { bar uint32; }
//     type bar int32
func (gf *GoFormatter) writeTypeDecl(name string, typ Type) error {
	if name == "" {
		return fmt.Errorf("need a name for type %s", typ)
	}

	typ, err := SkipQualifiers(typ)
	if err != nil {
		return err
	}

	switch v := typ.(type) {
	case *Enum:
		fmt.Fprintf(&gf.w, "type %s int32", name)
		if len(v.Values) == 0 {
			return nil
		}

		gf.w.WriteString("; const ( ")
		for _, ev := range v.Values {
			id := gf.Identifier(ev.Name)
			fmt.Fprintf(&gf.w, "%s%s %s = %d; ", name, id, name, ev.Value)
		}
		gf.w.WriteString(")")

		return nil
	}

	fmt.Fprintf(&gf.w, "type %s ", name)
	return gf.writeTypeLit(typ, 0)
}

// writeType outputs the name of a named type or a literal describing the type.
//
// It encodes https://golang.org/ref/spec#Types.
//
//     foo                  (if foo is a named type)
//     uint32
func (gf *GoFormatter) writeType(typ Type, depth int) error {
	typ, err := SkipQualifiers(typ)
	if err != nil {
		return err
	}

	name := gf.names[typ]
	if name != "" {
		gf.w.WriteString(name)
		return nil
	}

	return gf.writeTypeLit(typ, depth)
}

// writeTypeLit outputs a literal describing the type.
//
// The function ignores named types.
//
// It encodes https://golang.org/ref/spec#TypeLit.
//
//     struct { bar uint32; }
//     uint32
func (gf *GoFormatter) writeTypeLit(typ Type, depth int) error {
	depth++
	if depth > maxTypeDepth {
		return errNestedTooDeep
	}

	typ, err := SkipQualifiers(typ)
	if err != nil {
		return err
	}

	switch v := typ.(type) {
	case *Int:
		gf.writeIntLit(v)

	case *Enum:
		gf.w.WriteString("int32")

	case *Typedef:
		err = gf.writeType(v.Type, depth)

	case *Array:
		fmt.Fprintf(&gf.w, "[%d]", v.Nelems)
		err = gf.writeType(v.Type, depth)

	case *Struct:
		err = gf.writeStructLit(v.Size, v.Members, depth)

	case *Union:
		// Always choose the first member to repesent the union in Go.
		err = gf.writeStructLit(v.Size, v.Members[:1], depth)

	case *Datasec:
		err = gf.writeDatasecLit(v, depth)

	default:
		return fmt.Errorf("type %s: %w", typ, ErrNotSupported)
	}

	if err != nil {
		return fmt.Errorf("%s: %w", typ, err)
	}

	return nil
}

func (gf *GoFormatter) writeIntLit(i *Int) {
	// NB: Encoding.IsChar is ignored.
	if i.Encoding.IsBool() && i.Size == 1 {
		gf.w.WriteString("bool")
		return
	}

	bits := i.Size * 8
	if i.Encoding.IsSigned() {
		fmt.Fprintf(&gf.w, "int%d", bits)
	} else {
		fmt.Fprintf(&gf.w, "uint%d", bits)
	}
}

func (gf *GoFormatter) writeStructLit(size uint32, members []Member, depth int) error {
	gf.w.WriteString("struct { ")

	prevOffset := uint32(0)
	for i, m := range members {
		if m.Name == "" {
			return fmt.Errorf("field %d: anonymous fields are not supported", i)
		}
		if m.BitfieldSize > 0 {
			return fmt.Errorf("field %d: bitfields are not supported", i)
		}
		if m.Offset%8 != 0 {
			return fmt.Errorf("field %d: unsupported offset %d", i, m.Offset)
		}

		size, err := Sizeof(m.Type)
		if err != nil {
			return fmt.Errorf("field %d: %w", i, err)
		}

		offset := m.Offset / 8
		gf.writePadding(offset - prevOffset)
		prevOffset = offset + uint32(size)

		fmt.Fprintf(&gf.w, "%s ", gf.Identifier(m.Name))

		if err := gf.writeType(m.Type, depth); err != nil {
			return fmt.Errorf("field %d: %w", i, err)
		}

		gf.w.WriteString("; ")
	}

	gf.writePadding(size - prevOffset)
	gf.w.WriteString("}")
	return nil
}

func (gf *GoFormatter) writeDatasecLit(ds *Datasec, depth int) error {
	gf.w.WriteString("struct { ")

	prevOffset := uint32(0)
	for i, vsi := range ds.Vars {
		v := vsi.Type.(*Var)
		if v.Linkage != GlobalVar {
			// Ignore static, extern, etc. for now.
			continue
		}

		if v.Name == "" {
			return fmt.Errorf("variable %d: empty name", i)
		}

		gf.writePadding(vsi.Offset - prevOffset)
		prevOffset = vsi.Offset + vsi.Size

		fmt.Fprintf(&gf.w, "%s ", gf.Identifier(v.Name))

		if err := gf.writeType(v.Type, depth); err != nil {
			return fmt.Errorf("variable %d: %w", i, err)
		}

		gf.w.WriteString("; ")
	}

	gf.writePadding(ds.Size - prevOffset)
	gf.w.WriteString("}")
	return nil
}

func (gf *GoFormatter) writePadding(bytes uint32) {
	if bytes > 0 {
		fmt.Fprintf(&gf.w, "_ [%d]byte; ", bytes)
	}
}
