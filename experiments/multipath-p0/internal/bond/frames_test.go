package bond

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestOutOfOrderAcrossPaths(t *testing.T) {
	var b bytes.Buffer
	done := 0
	r := NewOrderedReceiver(&b, func() { done++ })
	for _, f := range []Frame{{'D', 5, []byte("world")}, {'F', 10, nil}, {'D', 0, []byte("hello")}} {
		if err := r.Push(f); err != nil {
			t.Fatal(err)
		}
	}
	if b.String() != "helloworld" || done != 1 || r.Next() != 10 {
		t.Fatalf("bad join: %q done=%d next=%d", b.String(), done, r.Next())
	}
}
func TestMalformedAndOverlap(t *testing.T) {
	var b bytes.Buffer
	r := NewOrderedReceiver(&b, nil)
	if err := r.Push(Frame{'D', 5, []byte("abc")}); err != nil {
		t.Fatal(err)
	}
	if err := r.Push(Frame{'D', 7, []byte("zz")}); err == nil {
		t.Fatal("overlap accepted")
	}
	if err := r.Push(Frame{'D', 4, []byte("hello")}); err == nil {
		t.Fatal("overlap accepted")
	}
	var p bytes.Buffer
	if err := WriteFrame(&p, Frame{'D', 1, []byte("hello")}); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(&p)
	if err != nil || f.Type != 'D' || f.Offset != 1 || string(f.Payload) != "hello" {
		t.Fatalf("roundtrip %+v %v", f, err)
	}
	var short [11]byte
	short[0] = 'D'
	binary.BigEndian.PutUint16(short[9:], MaxPayload+1)
	if _, err := ReadFrame(bytes.NewReader(short[:])); err == nil {
		t.Fatal("oversize accepted")
	}
	if _, err := ReadFrame(bytes.NewReader(nil)); err != io.EOF {
		t.Fatal(err)
	}
}
