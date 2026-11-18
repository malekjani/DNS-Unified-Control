// Package bond contains the experimental DUC multipath frame and reassembly primitives.
// Its wire format is NOT stable and it must not be exposed to untrusted networks.
package bond

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

const MaxPayload = 4096
const MaxReorderBytes = 4 << 20

// Frame is carried over an independent, reliable native DNS-engine TCP tunnel.
// Offsets are logical byte-stream positions, not per-path TCP sequence numbers.
type Frame struct {
	Type    byte
	Offset  uint64
	Payload []byte
}

func WriteFrame(w io.Writer, f Frame) error {
	if len(f.Payload) > MaxPayload {
		return fmt.Errorf("frame payload exceeds %d bytes", MaxPayload)
	}
	if f.Type != 'H' && f.Type != 'R' && f.Type != 'D' && f.Type != 'F' && f.Type != 'E' {
		return errors.New("invalid frame type")
	}
	if f.Type == 'D' && len(f.Payload) == 0 {
		return errors.New("empty data frame")
	}
	var hdr [11]byte
	hdr[0] = f.Type
	binary.BigEndian.PutUint64(hdr[1:9], f.Offset)
	binary.BigEndian.PutUint16(hdr[9:11], uint16(len(f.Payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(f.Payload) == 0 {
		return nil
	}
	_, err := w.Write(f.Payload)
	return err
}

func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [11]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := int(binary.BigEndian.Uint16(hdr[9:11]))
	if n > MaxPayload {
		return Frame{}, errors.New("oversized frame")
	}
	f := Frame{Type: hdr[0], Offset: binary.BigEndian.Uint64(hdr[1:9])}
	if f.Type != 'H' && f.Type != 'R' && f.Type != 'D' && f.Type != 'F' && f.Type != 'E' {
		return Frame{}, errors.New("invalid frame type")
	}
	if n > 0 {
		f.Payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return Frame{}, err
		}
	}
	return f, nil
}

// OrderedReceiver implements bounded out-of-order buffering across several paths.
// All Push calls (one per incoming path) serialize output writes.
type OrderedReceiver struct {
	mu           sync.Mutex
	dest         io.Writer
	next         uint64
	pending      map[uint64][]byte
	pendingBytes int
	finishOffset *uint64
	finished     bool
	onFinish     func()
}

func NewOrderedReceiver(w io.Writer, onFinish func()) *OrderedReceiver {
	return &OrderedReceiver{dest: w, pending: make(map[uint64][]byte), onFinish: onFinish}
}
func (r *OrderedReceiver) Next() uint64 { r.mu.Lock(); defer r.mu.Unlock(); return r.next }
func (r *OrderedReceiver) Push(f Frame) error {
	if f.Type != 'D' && f.Type != 'F' {
		return errors.New("unexpected frame for receiver")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished {
		return errors.New("data after FIN")
	}
	if f.Type == 'F' {
		if len(f.Payload) != 0 {
			return errors.New("FIN carries payload")
		}
		if f.Offset < r.next {
			return errors.New("FIN before delivered bytes")
		}
		if r.finishOffset != nil && *r.finishOffset != f.Offset {
			return errors.New("conflicting FIN offsets")
		}
		v := f.Offset
		r.finishOffset = &v
	} else {
		end := f.Offset + uint64(len(f.Payload))
		if end < f.Offset {
			return errors.New("offset overflow")
		}
		if f.Offset < r.next {
			return errors.New("duplicate or overlapping delivered frame")
		}
		if r.finishOffset != nil && end > *r.finishOffset {
			return errors.New("data exceeds FIN")
		}
		if len(f.Payload) == 0 {
			return errors.New("empty DATA")
		}
		if _, exists := r.pending[f.Offset]; exists {
			return errors.New("duplicate frame")
		}
		if len(f.Payload)+r.pendingBytes > MaxReorderBytes {
			return errors.New("reorder buffer exhausted")
		}
		// Reject overlapping queued segments, not just equal starting offsets.
		for off, b := range r.pending {
			if f.Offset < off+uint64(len(b)) && off < end {
				return errors.New("overlapping queued frames")
			}
		}
		r.pending[f.Offset] = append([]byte(nil), f.Payload...)
		r.pendingBytes += len(f.Payload)
	}
	for {
		b, ok := r.pending[r.next]
		if !ok {
			break
		}
		// A short write is a failure: never silently mark bytes as delivered.
		n, err := r.dest.Write(b)
		if err != nil {
			return err
		}
		if n != len(b) {
			return io.ErrShortWrite
		}
		delete(r.pending, r.next)
		r.next += uint64(len(b))
		r.pendingBytes -= len(b)
	}
	if r.finishOffset != nil && *r.finishOffset == r.next {
		r.finished = true
		if r.onFinish != nil {
			r.onFinish()
		}
	}
	return nil
}
