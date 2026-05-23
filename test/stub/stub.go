// Package stub provides a reflect-based method override queue for mock objects.
//
// Instead of one generic type per function signature, the internal mechanism
// uses a single queue of reflect-callable functions. Thin wrappers handle
// result extraction for common patterns:
//
//	StubE    — for methods returning (error)
//	StubRE   — for methods returning (R, error)
//	StubR    — for methods returning R
//	StubV    — for void methods (no return values)
//
// Usage in mock methods:
//
//	func (m *mockWorld) OsMkdirAll(path string, perm os.FileMode) error {
//	    return m.mkdirStub.Call(path, perm)
//	}
//
// Usage in tests:
//
//	t.World.mkdirStub.Fail(errWorldMkdir)         // return error
//	t.World.mkdirStub.Returns()                   // return nil (success)
//	t.World.mkdirStub.Default()                   // run default once
//	t.World.statStub.Returns(fi, nil)             // return (fi, nil)
//	t.World.statStub.Fail(errWorldBpftool)        // return (nil, err)
//	t.World.geteuidStub.Returns(1000)             // return 1000
package stub

import "reflect"

// ---------------------------------------------------------------------------
// Internal queue
// ---------------------------------------------------------------------------

type stubEntry struct {
	call func([]reflect.Value) []reflect.Value
}

type stub struct {
	queue   []stubEntry
	defCall func([]reflect.Value) []reflect.Value
}

func (s *stub) callNext(args []reflect.Value) []reflect.Value {
	e := s.queue[0]
	s.queue = s.queue[1:]
	return e.call(args)
}

func (s *stub) values(args ...any) []reflect.Value {
	r := make([]reflect.Value, len(args))
	for i, a := range args {
		r[i] = reflect.ValueOf(a)
	}
	return r
}

func (s *stub) len() int { return len(s.queue) }

// Default queues the default implementation for the next call.
func (s *stub) Default() { s.queue = append(s.queue, stubEntry{call: s.defCall}) }

func extractError(out []reflect.Value) error {
	if len(out) > 0 {
		if err, _ := out[len(out)-1].Interface().(error); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// StubE — for methods with signature f(args) error
// ---------------------------------------------------------------------------

// StubE provides override queues for methods returning (error).
type StubE struct{ stub }

// NewStubE creates a StubE with the given default implementation.
// The def argument must be a function matching f(args) error.
func NewStubE(def any) *StubE {
	return &StubE{stub: stub{defCall: reflect.ValueOf(def).Call}}
}

// Fail queues a handler that returns err and skips the default implementation.
func (s *StubE) Fail(err error) {
	s.queue = append(s.queue, stubEntry{
		call: func(_ []reflect.Value) []reflect.Value {
			return []reflect.Value{reflect.ValueOf(err)}
		},
	})
}

// Returns queues a handler that returns a nil error (success).
func (s *StubE) Returns() {
	s.queue = append(s.queue, stubEntry{
		call: func(_ []reflect.Value) []reflect.Value {
			return []reflect.Value{reflect.Zero(reflect.TypeFor[error]())}
		},
	})
}

// Call invokes the next queued handler with the given args,
// or falls back to the default implementation if the queue is empty.
func (s *StubE) Call(args ...any) error {
	if s.len() > 0 {
		return extractError(s.callNext(s.values(args...)))
	}
	return extractError(s.defCall(s.values(args...)))
}

// ---------------------------------------------------------------------------
// StubRE — for methods with signature f(args) (R, error)
// ---------------------------------------------------------------------------

// StubRE provides override queues for methods returning (R, error).
type StubRE[R any] struct {
	stub
	resultZero reflect.Value
}

// NewStubRE creates a StubRE with the given default implementation.
// The def argument must be a function matching f(args) (R, error).
func NewStubRE[R any](def any) StubRE[R] {
	var z R
	return StubRE[R]{
		stub:       stub{defCall: reflect.ValueOf(def).Call},
		resultZero: reflect.ValueOf(&z).Elem(),
	}
}

// Fail queues a handler that returns (zero, err).
func (s *StubRE[R]) Fail(err error) {
	s.queue = append(s.queue, stubEntry{
		call: func(_ []reflect.Value) []reflect.Value {
			return []reflect.Value{s.resultZero, reflect.ValueOf(err)}
		},
	})
}

// Returns queues a handler that returns the given values.
// It expects exactly 2 values: (result, error).
// A nil error is replaced with a nil error interface.
func (s *StubRE[R]) Returns(vals ...any) {
	if len(vals) != 2 {
		panic("StubRE.Returns expects exactly 2 values: (result, error)")
	}
	out := make([]reflect.Value, 2)
	for i, v := range vals {
		if v == nil {
			if i == 0 {
				out[i] = s.resultZero
			} else {
				out[i] = reflect.Zero(reflect.TypeFor[error]())
			}
		} else {
			out[i] = reflect.ValueOf(v)
		}
	}
	s.queue = append(s.queue, stubEntry{
		call: func(_ []reflect.Value) []reflect.Value { return out },
	})
}

// Call invokes the next queued handler with the given args,
// or falls back to the default implementation if the queue is empty.
func (s *StubRE[R]) Call(args ...any) (R, error) {
	var r R
	var out []reflect.Value
	if s.len() > 0 {
		out = s.callNext(s.values(args...))
	} else {
		out = s.defCall(s.values(args...))
	}
	if len(out) > 0 {
		r, _ = out[0].Interface().(R)
	}
	if len(out) > 1 {
		if err, _ := out[len(out)-1].Interface().(error); err != nil {
			return r, err
		}
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// StubR — for methods with signature f(args) R
// ---------------------------------------------------------------------------

// StubR provides override queues for methods returning R.
type StubR[R any] struct {
	stub
	resultZero reflect.Value
}

// NewStubR creates a StubR with the given default implementation.
// The def argument must be a function matching f(args) R.
func NewStubR[R any](def any) StubR[R] {
	var z R
	return StubR[R]{
		stub:       stub{defCall: reflect.ValueOf(def).Call},
		resultZero: reflect.ValueOf(&z).Elem(),
	}
}

// Returns queues a handler that returns v.
func (s *StubR[R]) Returns(v R) {
	s.queue = append(s.queue, stubEntry{
		call: func(_ []reflect.Value) []reflect.Value {
			return []reflect.Value{reflect.ValueOf(v)}
		},
	})
}

// Call invokes the next queued handler with the given args,
// or falls back to the default implementation if the queue is empty.
func (s *StubR[R]) Call(args ...any) R {
	var r R
	if s.len() > 0 {
		out := s.callNext(s.values(args...))
		if len(out) > 0 {
			r, _ = out[0].Interface().(R)
		}
		return r
	}
	out := s.defCall(s.values(args...))
	if len(out) > 0 {
		r, _ = out[0].Interface().(R)
	}
	return r
}

// ---------------------------------------------------------------------------
// StubV — for void methods f(args)
// ---------------------------------------------------------------------------

// StubV provides override queues for void methods.
type StubV struct{ stub }

// NewStubV creates a StubV with the given default implementation.
// The def argument must be a function matching f(args).
func NewStubV(def any) *StubV {
	return &StubV{stub: stub{defCall: reflect.ValueOf(def).Call}}
}

// Returns queues a handler that does nothing (skips the default).
func (s *StubV) Returns() {
	s.queue = append(s.queue, stubEntry{
		call: func(_ []reflect.Value) []reflect.Value { return nil },
	})
}

// Call invokes the next queued handler with the given args,
// or falls back to the default implementation if the queue is empty.
func (s *StubV) Call(args ...any) {
	if s.len() > 0 {
		s.callNext(s.values(args...))
		return
	}
	s.defCall(s.values(args...))
}
