package socks5

import (
	"sync"
	"testing"
)

func TestPool(t *testing.T) {
	p := newPool(2048)
	b := p.Get()
	bs := b[0:cap(b)]
	if len(bs) != cap(b) {
		t.Fatalf("invalid buffer")
	}
	p.Put(b)
}

func BenchmarkSyncPool(b *testing.B) {
	p := newPool(32 * 1024)
	wg := new(sync.WaitGroup)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		wg.Add(1)
		go func() {
			s := p.Get()
			p.Put(s)
			wg.Done()
		}()
	}
	wg.Wait()
}
