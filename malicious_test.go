package malicious

import (
	"bytes"
	"context"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

func TestMalicious(t *testing.T) {

	// Create a minimal blacklist for this test.
	bl := NewBlacklist()
	bl.Add("example.org.")
	bl.Add("totally.cool")
	bl.Close()

	// Create a new Malicious Plugin. Use the test.ErrorHandler as the next plugin.
	m := Malicious{Next: test.ErrorHandler(), blacklist: bl}

	// Setup a new output buffer that is *not* standard output, so we can check if
	// example is really being printed.
	b := &bytes.Buffer{}
	out = b

	ctx := context.TODO()
	r := new(dns.Msg)
	r.SetQuestion("example.org.", dns.TypeA)
	// Create a new Recorder that captures the result, this isn't actually used in this test
	// as it just serves as something that implements the dns.ResponseWriter interface.
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	// Call our plugin directly, and check the result.
	_, err := m.ServeDNS(ctx, rec, r)
	if err != nil {
		t.Fatalf("Error serving DNS: %v", err)
	}
	// if a := b.String(); a != "host 10.240.0.1 requested blacklisted domain: example.org.\n" { // TODO: Check log output instead of response
	// 	t.Errorf("Failed to print '%s', got %s", "example", a)
	// }
}
