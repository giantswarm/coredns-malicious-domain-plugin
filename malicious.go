package malicious

import (
	"context"
	"io"
	"os"
	"strings"
	"time"

	"github.com/coredns/coredns/request"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/alecthomas/mph"
	"github.com/miekg/dns"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin("malicious")

// Malicious is a plugin which counts requests to blacklisted domains
type Malicious struct {
	Next           plugin.Handler
	blacklist      *mph.CHD
	lastReloadTime time.Time
	Options        PluginOptions
	quit           chan bool
}

// ServeDNS implements the plugin.Handler interface. This method gets called when malicious is used
// in a Server.
func (e *Malicious) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	// Debug log that we've have seen the query. This will only be shown when the debug plugin is loaded.
	log.Debug("Received response")

	// For now, rebuild the blacklist if we get a new request after our reload period
	// This should be made asynchronous in the future so as not to block requests
	if time.Since(e.lastReloadTime) >= e.Options.ReloadPeriod {
		e.reloadBlacklist(ctx)
	}

	req := request.Request{W: w, Req: r}

	if e.blacklist != nil {
		// See if the requested domain is in the cache
		hit := e.blacklist.Get([]byte(req.Name()))
		if hit != nil {
			blacklistCount.WithLabelValues(metrics.WithServer(ctx), req.IP(), req.Name()).Inc()
			log.Info("host ", req.IP(), " requested blacklisted domain: ", req.Name())
		}
	} else {
		log.Warning("no blacklist has been loaded")
	}

	// Wrap the response when it returns from the next plugin
	pw := NewResponsePrinter(w)

	// Call next plugin (if any).
	return plugin.NextOrFailure(e.Name(), e.Next, ctx, pw, r)
}

func (e *Malicious) reloadBlacklist(ctx context.Context) {
	newBlacklist, err := buildCacheFromFile(e.Options.DomainFileName)
	if err != nil {
		if strings.Contains(err.Error(), "failed to find a collision-free hash function") {
			// Special case where there are 2^n objects in the blacklist
			log.Error("error rebuilding blacklist: number of items must not be a power of 2 (sorry)")
		} else {
			log.Error("error rebuilding blacklist: ", err)
		}
		reloadsFailedCount.WithLabelValues(metrics.WithServer(ctx)).Inc()
	} else {
		log.Info("updated blacklist")
		e.blacklist = newBlacklist
		e.lastReloadTime = time.Now()
	}
}

// Name implements the Handler interface.
func (e Malicious) Name() string { return "malicious" }

// ResponsePrinter wraps a dns.ResponseWriter and will let the plugin inspect the response.
type ResponsePrinter struct {
	dns.ResponseWriter
}

// NewResponsePrinter returns ResponseWriter.
func NewResponsePrinter(w dns.ResponseWriter) *ResponsePrinter {
	return &ResponsePrinter{ResponseWriter: w}
}

// WriteMsg calls the underlying ResponseWriter's WriteMsg method and handles our future response logic.
func (r *ResponsePrinter) WriteMsg(res *dns.Msg) error {
	// fmt.Fprintln(out, "example2")
	// TODO: Check return IP against IP blacklist?
	return r.ResponseWriter.WriteMsg(res)
}

// Make out a reference to os.Stdout so we can easily overwrite it for testing.
var out io.Writer = os.Stdout
