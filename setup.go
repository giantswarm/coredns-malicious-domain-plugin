package warnlist

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/coredns/caddy"
)

const MaxJitterPercent = 30

// PluginOptions stores the configuration options given in the corefile
type PluginOptions struct {
	DomainSource     string
	DomainSourceType string
	FileFormat       string
	MatchSubdomains  bool
	ReloadPeriod     time.Duration
}

// init registers this plugin.
func init() { plugin.Register("warnlist", setup) }

// setup is the function that gets called when the config parser sees the token "warnlist". Setup is responsible
// for parsing any extra options the plugin may have. The first token this function sees is "warnlist".
func setup(c *caddy.Controller) error {

	options, err := parseArguments(c)
	if err != nil {
		log.Error("Unable to parse arguments: ", err)
		return err
	}

	// Build the cache for the warnlist
	warnlist, err := buildCacheFromFile(options)
	reloadTime := time.Now()
	if err != nil {
		// Require the first build to succeed
		return err
	}

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	q := make(chan bool)
	wp := WarnlistPlugin{warnlist: warnlist, lastReloadTime: reloadTime, Options: options, quit: q}

	var tick *time.Ticker
	{
		// If our ReloadPeriod is configured, set up the reload hook
		if options.ReloadPeriod > 0*time.Second {
			tick = time.NewTicker(options.ReloadPeriod)
			reloadHook(&wp, tick)
		}
	}

	c.OnFinalShutdown(func() error {
		// log.Info("Final Shutdown")

		// If our ReloadPeriod is configured, tear down the reload hook
		if options.ReloadPeriod > 0*time.Second {
			tick.Stop()
			wp.quit <- true
		}

		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		wp.Next = next
		return &wp
	})

	// All OK, return a nil error.
	return nil
}

func reloadHook(wp *WarnlistPlugin, tick *time.Ticker) {
	go func() {
		for {
			// log.Info("loop iteration")
			select {
			case <-tick.C:
				// log.Info("Hook ticked")

				rebuildWarnlist(wp)

			case <-wp.quit:
				// log.Info("Stopping hook")
				tick.Stop()
				return
			}
		}
	}()
}

func parseArguments(c *caddy.Controller) (PluginOptions, error) {
	c.Next() // 0th token is the name of this plugin

	options := PluginOptions{}

	// Match subdomains by default
	options.MatchSubdomains = true

	for c.NextBlock() {
		if err := parseBlock(c, &options); err != nil {
			return options, err
		}
	}

	// Check that a source for the warnlist was given
	if options.DomainSource == "" {
		log.Error("domain warnlist file or url is required")
		return options, plugin.Error("warnlist", c.ArgErr())
	}

	// Check that the specified file format is valid
	valid := false
	for _, t := range []string{DomainFileFormatHostfile, DomainFileFormatTextList} {
		if options.FileFormat == t {
			valid = true
		}
	}
	if !valid {
		return options, plugin.Error("warnlist", c.Errf("unknown file format: %s", options.FileFormat))
	}

	return options, nil
}

// Parses the configuration lines following our plugin declaration in the Corefile
func parseBlock(c *caddy.Controller, options *PluginOptions) error {
	switch c.Val() {
	case "file":
		if !c.NextArg() {
			return c.ArgErr()
		}
		options.DomainSource = c.Val()
		options.DomainSourceType = DomainSourceTypeFile
		if !c.NextArg() {
			return c.ArgErr()
		}
		options.FileFormat = c.Val()
		log.Infof("Using domain warnlist file: %s with format %s", options.DomainSource, options.FileFormat)

	case "match_subdomains":
		if !c.NextArg() {
			return c.ArgErr()
		}
		matchBool, err := strconv.ParseBool(c.Val())
		if err != nil {
			log.Error("unable to parse match_subdomain setting (must be true or false")
			return c.ArgErr()
		}
		options.MatchSubdomains = matchBool
		if options.MatchSubdomains {
			log.Infof("matching subdomains")
		} else {
			log.Infof("not matching subdomains")
		}

	case "url":
		if !c.NextArg() {
			return c.ArgErr()
		}
		if options.DomainSource != "" {
			return c.Err("file argument was already specified. Plugin can use either 'file' or 'url' option, but not both")
		}
		options.DomainSource = c.Val()
		options.DomainSourceType = DomainSourceTypeURL
		if !c.NextArg() {
			return c.ArgErr()
		}
		options.FileFormat = c.Val()
		log.Infof("Using domain warnlist url: %s with format %s", options.DomainSource, options.FileFormat)

	case "reload":
		if !c.NextArg() {
			return c.ArgErr()
		}

		t, err := time.ParseDuration(c.Val())
		if err != nil {
			log.Error("unable to parse reload duration")
			return c.ArgErr()
		}
		t = jitter(t)
		options.ReloadPeriod = t
		log.Infof("Using reload period of: %s", options.ReloadPeriod)
	}

	return nil
}

func jitter(t time.Duration) time.Duration {
	// Get the max jitter as a duration.
	maxJitter, err := time.ParseDuration(fmt.Sprintf("%dms", t.Milliseconds()/MaxJitterPercent))
	if err != nil {
		log.Warningf("Failed to calculate jitter: %s", err)
		return t
	}

	// Calcluate the minimum time we have to wait.
	minDuration := t - maxJitter

	// Set the final duration to the min + a random duration between 0 and our max jitter.
	return minDuration + time.Duration(rand.Int63n(int64(maxJitter))) // nolint:gosec // rand not used for crypto.
}
