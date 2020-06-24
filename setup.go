package malicious

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"

	"github.com/alecthomas/mph"
	"github.com/caddyserver/caddy"
)

// PluginOptions stores the configuration options given in the corefile
type PluginOptions struct {
	DomainFileName string
	IPFileName     string
	ReloadPeriod   time.Duration
}

// var

// init registers this plugin.
func init() { plugin.Register("malicious", setup) }

// setup is the function that gets called when the config parser sees the token "malicious". Setup is responsible
// for parsing any extra options the plugin may have. The first token this function sees is "malicious".
func setup(c *caddy.Controller) error {

	options, err := parseArguments(c)
	if err != nil {
		log.Error("Unable to parse arguments: ", err)
	}

	// Build the cache for the blacklist
	blacklist, err := buildCacheFromFile(options.DomainFileName)
	reloadTime := time.Now()
	if err != nil {
		if strings.Contains(err.Error(), "failed to find a collision-free hash function") {
			// Special case where there are 2^n objects in the blacklist
			log.Error("error building blacklist: number of items must not be a power of 2 (sorry)")
		} else {
			log.Error("error building blacklist: ", err)
		}
		reloadTime = time.Time{} // Time zero date
	}

	// TODO: Make reload async
	// e := Malicious{blacklist: blacklist, lastReloadTime: time.Now(), quit: make(chan bool)}
	e := Malicious{blacklist: blacklist, lastReloadTime: reloadTime, quit: make(chan bool)}
	quit := make(chan bool)
	tick := time.NewTicker(time.Second * 5)
	reloadHook(&e, tick, quit)

	// Add a startup function that will -- after all plugins have been loaded -- check if the
	// prometheus plugin has been used - if so we will export metrics. We can only register
	// this metric once, hence the "once.Do".
	c.OnStartup(func() error {
		once.Do(func() {
			metrics.MustRegister(c, blacklistCount)
			metrics.MustRegister(c, reloadsFailedCount)
		})
		return nil
	})

	c.OnFinalShutdown(func() error {
		log.Info("ITS THE FINAL SHUTDOWN~")
		close(quit)
		log.Info("~~")
		tick.Stop()
		e.quit <- true
		close(e.quit)
		return nil
	})

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		e.Next = next
		e.Options = options
		return &e
		// &Malicious{Next: next, blacklist: blacklist, lastReloadTime: reloadTime, Options: options}
	})

	// All OK, return a nil error.
	return nil
}

func parseArguments(c *caddy.Controller) (PluginOptions, error) {
	c.Next() // 0th token is the name of this plugin

	options := PluginOptions{}

	i := 1
	for c.Next() {
		switch i {
		case 1:
			// 1st token is domain blacklist file
			log.Info("Using domain blacklist file: ", c.Val())
			options.DomainFileName = c.Val()
		case 2:
			// 2nd token is IP blacklist file
			log.Info("Using IP blacklist file: ", c.Val())
			options.IPFileName = c.Val()
		case 3:
			// 3rd token is reload time
			t, err := time.ParseDuration(c.Val())
			if err != nil {
				log.Error("unable to parse reload duration")
			} else {
				log.Info("Setting reload time to: ", c.Val())
				options.ReloadPeriod = t
			}
		}
		i++
	}

	if options.DomainFileName == "" {
		log.Error("domain blacklist file is required")
		return options, plugin.Error("malicious", c.ArgErr())
	}

	return options, nil
}

func buildCacheFromFile(fileName string) (*mph.CHD, error) {
	// Print a log message with the time it took to build the cache
	defer logTime("Building blacklist cache took %s", time.Now())

	file, err := os.Open(fileName)
	if err != nil {
		log.Error(err)
	}
	defer file.Close()

	builder := mph.Builder()

	// Known issue: the number of items in the cache must not be a power of 2
	// Because... math. So no files with only 2 entries. Or 4. Or 8... etc.
	// TODO: Get around this. Replace mph with custom hash set? Add a safe dummy blacklist item?
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}

		// Assume all domains are global origin, with trailing dot (e.g. example.com.)
		if !strings.HasSuffix(domain, ".") {
			domain += "."
		}
		// log.Info("Adding ", domain, " to domain blacklist")
		builder.Add([]byte(domain), []byte(""))
	}

	if err := scanner.Err(); err != nil {
		log.Error(err)
	}

	blacklist, err := builder.Build()
	if err == nil {
		log.Infof("added %d domains to blacklist", blacklist.Len())
	}

	return blacklist, err
}

// Prints the elapsed time in the pre-formatted message
func logTime(msg string, since time.Time) {
	elapsed := time.Since(since)
	msg = fmt.Sprintf(msg, elapsed)
	log.Info(msg)
}

// TODO: Make reload asynchronous
func reloadHook(e *Malicious, tick *time.Ticker, quit chan bool) {
	log.Info("reload called")
	go func() {
		// tick := time.NewTicker(time.Second * 5)
		// defer tick.Stop()
		log.Info("func called")
		count := 0
		for {
			log.Info("loop iteration")
			select {
			case <-tick.C:
				log.Info("Hook ticked")
				count++
				if count > 2 {
					log.Info("Sending quit to hook")
					e.quit <- true
					// break
				}

			case <-e.quit:
				log.Info("Stopping hook")
				return
			}
		}
	}()
}

// // TODO: Make reload asynchronous
// func reloadHook(e *Malicious, tick *time.Ticker) {
// 	go func() {
// 		// tick := time.NewTicker(time.Second * 5)
// 		// defer tick.Stop()

// 		count := 0
// 		for {
// 			select {
// 			case <-tick.C:
// 				log.Info("Hook ticked")
// 				count++
// 				if count > 2 {
// 					log.Info("Sending quit to hook")
// 					e.quit <- true
// 					// break
// 				}

// 			case <-e.quit:
// 				log.Info("Stopping hook")
// 				return
// 			}
// 		}
// 	}()
// }
