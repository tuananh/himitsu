package auto

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/tuananh/himitsu/pkg/himitsu"
)

var (
	// continueOnError controls whether Berglas should continue on error or panic.
	// The default behavior is to panic.
	continueOnError, _ = strconv.ParseBool(os.Getenv("HIMITSU_CONTINUE_ON_ERROR"))

	// logLevel is the log level to use.
	logLevel, _ = logrus.ParseLevel(os.Getenv("HIMITSU_LOG_LEVEL"))
)

func init() {
	ctx := context.Background()

	client, err := himitsu.New(ctx)
	if err != nil {
		handleError(fmt.Errorf("failed to initialize berglas client: %s", err))
		return
	}
	client.SetLogLevel(logLevel)

	for _, e := range os.Environ() {
		p := strings.SplitN(e, "=", 2)
		if len(p) < 2 {
			continue
		}

		k, v := p[0], p[1]
		if !himitsu.IsReference(v) {
			continue
		}

		s, err := client.Resolve(ctx, v)
		if err != nil {
			handleError(fmt.Errorf("failed to parse %q: %w", k, err))
			continue
		}

		if err := os.Setenv(k, string(s)); err != nil {
			handleError(fmt.Errorf("failed to set %q: %w", k, err))
			continue
		}
	}
}

func handleError(err error) {
	log.Printf("%s\n", err)
	if !continueOnError {
		panic(err)
	}
}
