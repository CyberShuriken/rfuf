package findings

import (
	"fmt"

	"github.com/CyberShuriken/rfuf/internal/findings/apiversion"
	"github.com/CyberShuriken/rfuf/internal/findings/authshape"
	"github.com/CyberShuriken/rfuf/internal/findings/backupscan"
	"github.com/CyberShuriken/rfuf/internal/findings/buckets"
	"github.com/CyberShuriken/rfuf/internal/findings/businesslogic"
	"github.com/CyberShuriken/rfuf/internal/findings/bypass403"
	"github.com/CyberShuriken/rfuf/internal/findings/cors2"
	"github.com/CyberShuriken/rfuf/internal/findings/envsecrets"
	"github.com/CyberShuriken/rfuf/internal/findings/gitexposure"
	"github.com/CyberShuriken/rfuf/internal/findings/hostheader"
	"github.com/CyberShuriken/rfuf/internal/findings/idor"
	"github.com/CyberShuriken/rfuf/internal/findings/jsmine"
	"github.com/CyberShuriken/rfuf/internal/findings/nextjsbypass"
	"github.com/CyberShuriken/rfuf/internal/findings/oauth"
	"github.com/CyberShuriken/rfuf/internal/findings/paramshape"
	"github.com/CyberShuriken/rfuf/internal/findings/paramsprayer"
	"github.com/CyberShuriken/rfuf/internal/findings/race"
	"github.com/CyberShuriken/rfuf/internal/findings/reflection"
	"github.com/CyberShuriken/rfuf/internal/findings/s3auditor"
	"github.com/CyberShuriken/rfuf/internal/findings/secheaders"
	"github.com/CyberShuriken/rfuf/internal/findings/specparser"
	"github.com/CyberShuriken/rfuf/internal/findings/takeover"
	"github.com/CyberShuriken/rfuf/internal/findings/takeoversvc"
)

// Dispatch maps a finder name to its Run function. Shared by
// cmd/findings-runner and the `rfuf findings` subcommand so the
// installed single binary does not need `go run` from the work dir.
var Dispatch = map[string]func(workDir string) error{
	"reflection":    reflection.Run,
	"paramshape":    paramshape.Run,
	"authshape":     authshape.Run,
	"signup":        takeover.Run,
	"idor":          idor.Run,
	"oauth":         oauth.Run,
	"race":          race.Run,
	"buckets":       buckets.Run,
	"takeoversvc":   takeoversvc.Run,
	"jsmine":        jsmine.Run,
	"secheaders":    secheaders.Run,
	"backupscan":    backupscan.Run,
	"businesslogic": businesslogic.Run,
	"hostheader":    hostheader.Run,
	"cors2":         cors2.Run,
	"specparser":    specparser.Run,
	"paramsprayer":  paramsprayer.Run,
	"bypass403":     bypass403.Run,
	"envsecrets":    envsecrets.Run,
	"gitexposure":   gitexposure.Run,
	"nextjsbypass":  nextjsbypass.Run,
	"s3auditor":     s3auditor.Run,
	"apiversion":    apiversion.Run,
}

// RunFinder dispatches to the named finder. Returns an error for unknown
// names or finder failures.
func RunFinder(name, workDir string) error {
	run, ok := Dispatch[name]
	if !ok {
		return fmt.Errorf("unknown finder %q", name)
	}
	return run(workDir)
}
