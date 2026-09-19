package apiversion

import (
	"fmt"
	"regexp"

	"github.com/CyberShuriken/rfuf/internal/findings/internal/iohelp"
)

var versionRegex = regexp.MustCompile(`(?i)/v([0-9]+)(/|$)`)
var aliases = []string{"v0", "beta", "dev", "staging", "alpha", "test", "preview", "internal"}

// Run identifies API versions and generates alternative targets.
func Run(workDir string) error {
	urls, err := iohelp.ReadLines(workDir + "/all_urls.txt")
	if err != nil || len(urls) == 0 {
		return nil
	}

	newUrls := make(map[string]struct{})
	for _, urlStr := range urls {
		matches := versionRegex.FindStringSubmatch(urlStr)
		if len(matches) < 2 {
			continue
		}

		versionStr := matches[1]
		var v int
		fmt.Sscanf(versionStr, "%d", &v)

		versions := []string{}
		for i := -2; i <= 2; i++ {
			if i == 0 {
				continue
			}
			if v+i < 0 {
				continue
			}
			versions = append(versions, fmt.Sprintf("v%d", v+i))
		}

		loc := versionRegex.FindStringIndex(urlStr)
		prefix := urlStr[:loc[0]]
		suffix := urlStr[loc[1]:]

		for _, vn := range versions {
			if v-1 < 0 && vn == fmt.Sprintf("v%d", v-1) {
				continue
			}
			newUrls[prefix+"/"+vn+suffix] = struct{}{}
		}

		for _, alias := range aliases {
			newUrls[prefix+"/"+alias+suffix] = struct{}{}
		}
	}

	if len(newUrls) == 0 {
		return nil
	}

	var result []string
	for u := range newUrls {
		result = append(result, u)
	}

	currentUrls, _ := iohelp.ReadLines(workDir + "/all_urls.txt")
	all := append(currentUrls, result...)

	unique := make(map[string]struct{})
	var final []string
	for _, u := range all {
		if _, ok := unique[u]; !ok {
			unique[u] = struct{}{}
			final = append(final, u)
		}
	}

	return iohelp.WriteLines(workDir+"/all_urls.txt", final)
}
