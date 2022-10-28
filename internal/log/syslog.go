// SPDX-License-Identifier: Apache-2.0

package log

import (
	"log"
	"sync"
)

const (
	syslogFlags = log.Llongfile
)

var once sync.Once

// UseSysLog initializes logging to syslog
func UseSysLog() error {
	return nil
}
