// Package all registers every built-in plugin.
//
// The registry is populated by init() functions, so a binary that never imports
// a plugin package reports an empty /api/v1/plugins — which the console renders as
// "no plugins installed". Importing this package from both the engine and the
// management API keeps a single list and stops the two binaries from disagreeing
// about what ships in the box.
package all

import (
	// Built-in inspection plugins.
	_ "github.com/jackby03/waffynx/plugins/bot-protection"
	_ "github.com/jackby03/waffynx/plugins/geo-block"
	_ "github.com/jackby03/waffynx/plugins/rate-limit"
	_ "github.com/jackby03/waffynx/plugins/request-validation"
)
