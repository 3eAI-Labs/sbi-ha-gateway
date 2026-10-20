// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package admin

import "time"

// TokenAt exposes TokenFile.current to the tests.
func TokenAt(t *TokenFile, now time.Time) []byte { return t.current(now) }
