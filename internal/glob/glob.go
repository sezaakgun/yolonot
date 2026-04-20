// Package glob provides fnmatch-style glob matching shared across yolonot
// packages. `*` matches any characters including path separators (which is
// different from filepath.Match's semantics).
package glob

// Match reports whether text matches the given glob pattern. `*` matches
// any sequence of characters (including `/`), `?` matches any single
// character. All other characters match literally.
func Match(pattern, text string) bool {
	px, tx := 0, 0
	nextPx, nextTx := -1, -1

	for tx < len(text) || px < len(pattern) {
		if px < len(pattern) {
			switch pattern[px] {
			case '*':
				nextPx = px
				nextTx = tx
				px++
				continue
			case '?':
				if tx < len(text) {
					px++
					tx++
					continue
				}
			default:
				if tx < len(text) && pattern[px] == text[tx] {
					px++
					tx++
					continue
				}
			}
		}
		if nextPx >= 0 && nextTx < len(text) {
			nextTx++
			px = nextPx + 1
			tx = nextTx
		} else {
			return false
		}
	}
	return true
}
