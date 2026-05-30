package cognitivefixture

// deeplyNested has low cyclomatic complexity but high cognitive complexity:
// the nesting is what makes it hard to follow, which is exactly what the
// cognitive-complexity rule (and not the cyclomatic one) is meant to catch.
func deeplyNested(a, b, c, d, e, f, g bool) int {
	r := 0
	if a {
		if b {
			if c {
				if d {
					if e {
						if f {
							if g {
								r++
							}
						}
					}
				}
			}
		}
	}
	return r
}
