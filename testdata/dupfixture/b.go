package dupfixture

func process(items []int) int {
	total := 0
	for _, v := range items {
		if v > 0 {
			total += v
		} else {
			total -= v
		}
	}
	return total
}
