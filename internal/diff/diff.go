// Package diff produces a small line diff for config review. Configs are a
// few hundred lines at most, so a plain LCS table is fine.
package diff

import "strings"

// Lines returns a unified-style diff of a and b: changed lines prefixed with
// "-" or "+", unchanged lines near a change with "  ", and "..." between
// distant hunks. Empty when a and b are equal.
func Lines(a, b string) string {
	if a == b {
		return ""
	}
	x, y := split(a), split(b)
	n, m := len(x), len(y)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	type op struct {
		kind byte
		text string
	}
	var ops []op
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && x[i] == y[j]:
			ops = append(ops, op{' ', x[i]})
			i, j = i+1, j+1
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, op{'-', x[i]})
			i++
		default:
			ops = append(ops, op{'+', y[j]})
			j++
		}
	}

	const context = 2
	show := make([]bool, len(ops))
	for k, o := range ops {
		if o.kind != ' ' {
			for c := max(0, k-context); c <= min(len(ops)-1, k+context); c++ {
				show[c] = true
			}
		}
	}
	var out strings.Builder
	gap := false
	for k, o := range ops {
		if !show[k] {
			gap = true
			continue
		}
		if gap && out.Len() > 0 {
			out.WriteString("...\n")
		}
		gap = false
		out.WriteByte(o.kind)
		out.WriteByte(' ')
		out.WriteString(o.text)
		out.WriteByte('\n')
	}
	return out.String()
}

func split(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
