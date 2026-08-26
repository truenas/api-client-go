// SPDX-License-Identifier: LGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

// progressBar is a simple text-based progress bar (ports utils.ProgressBar):
//
//	Status: (message)
//	Total Progress: [#####################___________________] 53.00%
type progressBar struct {
	mu         sync.Mutex
	out        io.Writer
	message    string
	percentage float64 // 0.0 to 1.0
	used       bool
}

func newProgressBar(out io.Writer) *progressBar {
	return &progressBar{out: out}
}

// update sets a new percentage (0-100) and/or message and redraws.
func (p *progressBar) update(percent float64, message string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.used {
		fmt.Fprint(p.out, "\n")
		p.used = true
	}
	if percent != 0 {
		p.percentage = percent / 100.0
	}
	if message != "" {
		p.message = message
	}
	p.draw()
}

// draw erases the previous progress bar and draws an updated one. Callers
// must hold p.mu.
func (p *progressBar) draw() {
	const width = 40
	filled := int(p.percentage * width)
	if filled > width {
		filled = width
	}
	message := strings.TrimSpace(p.message)
	if message == "" {
		message = "(none)"
	}
	fmt.Fprint(p.out, "\033[2K\033[A\033[2K\r")
	fmt.Fprintf(p.out, "Status: %s\n", message)
	fmt.Fprintf(p.out, "Total Progress: [%s%s] %.2f%%",
		strings.Repeat("#", filled), strings.Repeat("_", width-filled), p.percentage*100)
}

// finish fills the bar to 100% and terminates the line.
func (p *progressBar) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.percentage = 1
	if p.used {
		p.draw()
		fmt.Fprint(p.out, "\n")
	}
}
