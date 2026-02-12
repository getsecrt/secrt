package envelope

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MaxTTLSeconds is the maximum allowed TTL (1 year).
const MaxTTLSeconds = 31536000

var ErrInvalidTTL = errors.New("invalid TTL")

// ParseTTL parses a CLI TTL string to seconds.
// Grammar: <positive-integer>[s|m|h|d|w]
// No unit defaults to seconds. Result must be 1..31536000.
func ParseTTL(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, ErrInvalidTTL
	}

	var numStr string
	var unit byte

	last := s[len(s)-1]
	if last >= '0' && last <= '9' {
		numStr = s
		unit = 's'
	} else {
		if len(s) < 2 {
			return 0, fmt.Errorf("%w: %q", ErrInvalidTTL, s)
		}
		// Only single-char units are valid
		unitStr := s[len(s)-1:]
		numStr = s[:len(s)-1]

		switch unitStr {
		case "s", "m", "h", "d", "w":
			unit = unitStr[0]
		default:
			return 0, fmt.Errorf("%w: unknown unit in %q", ErrInvalidTTL, s)
		}
	}

	// Reject decimals, spaces, negative signs in the numeric part
	if strings.ContainsAny(numStr, ". -+") {
		return 0, fmt.Errorf("%w: %q", ErrInvalidTTL, s)
	}

	n, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q", ErrInvalidTTL, s)
	}

	if n <= 0 {
		return 0, fmt.Errorf("%w: value must be positive", ErrInvalidTTL)
	}

	var multiplier int64
	switch unit {
	case 's':
		multiplier = 1
	case 'm':
		multiplier = 60
	case 'h':
		multiplier = 3600
	case 'd':
		multiplier = 86400
	case 'w':
		multiplier = 604800
	}

	result := n * multiplier
	if result > MaxTTLSeconds {
		return 0, fmt.Errorf("%w: exceeds maximum (%d seconds)", ErrInvalidTTL, MaxTTLSeconds)
	}

	return result, nil
}
