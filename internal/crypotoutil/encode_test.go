// Copyright 2021 E99p1ant. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package crypotoutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Encode(test *testing.T) {
	for _, tc := range []struct {
		name     string
		str      string
		slat     string
		expected string
	}{
		{
			name:     "normal",
			str:      "aaaaaaaaaaaa",
			slat:     "bbbbbbbbbbbb",
			expected: "\xd4\xeb24\xa6\xe5\x7dE_\xdc\xa5\xbc\xbe\xfb\x3a\xd1",
		},
	} {
		got := Encode(tc.str, tc.slat)
		assert.Equal(test, tc.expected, got)
	}
}
