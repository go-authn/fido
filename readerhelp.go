// Copyright (c) the go-authn authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package fido

import (
	"bytes"
	"io"
)

// bytesReader is bytes.NewReader, named so the one place that needs a reader
// does not pull the whole of bytes into the reader's line of sight.
func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
