// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js || ts_omit_debug

package wgengine

import "tailscale.com/util/usermetric"

func NewWatchdog(e Engine, mr *usermetric.Registry) Engine { return e }
