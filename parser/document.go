// Copyright (c) 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

package parser

import spdx "github.com/spdx/tools-golang/spdx/v2_2"

type Document struct {
	SPDXDocRef    *spdx.Document
	ConfigDataRef *Config
}
