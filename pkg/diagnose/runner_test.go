// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package diagnose

import (
	"bytes"
	"errors"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/diagnose/diagnosis"

	"github.com/stretchr/testify/assert"
)

func TestConnectivityAutodiscovery(t *testing.T) {

	diagnosis.RegisterMetadataAvail("failing", func() error { return errors.New("fail") })
	diagnosis.RegisterMetadataAvail("succeeding", func() error { return nil })

	w := &bytes.Buffer{}
	RunMetadataAvail(w)

	result := w.String()
	assert.Contains(t, result, "=== Running failing diagnosis ===\n===> FAIL")
	assert.Contains(t, result, "=== Running succeeding diagnosis ===\n===> PASS")
}
