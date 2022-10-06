// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package cgroups

import (
	"strconv"
)

func (c *cgroupV1) GetIOStats(stats *IOStats) error {
	if stats == nil {
		return &InvalidInputError{Desc: "input stats cannot be nil"}
	}

	if !c.controllerMounted("blkio") {
		return &ControllerNotFoundError{Controller: "blkio"}
	}

	// Struct is defaulted to allow in-place sums
	// But we clear it if we get errors while trying to read data
	stats.Devices = make(map[string]DeviceIOStats)
	stats.ReadBytes = uint64Ptr(0)
	stats.WriteBytes = uint64Ptr(0)
	stats.ReadOperations = uint64Ptr(0)
	stats.WriteOperations = uint64Ptr(0)

	if err := c.parseV1blkio(c.pathFor("blkio", "blkio.throttle.io_service_bytes"), stats.Devices, bytesWriter(stats)); err != nil {
		stats.ReadBytes = nil
		stats.WriteBytes = nil
		reportError(err)
	}

	if err := c.parseV1blkio(c.pathFor("blkio", "blkio.throttle.io_serviced"), stats.Devices, opsWriter(stats)); err != nil {
		stats.ReadOperations = nil
		stats.WriteOperations = nil
		reportError(err)
	}

	if len(stats.Devices) == 0 {
		stats.Devices = nil
	}

	return nil
}

func (c *cgroupV1) parseV1blkio(path string, perDevice map[string]DeviceIOStats, Writer func(*DeviceIOStats, string, uint64) bool) error {
	return parseColumnStats(c.fr, path, func(fields []string) (error, bool) {
		if len(fields) < 3 {
			return nil, false
		}

		value, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return err, false
		}

		device := perDevice[fields[0]]
		if Writer(&device, fields[1], value) {
			perDevice[fields[0]] = device
		}

		return nil, false
	})
}

func bytesWriter(stats *IOStats) func(*DeviceIOStats, string, uint64) bool {
	return func(device *DeviceIOStats, opType string, value uint64) bool {
		written := false

		switch {
		case opType == "Read":
			written = true
			device.ReadBytes = &value
			stats.ReadBytes = uint64Ptr(*stats.ReadBytes + value)
		case opType == "Write":
			written = true
			device.WriteBytes = &value
			stats.WriteBytes = uint64Ptr(*stats.WriteBytes + value)
		}

		return written
	}
}

func opsWriter(stats *IOStats) func(*DeviceIOStats, string, uint64) bool {
	return func(device *DeviceIOStats, opType string, value uint64) bool {
		written := false

		switch {
		case opType == "Read":
			written = true
			device.ReadOperations = &value
			stats.ReadOperations = uint64Ptr(*stats.ReadOperations + value)
		case opType == "Write":
			written = true
			device.WriteOperations = &value
			stats.WriteOperations = uint64Ptr(*stats.WriteOperations + value)
		}

		return written
	}
}
