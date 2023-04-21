// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021-present Datadog, Inc.

//go:build otlp
// +build otlp

package otlp

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/collector/otelcol"

	"github.com/DataDog/datadog-agent/pkg/config"
	coreOtlp "github.com/DataDog/datadog-agent/pkg/otlp"
	"github.com/DataDog/datadog-agent/pkg/serializer"
	"github.com/DataDog/datadog-agent/pkg/serverless/executioncontext"
	"github.com/DataDog/datadog-agent/pkg/trace/api"
	"github.com/DataDog/datadog-agent/pkg/trace/info"
	"github.com/DataDog/datadog-agent/pkg/trace/pb"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// ServerlessOTLPAgent represents an OTLP agent in a serverless context
type ServerlessOTLPAgent struct {
	pipeline *coreOtlp.Pipeline

	// TODO
	executionContext *executioncontext.ExecutionContext
	ProcessTrace     func(p *api.Payload)
	otelSpanChan     <-chan *pb.Span
	stop             chan struct{}
}

// NewServerlessOTLPAgent creates a new ServerlessOTLPAgent with the correct
// otel pipeline.
func NewServerlessOTLPAgent(serializer serializer.MetricSerializer, executionContext *executioncontext.ExecutionContext, otelSpanChan <-chan *pb.Span) *ServerlessOTLPAgent {
	pipeline, err := coreOtlp.NewPipelineFromAgentConfig(config.Datadog, serializer)
	if err != nil {
		log.Error("Error creating new otlp pipeline:", err)
		return nil
	}
	return &ServerlessOTLPAgent{
		pipeline:         pipeline,
		executionContext: executionContext,
	}
}

// Start starts the OTLP agent listening for traces and metrics
func (o *ServerlessOTLPAgent) Start() {
	go func() {
		if err := o.pipeline.Run(context.Background()); err != nil {
			log.Errorf("Error running the OTLP pipeline: %s", err)
		}
	}()
	if o.otelSpanChan != nil {
		o.stop = make(chan struct{})
		go o.createRootSpans()
	}
}

// Stop stops the OTLP agent.
func (o *ServerlessOTLPAgent) Stop() {
	if o == nil {
		return
	}
	o.pipeline.Stop()
	if err := o.waitForState(collectorStateClosed, time.Second); err != nil {
		log.Error("Error stopping OTLP endpints:", err)
	}
	if o.otelSpanChan != nil {
		close(o.stop)
	}
}

// IsEnabled returns true if the OTLP endpoint should be enabled.
func IsEnabled() bool {
	return coreOtlp.IsEnabled(config.Datadog)
}

var (
	collectorStateRunning = otelcol.StateRunning.String()
	collectorStateClosed  = otelcol.StateClosed.String()
)

// state returns the current state of the underlying otel collector.
func (o *ServerlessOTLPAgent) state() string {
	return coreOtlp.GetCollectorStatus(o.pipeline).Status
}

// Wait waits until the OTLP agent is running.
func (o *ServerlessOTLPAgent) Wait(timeout time.Duration) error {
	return o.waitForState(collectorStateRunning, timeout)
}

// waitForState waits until the underlying otel collector is in a given state.
func (o *ServerlessOTLPAgent) waitForState(state string, timeout time.Duration) error {
	after := time.After(timeout)
	for {
		if o.state() == state {
			return nil
		}
		select {
		case <-after:
			return fmt.Errorf("timeout waiting for otlp agent state %s", state)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

var functionName = os.Getenv("AWS_LAMBDA_FUNCTION_NAME")

func (o *ServerlessOTLPAgent) createRootSpans() {
	for {
		select {
		case span := <-o.otelSpanChan:
			o.createRootSpan(span)
		case <-o.stop:
			return
		}
	}
}

func (o *ServerlessOTLPAgent) createRootSpan(otelSpan *pb.Span) {
	log.Debug("opentelemetry root span received, creating aws.lambda execution span")
	if o.ProcessTrace == nil {
		log.Error("cannot process new aws.lambda span, dropping")
		return
	}

	span := &pb.Span{
		Service:  "aws.lambda", // will be replaced by the span processor
		Name:     "aws.lambda",
		Resource: functionName,
		TraceID:  otelSpan.TraceID,
		SpanID:   otelSpan.ParentID,
		Start:    otelSpan.Start,
		Duration: otelSpan.Duration,
		Meta: map[string]string{
			"_dd.origin": "lambda",
			"request_id": otelSpan.Meta["faas.execution"],
		},
		Type: "serverless",
	}

	if o.executionContext != nil {
		ec := o.executionContext.GetCurrentState()
		span.Meta["cold_start"] = fmt.Sprintf("%v", ec.Coldstart)
	}

	go o.ProcessTrace(&api.Payload{
		Source: info.NewReceiverStats().GetTagStats(info.Tags{}),
		TracerPayload: &pb.TracerPayload{
			Chunks: []*pb.TraceChunk{&pb.TraceChunk{
				Priority: 1,
				Spans:    []*pb.Span{span},
			}},
		},
	})
}
