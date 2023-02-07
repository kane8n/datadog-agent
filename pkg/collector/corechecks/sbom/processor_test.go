// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package sbom

import (
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/DataDog/agent-payload/v5/cyclonedx_v1_4"
	model "github.com/DataDog/agent-payload/v5/sbom"
	"github.com/DataDog/datadog-agent/pkg/aggregator/mocksender"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	"github.com/DataDog/datadog-agent/pkg/util/pointer"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
	"github.com/stretchr/testify/mock"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProcessEvents(t *testing.T) {
	sender := mocksender.NewMockSender(check.ID(""))
	sender.On("SBOM", mock.Anything, mock.Anything).Return()
	p := newProcessor(sender, 2, 50*time.Millisecond)

	sbomGenerationTime := time.Now()

	p.processEvents(workloadmeta.EventBundle{
		Events: []workloadmeta.Event{
			{
				Type: workloadmeta.EventTypeSet,
				Entity: &workloadmeta.ContainerImageMetadata{
					EntityID: workloadmeta.EntityID{
						Kind: workloadmeta.KindContainerImageMetadata,
						ID:   "sha256:9634b84c45c6ad220c3d0d2305aaa5523e47d6d43649c9bbeda46ff010b4aacd",
					},
					RepoTags: []string{
						"datadog/agent:7-rc",
						"datadog/agent:7.41.1-rc.1",
						"gcr.io/datadoghq/agent:7-rc",
						"gcr.io/datadoghq/agent:7.41.1-rc.1",
						"public.ecr.aws/datadog/agent:7-rc",
						"public.ecr.aws/datadog/agent:7.41.1-rc.1",
					},
					RepoDigests: []string{
						"datadog/agent@sha256:052f1fdf4f9a7117d36a1838ab60782829947683007c34b69d4991576375c409",
						"gcr.io/datadoghq/agent@sha256:052f1fdf4f9a7117d36a1838ab60782829947683007c34b69d4991576375c409",
						"public.ecr.aws/datadog/agent@sha256:052f1fdf4f9a7117d36a1838ab60782829947683007c34b69d4991576375c409",
					},
					SBOM: &workloadmeta.SBOM{
						CycloneDXBOM: &cyclonedx.BOM{
							SpecVersion: cyclonedx.SpecVersion1_4,
							Version:     42,
							Components: &[]cyclonedx.Component{
								{
									Name: "Foo",
								},
								{
									Name: "Bar",
								},
								{
									Name: "Baz",
								},
							},
						},
						GenerationTime:     sbomGenerationTime,
						GenerationDuration: 10 * time.Second,
					},
				},
			},
		},
		Ch: make(chan struct{}),
	})

	sender.AssertNumberOfCalls(t, "SBOM", 1)
	sender.AssertSBOM(t, []model.SBOMPayload{
		{
			Version: 1,
			Source:  &sourceAgent,
			Entities: []*model.SBOMEntity{
				{
					Type: model.SBOMSourceType_CONTAINER_IMAGE_LAYERS,
					Id:   "datadog/agent@sha256:9634b84c45c6ad220c3d0d2305aaa5523e47d6d43649c9bbeda46ff010b4aacd",
					Tags: []string{
						"7-rc",
						"7.41.1-rc.1",
					},
					InUse:              true,
					GeneratedAt:        timestamppb.New(sbomGenerationTime),
					GenerationDuration: durationpb.New(10 * time.Second),
					Sbom: &model.SBOMEntity_Cyclonedx{
						Cyclonedx: &cyclonedx_v1_4.Bom{
							SpecVersion: "1.4",
							Version:     pointer.Ptr(int32(42)),
							Components: []*cyclonedx_v1_4.Component{
								{
									Name: "Foo",
								},
								{
									Name: "Bar",
								},
								{
									Name: "Baz",
								},
							},
						},
					},
				},
				{
					Type: model.SBOMSourceType_CONTAINER_IMAGE_LAYERS,
					Id:   "gcr.io/datadoghq/agent@sha256:9634b84c45c6ad220c3d0d2305aaa5523e47d6d43649c9bbeda46ff010b4aacd",
					Tags: []string{
						"7-rc",
						"7.41.1-rc.1",
					},
					InUse:              true,
					GeneratedAt:        timestamppb.New(sbomGenerationTime),
					GenerationDuration: durationpb.New(10 * time.Second),
					Sbom: &model.SBOMEntity_Cyclonedx{
						Cyclonedx: &cyclonedx_v1_4.Bom{
							SpecVersion: "1.4",
							Version:     pointer.Ptr(int32(42)),
							Components: []*cyclonedx_v1_4.Component{
								{
									Name: "Foo",
								},
								{
									Name: "Bar",
								},
								{
									Name: "Baz",
								},
							},
						},
					},
				},
			},
		},
	})

	time.Sleep(100 * time.Millisecond)

	sender.AssertNumberOfCalls(t, "SBOM", 2)
	sender.AssertSBOM(t, []model.SBOMPayload{
		{
			Version: 1,
			Source:  &sourceAgent,
			Entities: []*model.SBOMEntity{
				{
					Type: model.SBOMSourceType_CONTAINER_IMAGE_LAYERS,
					Id:   "public.ecr.aws/datadog/agent@sha256:9634b84c45c6ad220c3d0d2305aaa5523e47d6d43649c9bbeda46ff010b4aacd",
					Tags: []string{
						"7-rc",
						"7.41.1-rc.1",
					},
					InUse:              true,
					GeneratedAt:        timestamppb.New(sbomGenerationTime),
					GenerationDuration: durationpb.New(10 * time.Second),
					Sbom: &model.SBOMEntity_Cyclonedx{
						Cyclonedx: &cyclonedx_v1_4.Bom{
							SpecVersion: "1.4",
							Version:     pointer.Ptr(int32(42)),
							Components: []*cyclonedx_v1_4.Component{
								{
									Name: "Foo",
								},
								{
									Name: "Bar",
								},
								{
									Name: "Baz",
								},
							},
						},
					},
				},
			},
		},
	})

	p.stop()
}

func TestProcessEvents_repoTagWithNoMatchingRepoDigest(t *testing.T) {
	// In containerd some images are created without a repo digest, and it's
	// also possible to remove repo digests manually. To test that scenario, in
	// this test, we define an image with 2 repo tags: one for the gcr.io
	// registry and another for the public.ecr.aws registry, but there's only
	// one repo digest.
	// We expect to send 2 events, one for each registry.

	sender := mocksender.NewMockSender("")
	sender.On("SBOM", mock.Anything, mock.Anything).Return()
	p := newProcessor(sender, 2, 50*time.Millisecond)

	sbomGenerationTime := time.Now()

	p.processEvents(workloadmeta.EventBundle{
		Events: []workloadmeta.Event{
			{
				Type: workloadmeta.EventTypeSet,
				Entity: &workloadmeta.ContainerImageMetadata{
					EntityID: workloadmeta.EntityID{
						Kind: workloadmeta.KindContainerImageMetadata,
						ID:   "sha256:9634b84c45c6ad220c3d0d2305aaa5523e47d6d43649c9bbeda46ff010b4aacd",
					},
					RepoTags: []string{
						"gcr.io/datadoghq/agent:7-rc",
						"public.ecr.aws/datadog/agent:7-rc",
					},
					RepoDigests: []string{
						// Notice that there's a repo tag for gcr.io, but no repo digest.
						"public.ecr.aws/datadog/agent@sha256:052f1fdf4f9a7117d36a1838ab60782829947683007c34b69d4991576375c409",
					},
					SBOM: &workloadmeta.SBOM{
						CycloneDXBOM: &cyclonedx.BOM{
							SpecVersion: cyclonedx.SpecVersion1_4,
							Version:     42,
							Components: &[]cyclonedx.Component{
								{
									Name: "Foo",
								},
								{
									Name: "Bar",
								},
								{
									Name: "Baz",
								},
							},
						},
						GenerationTime:     sbomGenerationTime,
						GenerationDuration: 10 * time.Second,
					},
				},
			},
		},
		Ch: make(chan struct{}),
	})

	time.Sleep(100 * time.Millisecond)

	sender.AssertNumberOfCalls(t, "SBOM", 1)
	sender.AssertSBOM(t, []model.SBOMPayload{
		{
			Version: 1,
			Source:  &sourceAgent,
			Entities: []*model.SBOMEntity{
				{
					Type: model.SBOMSourceType_CONTAINER_IMAGE_LAYERS,
					Id:   "public.ecr.aws/datadog/agent@sha256:9634b84c45c6ad220c3d0d2305aaa5523e47d6d43649c9bbeda46ff010b4aacd",
					Tags: []string{
						"7-rc",
					},
					InUse:              true,
					GeneratedAt:        timestamppb.New(sbomGenerationTime),
					GenerationDuration: durationpb.New(10 * time.Second),
					Sbom: &model.SBOMEntity_Cyclonedx{
						Cyclonedx: &cyclonedx_v1_4.Bom{
							SpecVersion: "1.4",
							Version:     pointer.Ptr(int32(42)),
							Components: []*cyclonedx_v1_4.Component{
								{
									Name: "Foo",
								},
								{
									Name: "Bar",
								},
								{
									Name: "Baz",
								},
							},
						},
					},
				},
				{
					Type: model.SBOMSourceType_CONTAINER_IMAGE_LAYERS,
					Id:   "gcr.io/datadoghq/agent@sha256:9634b84c45c6ad220c3d0d2305aaa5523e47d6d43649c9bbeda46ff010b4aacd",
					Tags: []string{
						"7-rc",
					},
					InUse:              true,
					GeneratedAt:        timestamppb.New(sbomGenerationTime),
					GenerationDuration: durationpb.New(10 * time.Second),
					Sbom: &model.SBOMEntity_Cyclonedx{
						Cyclonedx: &cyclonedx_v1_4.Bom{
							SpecVersion: "1.4",
							Version:     pointer.Ptr(int32(42)),
							Components: []*cyclonedx_v1_4.Component{
								{
									Name: "Foo",
								},
								{
									Name: "Bar",
								},
								{
									Name: "Baz",
								},
							},
						},
					},
				},
			},
		},
	})

	p.stop()
}
