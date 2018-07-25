/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package images

import (
	"context"
	"fmt"

	eventstypes "github.com/containerd/containerd/api/events"
	imagesapi "github.com/containerd/containerd/api/services/images/v1"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/gc"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/services"
	ptypes "github.com/gogo/protobuf/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.ServicePlugin,
		ID:   services.ImagesService,
		Requires: []plugin.Type{
			plugin.MetadataPlugin,
			plugin.GCPlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			m, err := ic.Get(plugin.MetadataPlugin)
			if err != nil {
				return nil, err
			}
			g, err := ic.Get(plugin.GCPlugin)
			if err != nil {
				return nil, err
			}

			return &local{
				store:     metadata.NewImageStore(m.(*metadata.DB)),
				publisher: ic.Events,
				gc:        g.(gcScheduler),
			}, nil
		},
	})
}

type gcScheduler interface {
	ScheduleAndWait(context.Context) (gc.Stats, error)
}

type local struct {
	store     images.Store
	gc        gcScheduler
	publisher events.Publisher
}

var _ imagesapi.ImagesClient = &local{}

func (l *local) Get(ctx context.Context, req *imagesapi.GetImageRequest, _ ...grpc.CallOption) (*imagesapi.GetImageResponse, error) {
	image, err := l.store.Get(ctx, req.Name)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	imagepb := imageToProto(&image)
	return &imagesapi.GetImageResponse{
		Image: &imagepb,
	}, nil
}

func (l *local) List(ctx context.Context, req *imagesapi.ListImagesRequest, _ ...grpc.CallOption) (*imagesapi.ListImagesResponse, error) {
	images, err := l.store.List(ctx, req.Filters...)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return &imagesapi.ListImagesResponse{
		Images: imagesToProto(images),
	}, nil
}

func (l *local) Create(ctx context.Context, req *imagesapi.CreateImageRequest, _ ...grpc.CallOption) (*imagesapi.CreateImageResponse, error) {
	log.G(ctx).WithField("name", req.Image.Name).WithField("target", req.Image.Target.Digest).Debugf("create image")
	if req.Image.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Image.Name required")
	}

	var (
		image = imageFromProto(&req.Image)
		resp  imagesapi.CreateImageResponse
	)
	created, err := l.store.Create(ctx, image)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	resp.Image = imageToProto(&created)

	if err := l.publisher.Publish(ctx, "/images/create", &eventstypes.ImageCreate{
		Name:   resp.Image.Name,
		Labels: resp.Image.Labels,
	}); err != nil {
		return nil, err
	}

	return &resp, nil

}

func (l *local) Update(ctx context.Context, req *imagesapi.UpdateImageRequest, _ ...grpc.CallOption) (*imagesapi.UpdateImageResponse, error) {
	if req.Image.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Image.Name required")
	}

	var (
		image      = imageFromProto(&req.Image)
		resp       imagesapi.UpdateImageResponse
		fieldpaths []string
	)

	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		fieldpaths = append(fieldpaths, req.UpdateMask.Paths...)
	}

	updated, err := l.store.Update(ctx, image, fieldpaths...)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	resp.Image = imageToProto(&updated)

	if err := l.publisher.Publish(ctx, "/images/update", &eventstypes.ImageUpdate{
		Name:   resp.Image.Name,
		Labels: resp.Image.Labels,
	}); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (l *local) Delete(ctx context.Context, req *imagesapi.DeleteImageRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
	log.G(ctx).WithField("name", req.Name).Debugf("delete image")

	if err := l.store.Delete(ctx, req.Name); err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	if err := l.publisher.Publish(ctx, "/images/delete", &eventstypes.ImageDelete{
		Name: req.Name,
	}); err != nil {
		return nil, err
	}

	if req.Sync {
		if _, err := l.gc.ScheduleAndWait(ctx); err != nil {
			return nil, err
		}
	}

	return &ptypes.Empty{}, nil
}

func (l *local) EncryptImage(ctx context.Context, req *imagesapi.EncryptImageRequest, _ ...grpc.CallOption) (*imagesapi.EncryptImageResponse, error) {
	log.G(ctx).WithField("name", req.Name).Debugf("encrypt image")

	var resp   imagesapi.EncryptImageResponse

	encrypted, err := l.store.EncryptImage(ctx, req.Name, req.NewName, &images.CryptoConfig{
		Ec:	&images.EncryptConfig{
			Recipients    : req.Cc.Recipients,
			GPGPubRingFile: req.Cc.Gpgpubkeyring,
			Operation     : req.Cc.Operation,
		},
	}, layers32ToLayers(req.Layers), req.Platforms)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	resp.Image = imageToProto(&encrypted)

	if err := l.publisher.Publish(ctx, "/images/update", &eventstypes.ImageUpdate{
		Name:   resp.Image.Name,
		Labels: resp.Image.Labels,
	}); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (l *local) DecryptImage(ctx context.Context, req *imagesapi.DecryptImageRequest, _ ...grpc.CallOption) (*imagesapi.DecryptImageResponse, error) {
	log.G(ctx).WithField("name", req.Name).Debugf("decrypt image")

	fmt.Printf("req.Platforms: %s\n", req.Platforms)

	var resp   imagesapi.DecryptImageResponse

	keyIdMap := make(map[uint64]images.DecryptKeyData)

	for k, v := range req.Dc.KeyIdMap {
		keyIdMap[k] = images.DecryptKeyData{
			KeyData:         v.KeyData,
			KeyDataPassword: v.KeyDataPassword,
		}
	}

	encrypted, err := l.store.DecryptImage(ctx, req.Name, req.NewName, &images.CryptoConfig{
		Dc:	&images.DecryptConfig{
			KeyIdMap: keyIdMap,
		},
	}, layers32ToLayers(req.Layers), req.Platforms)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	resp.Image = imageToProto(&encrypted)

	if err := l.publisher.Publish(ctx, "/images/update", &eventstypes.ImageUpdate{
		Name:   resp.Image.Name,
		Labels: resp.Image.Labels,
	}); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (l *local) GetImageLayerInfo(ctx context.Context, req *imagesapi.GetImageLayerInfoRequest, _ ...grpc.CallOption) (*imagesapi.GetImageLayerInfoResponse, error) {
	log.G(ctx).WithField("name", req.Name).Debugf("GetImageLayerInfo")

	var resp imagesapi.GetImageLayerInfoResponse

	lis, err := l.store.GetImageLayerInfo(ctx, req.Name, layers32ToLayers(req.Layers), req.Platforms)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	resp.LayerInfo = make([]*imagesapi.LayerInfo, len(lis))
	for i := 0; i < len(lis); i++ {
		resp.LayerInfo[i] = &imagesapi.LayerInfo{
			ID:         lis[i].Id,
			KeyIds:     lis[i].KeyIds,
			Digest:     lis[i].Digest,
			Encryption: lis[i].Encryption,
			FileSize:   lis[i].FileSize,
			Platform:   lis[i].Platform,
		}
	}

	return &resp, nil
}

func layers32ToLayers(layers []int32) []int {
	var l []int

	for _, layer := range layers{
		l = append(l, int(layer))
	}
	return l;
}
