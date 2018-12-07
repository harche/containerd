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
	b64 "encoding/base64"
	"fmt"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/containerd/containerd/cmd/ctr/commands/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var pullCommand = cli.Command{
	Name:      "pull",
	Usage:     "pull an image from a remote",
	ArgsUsage: "[flags] <ref>",
	Description: `Fetch and prepare an image for use in containerd.

After pulling an image, it should be ready to use the same reference in a run
command. As part of this process, we do the following:

1. Fetch all resources into containerd.
2. Prepare the snapshot filesystem with the pulled resources.
3. Register metadata for the image.
`,
	Flags: append(append(append(commands.RegistryFlags, append(commands.SnapshotterFlags, commands.LabelFlag)...),
		cli.StringSliceFlag{
			Name:  "platform",
			Usage: "Pull content from a specific platform",
			Value: &cli.StringSlice{},
		},
		cli.BoolFlag{
			Name:  "all-platforms",
			Usage: "pull content from all platforms",
		},
	), commands.ImageDecryptionFlags...,
	),
	Action: func(context *cli.Context) error {
		var (
			ref = context.Args().First()
		)
		if ref == "" {
			return fmt.Errorf("please provide an image reference to pull")
		}

		client, ctx, cancel, err := commands.NewClient(context)
		if err != nil {
			return err
		}
		defer cancel()

		ctx, done, err := client.WithLease(ctx)
		if err != nil {
			return err
		}
		defer done(ctx)

		config, err := content.NewFetchConfig(ctx, context)
		if err != nil {
			return err
		}
		img, err := content.Fetch(ctx, client, ref, config)
		if err != nil {
			return err
		}

		log.G(ctx).WithField("image", ref).Debug("unpacking")

		// TODO: Show unpack status

		var p []ocispec.Platform
		if context.Bool("all-platforms") {
			p, err = images.Platforms(ctx, client.ContentStore(), img.Target)
			if err != nil {
				return errors.Wrap(err, "unable to resolve image platforms")
			}
		} else {
			for _, s := range context.StringSlice("platform") {
				ps, err := platforms.Parse(s)
				if err != nil {
					return errors.Wrapf(err, "unable to parse platform %s", s)
				}
				p = append(p, ps)
			}
		}
		if len(p) == 0 {
			p = append(p, platforms.DefaultSpec())
		}

		if err != nil {
			return err
		}

		layers32 := commands.IntToInt32Array(context.IntSlice("layer"))

		layerInfos, err := getImageLayerInfo(client, ctx, img.Name, layers32, context.StringSlice("platform"))
		if err != nil {
			return err
		}

		isEncrypted := false
		for i := 0; i < len(layerInfos); i++ {
			if len(layerInfos[i].Descriptor.Annotations) > 0 {
				isEncrypted = true
				break
			}
		}

		for _, platform := range p {
			fmt.Printf("unpacking %s %s...\n", platforms.Format(platform), img.Target.Digest)
			i := containerd.NewImageWithPlatform(client, img, platforms.Only(platform))

			if isEncrypted {
				dcKeys, _ := CreateDcParameters(context, layerInfos)
				var dcparameters []string

				gpgKeys := dcKeys["gpg-privatekeys"]
				gpgKeysPasswd := dcKeys["gpg-privatekeys-passwords"]
				for idx, gpgKey := range gpgKeys {
					base64GpgKey := b64.StdEncoding.EncodeToString(gpgKey)
					base64GpgKeyPasswd := b64.StdEncoding.EncodeToString(gpgKeysPasswd[idx])
					dcparameters = append(dcparameters, base64GpgKey+":"+base64GpgKeyPasswd)
				}

				privKeys := dcKeys["privkeys"]
				privateKeysPasswd := dcKeys["privkeys-passwords"]
				for idx, privKey := range privKeys {
					base64GpgKey := b64.StdEncoding.EncodeToString(privKey)
					base64GpgKeyPasswd := b64.StdEncoding.EncodeToString(privateKeysPasswd[idx])
					dcparameters = append(dcparameters, base64GpgKey+":"+base64GpgKeyPasswd)
				}

				i.SetDecryptionParameters(dcparameters)

			}
			err = i.Unpack(ctx, context.String("snapshotter"))
			if err != nil {
				return err
			}
		}

		fmt.Println("done")
		return nil
	},
}
