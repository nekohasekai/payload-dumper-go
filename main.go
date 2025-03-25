package main

import (
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/huh/spinner"
	"github.com/charmbracelet/lipgloss"
	"github.com/golang/protobuf/proto"
	"github.com/nekohasekai/android-ota-extractor/chromeos_update_engine"
	"github.com/sagernet/sing-box/common/humanize"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/binary"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/spf13/cobra"
	"github.com/xi2/xz"
)

var flagOutputDirectory string

var rootCmd = &cobra.Command{
	Use:  "android-ota-extractor <source>",
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := run(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
}

func main() {
	rootCmd.Flags().StringVarP(&flagOutputDirectory, "output", "o", ".", "Output directory")
	rootCmd.Execute()
}

func run(source string) error {
	spinnerCtx, done := context.WithCancel(context.Background())
	defer done()
	go spinner.New().
		Type(spinner.Line).
		Title(lipgloss.NewStyle().Foreground(lipgloss.Color("227")).Render(" Fetch metadata")).
		Context(spinnerCtx).
		Run()
	var (
		reader io.ReaderAt
		length int64
		err    error
	)
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		reader, length, err = createHTTPReader(context.Background(), source)
		if err != nil {
			return err
		}
	} else {
		file, err := os.Open(source)
		if err != nil {
			return err
		}
		stat, err := file.Stat()
		if err != nil {
			return err
		}
		reader = file
		length = stat.Size()
	}
	isZIP, err := checkZIP(reader)
	if err != nil {
		return err
	}
	var sectionReader *io.SectionReader
	if isZIP {
		zipReader, err := zip.NewReader(reader, length)
		if err != nil {
			return err
		}
		zipFile := common.Find(zipReader.File, func(it *zip.File) bool {
			return it.Name == "payload.bin"
		})
		if zipFile == nil {
			return E.New("missing payload.bin in zip")
		}
		if zipFile.Method != zip.Store {
			return E.New("unsupported compression")
		}
		rawReader, err := zipFile.OpenRaw()
		if err != nil {
			return err
		}
		sectionReader = rawReader.(*io.SectionReader)
	} else {
		sectionReader = io.NewSectionReader(reader, 0, length)
	}
	const payloadMagic = "CrAU"
	const brilloMajorPayloadVersion = 2
	magic := make([]byte, len(payloadMagic))
	_, err = io.ReadFull(sectionReader, magic)
	if err != nil {
		return err
	} else if string(magic) != payloadMagic {
		return E.New("invalid payload.bin header")
	}
	// version & lengths
	var version, manifestLen uint64
	var metadataSigLen uint32
	err = binary.Read(sectionReader, binary.BigEndian, &version)
	if err != nil || version != brilloMajorPayloadVersion {
		return E.New("invalid payload version")
	}
	err = binary.Read(sectionReader, binary.BigEndian, &manifestLen)
	if err != nil || !(manifestLen > 0) {
		return E.New("invalid manifest length")
	}
	err = binary.Read(sectionReader, binary.BigEndian, &metadataSigLen)
	if err != nil || !(metadataSigLen > 0) {
		return E.New("invalid metadata signature")
	}
	// manifest
	manifestRaw := make([]byte, manifestLen)
	n, err := sectionReader.Read(manifestRaw)
	if err != nil || uint64(n) != manifestLen {
		return E.New("invalid manifest")
	}
	var manifest chromeos_update_engine.DeltaArchiveManifest
	err = proto.Unmarshal(manifestRaw, &manifest)
	if err != nil {
		return E.Cause(err, "parse manifest")
	}
	done()
	var options []huh.Option[*chromeos_update_engine.PartitionUpdate]
	for _, partition := range manifest.Partitions {
		var updateSize int64
		for _, op := range partition.Operations {
			if op.DataLength != nil {
				updateSize += int64(*op.DataLength)
			} else if op.DstExtents != nil {
				for _, ext := range op.DstExtents {
					updateSize += int64(*ext.NumBlocks * uint64(*manifest.BlockSize))
				}
			}
		}
		options = append(options, huh.NewOption[*chromeos_update_engine.PartitionUpdate](F.ToString(*partition.PartitionName, " (", humanize.Bytes(uint64(updateSize)), "/", humanize.Bytes(*partition.NewPartitionInfo.Size), ")"), partition))
	}
	var selected []*chromeos_update_engine.PartitionUpdate
	err = huh.NewMultiSelect[*chromeos_update_engine.PartitionUpdate]().
		Options(options...).
		Height(10).
		Title(lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Render(F.ToString(" Select the images you want to download [", humanize.Bytes(uint64(length)), "]"))).
		Value(&selected).
		WithTheme(huh.ThemeBase16()).
		Run()
	if len(selected) == 0 {
		return nil
	}
	for _, partition := range selected {
		err = spinner.New().
			Type(spinner.Line).
			Title(lipgloss.NewStyle().Foreground(lipgloss.Color("227")).Render(" Extracting " + *partition.PartitionName)).
			ActionWithErr(func(ctx context.Context) error {
				return extractPartition(partition, sectionReader, 24+manifestLen+uint64(metadataSigLen), *manifest.BlockSize)
			}).
			Accessible(false).
			Context(context.Background()).
			Run()
		if err != nil {
			return err
		}
	}
	return nil
}

func checkZIP(reader io.ReaderAt) (bool, error) {
	const zipMagic = "PK"
	header := make([]byte, len(zipMagic))
	_, err := reader.ReadAt(header, 0)
	return string(header) == zipMagic, err
}

func extractPartition(p *chromeos_update_engine.PartitionUpdate, r *io.SectionReader, baseOffset uint64, blockSize uint32) error {
	outFile, err := os.Create(filepath.Join(flagOutputDirectory, F.ToString(*p.PartitionName, ".img")))
	if err != nil {
		return err
	}
	for _, op := range p.Operations {
		var (
			data       []byte
			outSeekPos int64
		)
		if op.DataLength != nil {
			data = make([]byte, *op.DataLength)
			_, err = r.ReadAt(data, int64(baseOffset+*op.DataOffset))
			if err != nil {
				return err
			}
			outSeekPos = int64(*op.DstExtents[0].StartBlock * uint64(blockSize))
			_, err = outFile.Seek(outSeekPos, 0)
			if err != nil {
				_ = outFile.Close()
				return err
			}
		}

		switch *op.Type {
		case chromeos_update_engine.InstallOperation_REPLACE:
			_, err = outFile.Write(data)
			if err != nil {
				_ = outFile.Close()
				return err
			}
		case chromeos_update_engine.InstallOperation_REPLACE_BZ:
			bzr := bzip2.NewReader(bytes.NewReader(data))
			_, err = io.Copy(outFile, bzr)
			if err != nil {
				_ = outFile.Close()
				return err
			}
		case chromeos_update_engine.InstallOperation_REPLACE_XZ:
			xzr, err := xz.NewReader(bytes.NewReader(data), 0)
			if err != nil {
				_ = outFile.Close()
				return err
			}
			_, err = io.Copy(outFile, xzr)
			if err != nil {
				_ = outFile.Close()
				return err
			}
		case chromeos_update_engine.InstallOperation_ZERO:
			for _, ext := range op.DstExtents {
				outSeekPos = int64(*ext.StartBlock * uint64(blockSize))
				_, err = outFile.Seek(outSeekPos, 0)
				if err != nil {
					_ = outFile.Close()
					return err
				}
				// write zeros
				_, err = io.Copy(outFile, bytes.NewReader(make([]byte, *ext.NumBlocks*uint64(blockSize))))
				if err != nil {
					_ = outFile.Close()
					return err
				}
			}
		default:
			_ = outFile.Close()
			return E.New("unsupported operation: " + op.Type.String())
		}
	}
	return nil
}
