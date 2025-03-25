package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"github.com/sagernet/sing-box/common/humanize"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

func createHTTPReader(ctx context.Context, requestURL string) (*HTTPReader, int64, error) {
	client := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			Proxy:             http.ProxyFromEnvironment,
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("User-Agent", "curl/7.64.1")
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, 0, E.New("unexpected status: ", response.Status)
	}
	if response.ContentLength <= 0 {
		return nil, 0, E.New("unexpected content-length: ", response.ContentLength)
	}
	if response.Header.Get("Accept-Ranges") != "bytes" {
		return nil, 0, E.New("unexpected accept-ranges: ", response.Header.Get("Accept-Ranges"))
	}
	response.Body.Close()
	return NewHTTPReader(ctx, client, request, response.ContentLength), response.ContentLength, nil
}

var _ io.ReaderAt = (*HTTPReader)(nil)

type HTTPReader struct {
	ctx           context.Context
	client        *http.Client
	request       *http.Request
	contentLength int64
}

func NewHTTPReader(ctx context.Context, client *http.Client, request *http.Request, contentLength int64) *HTTPReader {
	return &HTTPReader{
		ctx:           ctx,
		client:        client,
		request:       request,
		contentLength: contentLength,
	}
}

func (r *HTTPReader) ReadAt(p []byte, off int64) (n int, err error) {
	request := r.request.Clone(r.ctx)
	var rangeEnd int64
	if off+int64(len(p)) > r.contentLength {
		rangeEnd = r.contentLength - 1
	} else {
		rangeEnd = off + int64(len(p)) - 1
	}
	request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, rangeEnd))
	log.Debug(request.Method, " ", filepath.Base(request.URL.Path), " ", off, "-", rangeEnd, " (", humanize.Bytes(uint64(rangeEnd-off)), ")")
	response, err := r.client.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	return io.ReadFull(response.Body, p)
}
