// Copyright 2013 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package imageproxy provides an image proxy server.  For typical use of
// creating and using a Proxy, see cmd/imageproxy/main.go.
package imageproxy // import "willnorris.com/go/imageproxy"

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
	"crypto/md5"
	"encoding/base64"
	"crypto/cipher"
	"golang.org/x/crypto/blowfish"
	"github.com/golang/glog"
	"github.com/gregjones/httpcache"
)

// Proxy serves image requests.
//
// Note that a Proxy should not be run behind a http.ServeMux, since the
// ServeMux aggressively cleans URLs and removes the double slash in the
// embedded request URL.
type Proxy struct {
	Client *http.Client // client used to fetch remote URLs
	Cache  Cache        // cache used to cache responses

	// Whitelist specifies a list of remote hosts that images can be
	// proxied from.  An empty list means all hosts are allowed.
	Whitelist []string
	SecretSign string
	cipher *blowfish.Cipher 
}

// NewProxy constructs a new proxy.  The provided http RoundTripper will be
// used to fetch remote URLs.  If nil is provided, http.DefaultTransport will
// be used.
func NewProxy(transport http.RoundTripper, cache Cache, secretSign string, secretKey string) *Proxy {
	if transport == nil {
		transport = http.DefaultTransport
	}
	if cache == nil {
		cache = NopCache
	}

	client := new(http.Client)
	client.Transport = &Transport{
		Transport:           &TransformingTransport{transport, client},
		Cache:               cache,
		MarkCachedResponses: true,
	}

	var pcipher *blowfish.Cipher = nil
	if len(secretKey)>0 {
		tcipher, err := blowfish.NewCipher([]byte(secretKey))
		pcipher = tcipher
		if err != nil {
			panic(err)
		}
	}
	return &Proxy{
		Client: client,
		Cache:  cache,
		SecretSign: secretSign,
		cipher: pcipher,
	}
}

// works similar to nginx's secure_link
func (p *Proxy) getSignature(url string) string {
	hasher := md5.New()
	hasher.Write([]byte(p.SecretSign))
	hasher.Write([]byte(url))
	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func crypt_pad(pt []byte) []byte {
	// calculate modulus of plaintext to blowfish's cipher block size
	// if result is not 0, then we need to pad
	modulus := len(pt) % blowfish.BlockSize
	if modulus != 0 {
		// how many bytes do we need to pad to make pt to be a multiple of blowfish's block size?
		padlen := blowfish.BlockSize - modulus
		// let's add the required padding
		for i := 0; i < padlen; i++ {
			// add the pad, one at a time
			pt = append(pt, 0)
		}
	}
	// return the whole-multiple-of-blowfish.BlockSize-sized plaintext to the calling function
	return pt
}
var crypt_iv []byte = []byte("nosecure")
func decryptUrl(pcipher *blowfish.Cipher, url string) string {
	decoded,err:=base64.URLEncoding.DecodeString(url)
	if (err != nil) {
		return ""
	}
	decoded = crypt_pad(decoded)

	dcbc := cipher.NewCBCDecrypter(pcipher, crypt_iv)
	dcbc.CryptBlocks(decoded, decoded)
	decoded = bytes.Trim(decoded, "\x00")
	return string(decoded)
}

// ServeHTTP handles image requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/favicon.ico" {
		return // ignore favicon requests
	}

	if len(p.SecretSign) > 0 {
		segments := strings.SplitN(r.URL.Path, "/", 3)
		r.URL.Path = segments[0]+"/"+segments[2]
		signature := segments[1]
		if signature != p.getSignature(segments[2]) {
			msg := fmt.Sprintf("invalid signature")
			glog.Error(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
	}

	if p.cipher != nil {
		segments := strings.SplitN(r.URL.Path, "/", 3)
		str := decryptUrl(p.cipher, segments[2])
		if len(str) == 0 {
			msg := fmt.Sprintf("error while decrypting")
			glog.Error(msg)
			http.Error(w, msg, http.StatusBadRequest)
		}
		r.URL.Path = segments[0]+"/"+segments[1]+"/"+str
	}

	req, err := NewRequest(r)
	if err != nil {
		msg := fmt.Sprintf("invalid request URL: %v", err)
		glog.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	if !p.allowed(req.URL) {
		msg := fmt.Sprintf("remote URL is not for an allowed host: %v", req.URL)
		glog.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	u := req.URL.String()
	if req.Options != emptyOptions {
		u += "#" + req.Options.String()
	}

	resp, err := p.Client.Get(u)
	if err != nil {
		msg := fmt.Sprintf("error fetching remote image: %v", err)
		glog.Error(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	cached := resp.Header.Get(httpcache.XFromCache)
	glog.Infof("request: %v (served from cache: %v)", *req, cached == "1")

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("remote URL %q returned status: %v", req.URL, resp.Status)
		glog.Error(msg)
		http.Error(w, msg, resp.StatusCode)
		return
	}

	copyHeader(w, resp, "Last-Modified")
	copyHeader(w, resp, "Expires")
	copyHeader(w, resp, "Etag")

	if is304 := check304(r, resp); is304 {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	copyHeader(w, resp, "Content-Length")
	copyHeader(w, resp, "Content-Type")
	io.Copy(w, resp.Body)
}

func copyHeader(w http.ResponseWriter, r *http.Response, header string) {
	key := http.CanonicalHeaderKey(header)
	if value, ok := r.Header[key]; ok {
		w.Header()[key] = value
	}
}

// allowed returns whether the specified URL is on the whitelist of remote hosts.
func (p *Proxy) allowed(u *url.URL) bool {
	if len(p.Whitelist) == 0 {
		return true
	}

	for _, host := range p.Whitelist {
		if u.Host == host {
			return true
		}
		if strings.HasPrefix(host, "*.") && strings.HasSuffix(u.Host, host[2:]) {
			return true
		}
	}

	return false
}

// check304 checks whether we should send a 304 Not Modified in response to
// req, based on the response resp.  This is determined using the last modified
// time and the entity tag of resp.
func check304(req *http.Request, resp *http.Response) bool {
	// TODO(willnorris): if-none-match header can be a comma separated list
	// of multiple tags to be matched, or the special value "*" which
	// matches all etags
	etag := resp.Header.Get("Etag")
	if etag != "" && etag == req.Header.Get("If-None-Match") {
		return true
	}

	lastModified, err := time.Parse(time.RFC1123, resp.Header.Get("Last-Modified"))
	if err != nil {
		return false
	}
	ifModSince, err := time.Parse(time.RFC1123, req.Header.Get("If-Modified-Since"))
	if err != nil {
		return false
	}
	if lastModified.Before(ifModSince) {
		return true
	}

	return false
}

// TransformingTransport is an implementation of http.RoundTripper that
// optionally transforms images using the options specified in the request URL
// fragment.
type TransformingTransport struct {
	// Transport is the underlying http.RoundTripper used to satisfy
	// non-transform requests (those that do not include a URL fragment).
	Transport http.RoundTripper

	// CachingClient is used to fetch images to be resized.  This client is
	// used rather than Transport directly in order to ensure that
	// responses are properly cached.
	CachingClient *http.Client
}

// RoundTrip implements the http.RoundTripper interface.
func (t *TransformingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Fragment == "" {
		// normal requests pass through
		glog.Infof("fetching remote URL: %v", req.URL)
		return t.Transport.RoundTrip(req)
	}

	u := *req.URL
	u.Fragment = ""
	glog.Infof("getting from caching client: %v", u.String())
	resp, err := t.CachingClient.Get(u.String())
	glog.Infof("got from caching client: %v", u.String())
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	opt := ParseOptions(req.URL.Fragment)
	img, err := Transform(b, opt)
	if err != nil {
		glog.Errorf("error transforming image: %v", err)
		img = b
	}

	// replay response with transformed image and updated content length
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "%s %s\n", resp.Proto, resp.Status)
	resp.Header.WriteSubset(buf, map[string]bool{"Content-Length": true})
	fmt.Fprintf(buf, "Content-Length: %d\n\n", len(img))
	buf.Write(img)

	return http.ReadResponse(bufio.NewReader(buf), req)
}
