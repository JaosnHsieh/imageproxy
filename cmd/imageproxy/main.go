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

// imageproxy starts an HTTP server that proxies requests for remote images.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gregjones/httpcache"
	"github.com/gregjones/httpcache/diskcache"
	"github.com/peterbourgon/diskv"
	"../../"
)

// goxc values
var (
	// VERSION is the version string for imageproxy.
	VERSION = "HEAD"

	// BUILD_DATE is the timestamp of when imageproxy was built.
	BUILD_DATE string
)

var addr = flag.String("addr", "localhost:8080", "TCP address to listen on")
var whitelist = flag.String("whitelist", "", "comma separated list of allowed remote hosts")
var cacheDir = flag.String("cacheDir", "", "directory to use for file cache")
var cacheSize = flag.Uint64("cacheSize", 100, "maximum size of file cache (in MB)")
var version = flag.Bool("version", false, "print version information")
var secretSign = flag.String("secret_sign", "", "secret for md5(secret+remaining_url) signing")
var secretKey = flag.String("secret_key", "", "key for blowfish encryption of real url")

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("%v\nBuild: %v\n", VERSION, BUILD_DATE)
		return
	}

	var c httpcache.Cache
	if *cacheDir != "" {
		d := diskv.New(diskv.Options{
			BasePath:     *cacheDir,
			CacheSizeMax: *cacheSize * 1024 * 1024,
			Transform: func(s string) []string {
				return []string{ s[0:2],s[2:4]}
			},
			Index: nil,
		})
		c = diskcache.NewWithDiskv(d)
	} else {
		c = httpcache.NewMemoryCache()
	}

	p := imageproxy.NewProxy(nil, c, *secretSign, *secretKey)
	if *whitelist != "" {
		p.Whitelist = strings.Split(*whitelist, ",")
	}

	server := &http.Server{
		Addr:    *addr,
		Handler: p,
	}

	fmt.Printf("imageproxy (version %v) listening on %s\n", VERSION, server.Addr)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
