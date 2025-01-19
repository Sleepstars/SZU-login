// Copyright 2021 E99p1ant. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"

	log "unknwon.dev/clog/v2"

	"github.com/Sleepstars/SZU-login/pkg/srun"
)

func main() {
	defer log.Stop()
	err := log.NewConsole()
	if err != nil {
		panic(err)
	}

	host := flag.String("host", "https://net.szu.edu.cn/", "")
	username := flag.String("username", "", "")
	password := flag.String("password", "", "")
	flag.Parse()

	client := srun.NewClient(*host, *username, *password)
	challengeResp, err := client.GetChallenge()
	if err != nil {
		log.Fatal("Failed to get challenge %v", err)
	}
	challenge := challengeResp.Challenge
	log.Trace("Challenge: %q", challenge)

	portalResp, err := client.Portal(challengeResp.Challenge)
	if err != nil {
		log.Fatal("Failed to portal: %v", err)
	}
	log.Trace("%+v", portalResp)
}
