package core

import (
	"encoding/json"
	"fmt"

	"github.com/KKingZero/ARK/pkg/agent"
)

// EmitJSONStep prints one agent step as JSON (console -json mode).
func EmitJSONStep(step agent.StepOutput) {
	b, _ := json.Marshal(step)
	fmt.Println(string(b))
}