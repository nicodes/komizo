package workload

import (
	"bytes"
	_ "embed"
	"encoding/json"
)

//go:embed operation-contract.json
var operationContract []byte

type OperationPhase struct {
	Decision               string `json:"decision"`
	ReconciliationRequired bool   `json:"reconciliation_required"`
}

var operationPhases = func() map[string]OperationPhase {
	var contract struct {
		Version int                       `json:"version"`
		Phases  map[string]OperationPhase `json:"phases"`
	}
	if json.Unmarshal(operationContract, &contract) != nil || contract.Version != 1 || len(contract.Phases) != 12 {
		panic("invalid compiled operation contract")
	}
	return contract.Phases
}()

func KnownOperationPhase(phase string) bool {
	_, known := operationPhases[phase]
	return known
}

// OperationContract returns the producer's versioned public vocabulary. It
// contains no private operation bodies and callers cannot mutate the producer.
func OperationContract() []byte { return bytes.Clone(operationContract) }
