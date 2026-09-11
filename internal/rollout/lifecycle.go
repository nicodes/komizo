package rollout

import (
	"context"
	"errors"
	"reflect"
	"time"
)

// Retirement binds durable proof to one container incarnation. Stage advances
// only after a positive backend acknowledgement. Replays must be idempotent.
type Retirement struct {
	ID         string `json:"id"`
	StartedAt  string `json:"started_at"`
	Stage      string `json:"stage"`
	Absent     bool   `json:"absent,omitempty"`
	NotStarted bool   `json:"not_started,omitempty"`
}

func (e *Engine) confirmRoutes(ctx context.Context, tx *Transaction) error {
	op, cancel := context.WithTimeout(ctx, tx.Limits.Operation)
	defer cancel()
	current, epoch, err := e.Router.Current(op)
	if err != nil || epoch != tx.Epoch || !reflect.DeepEqual(current, tx.After) {
		return errors.New("routing or epoch changed; retirement refused")
	}
	return nil
}

func (e *Engine) retirementBudget(state *State) error {
	tx := state.Pending
	if tx.RetirementExceeded || !time.Now().Before(tx.SwitchStartedAt.Add(tx.Limits.Retire)) {
		tx.RetirementExceeded = true
		if err := e.Store.Save(state); err != nil {
			return err
		}
		return ErrRetirementBudget
	}
	return nil
}

func (e *Engine) retireInstance(ctx context.Context, state *State, i Instance, abort, quiesceOnly bool) error {
	tx := state.Pending
	if tx.Retirements == nil {
		tx.Retirements = map[string]Retirement{}
	}
	for {
		proof := tx.Retirements[i.Name]
		var action string
		switch proof.Stage {
		case "":
			action = "quiesce"
			if abort {
				action = "abort-quiesce"
			}
		case "quiesce":
			if quiesceOnly {
				return nil
			}
			action = "seal"
		case "seal":
			action = "drain"
		case "drain":
			action = "stop"
		case "stop":
			action = "remove"
		case "remove":
			return nil
		default:
			return errors.New("invalid retirement checkpoint")
		}
		if !abort {
			if err := e.retirementBudget(state); err != nil {
				return err
			}
			if err := e.confirmRoutes(ctx, tx); err != nil {
				return err
			}
			if !quiesceOnly {
				op, cancel := context.WithTimeout(ctx, tx.Limits.Operation)
				status, err := e.Router.Status(op, tx.Before.Generation)
				cancel()
				if err != nil || status.Epoch != tx.Epoch || status.Active || status.Requests != 0 {
					return errors.New("gateway drain proof lost; retirement refused")
				}
			}
		} else {
			op, cancel := context.WithTimeout(ctx, tx.Limits.Operation)
			current, _, err := e.Router.Current(op)
			cancel()
			if !tx.SwitchStartedAt.IsZero() || err != nil || !reflect.DeepEqual(current, tx.Before) {
				return errors.New("candidate routing is not confirmed pre-switch; abort retirement refused")
			}
		}
		op, cancel := context.WithTimeout(ctx, tx.Limits.Operation)
		next, err := e.Backend.Lifecycle(op, i, action, proof)
		cancel()
		if err != nil {
			return err
		}
		stage := action
		if action == "abort-quiesce" {
			stage = "quiesce"
		}
		if next.Stage != stage || (proof.Stage != "" && (next.ID != proof.ID || next.StartedAt != proof.StartedAt || next.Absent != proof.Absent || next.NotStarted != proof.NotStarted)) {
			return errors.New("backend lifecycle proof changed incarnation or stage")
		}
		if (next.Absent && (!abort || next.ID != "" || next.StartedAt != "")) || (!next.Absent && (next.ID == "" || next.StartedAt == "")) {
			return errors.New("backend lifecycle proof lacks a scoped incarnation")
		}
		if next.NotStarted && (!abort || next.Absent) {
			return errors.New("invalid never-started candidate proof")
		}
		tx.Retirements[i.Name] = next
		if err := e.Store.Save(state); err != nil {
			return err
		}
	}
}
