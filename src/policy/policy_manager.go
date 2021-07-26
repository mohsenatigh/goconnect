package policy

import "sync"

//---------------------------------------------------------------------------------------

type cPolicyManager struct {
	objects map[string]cPolicy
	lock    sync.RWMutex
}
