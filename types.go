package authorizer

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"path"

	"github.com/hexcraft-biz/xuuid"
)

// ================================================================
type AccessRules struct {
	Subsets    []string `json:"subsets"`
	Exceptions []string `json:"exceptions,omitempty"`
}

func (r *AccessRules) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("Type assertion to []byte failed")
	}

	return json.Unmarshal(bytes, r)
}

func (r *AccessRules) Value() (driver.Value, error) {
	r.RemoveRedundant()
	return json.Marshal(r)
}

func (r *AccessRules) AddSubset(rule string) {
	if rule != "*" {
		rule = path.Join("/", rule)
	}
	r.Subsets = append(r.Subsets, rule)
}

func (r *AccessRules) AddException(rule string) {
	if rule != "*" {
		rule = path.Join("/", rule)
	}
	r.Exceptions = append(r.Exceptions, rule)
}

func (r *AccessRules) RemoveRedundant() {
	r.Subsets = removeRedundant(r.Subsets)
	r.Exceptions = removeRedundant(r.Exceptions)
}

func (r *AccessRules) Merge(rules *AccessRules) {
	r.Subsets = append(r.Subsets, rules.Subsets...)
	r.Exceptions = append(r.Exceptions, rules.Exceptions...)
	r.RemoveRedundant()
}

func (r AccessRules) CanAccess(subset string) bool {
	if isCovered(subset, r.Subsets) {
		if isCovered(subset, r.Exceptions) {
			return false
		}
		return true
	}
	return false
}

// ================================================================
type AccessRulesWithBehavior struct {
	Behavior string `json:"behavior" db:"-" binding:"required"`
	*AuthorizationAction
}

func NewAccessRulesWithBehavior(behavior string, affectedEndpointId xuuid.UUID, accessRules *AccessRules) *AccessRulesWithBehavior {
	return &AccessRulesWithBehavior{
		Behavior: behavior,
		AuthorizationAction: &AuthorizationAction{
			AffectedEndpointId: affectedEndpointId,
			AccessRules:        accessRules,
		},
	}
}

type AuthorizationAction struct {
	AffectedEndpointId xuuid.UUID   `json:"affectedEndpointId" db:"endpoint_id" binding:"required"`
	AccessRules        *AccessRules `json:"accessRules" db:"access_rules" binding:"required"`
}

func (r *AccessRulesWithBehavior) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("Type assertion to []byte failed")
	}

	return json.Unmarshal(bytes, r)
}

func (r AccessRulesWithBehavior) Value() (driver.Value, error) {
	return json.Marshal(r)
}
