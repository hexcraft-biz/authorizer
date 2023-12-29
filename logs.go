package authorizer

import (
	"database/sql/driver"
	"encoding/json"
	"errors"

	"github.com/hexcraft-biz/xtime"
	"github.com/hexcraft-biz/xuuid"
)

type AuthorizationLog struct {
	AuthorizationLogId  xuuid.UUID           `json:"authorizationLogId" db:"authorization_log_id" binding:"-"`
	Ctime               xtime.Time           `json:"createdAt" db:"ctime" binding:"-"`
	AffectedCustodianId xuuid.UUID           `json:"affectedCustodianId" db:"affected_custodian_id" binding:"-"`
	ByCustodianId       xuuid.UUID           `json:"byCustodianId"  db:"by_custodian_id" binding:"-"`
	Actions             AuthorizationActions `json:"actions" db:"actions" binding:"-"`
}

func NewAuthorizationLog(ct xtime.Time, affectedCustodianId, byCustodianId xuuid.UUID, actions AuthorizationActions) *AuthorizationLog {
	return &AuthorizationLog{
		AuthorizationLogId:  xuuid.New(),
		Ctime:               ct,
		AffectedCustodianId: affectedCustodianId,
		ByCustodianId:       byCustodianId,
		Actions:             actions,
	}
}

// ================================================================
type AuthorizationActions map[string][]*AuthorizationAction

func (r *AuthorizationActions) Add(arb *AccessRulesWithBehavior) {
	if _, ok := (*r)[arb.Behavior]; !ok {
		(*r)[arb.Behavior] = []*AuthorizationAction{}
	}

	(*r)[arb.Behavior] = append((*r)[arb.Behavior], arb.AuthorizationAction)
}

func (r *AuthorizationActions) Scan(value any) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("Type assertion to []byte failed")
	}

	return json.Unmarshal(bytes, r)
}

func (r AuthorizationActions) Value() (driver.Value, error) {
	return json.Marshal(r)
}
