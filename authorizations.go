package authorizer

import (
	"net/http"
	"path"

	"github.com/hexcraft-biz/her"
	"github.com/hexcraft-biz/xscope"
	"github.com/hexcraft-biz/xtime"
	"github.com/hexcraft-biz/xuuid"
	"github.com/jmoiron/sqlx"
)

type AuthorizationOnDuplicateKeyUpdate struct {
	*Authorization
	MMtime       xtime.Time   `db:"m_mtime`
	MAccessRules *AccessRules `db:"m_access_rules"`
}

type Authorization struct {
	EndpointId  xuuid.UUID   `db:"endpoint_id"`
	CustodianId xuuid.UUID   `db:"custodian_id"`
	Ctime       xtime.Time   `db:"ctime"`
	Mtime       xtime.Time   `db:"mtime"`
	AccessRules *AccessRules `db:"access_rules"`
}

type scopeEndpoints struct {
	ScopeId    string     `db:"scope_id"`
	EndpointId xuuid.UUID `db:"endpoint_id"`
}

func NewAuthorizations(db *sqlx.DB, scopes xscope.Slice, custodianId xuuid.UUID, ct xtime.Time) (map[string][]*Authorization, her.Error) {
	q := `SELECT scope_id, endpoint_id FROM scope_endpoints WHERE scope_id IN (` + scopes.GetVarPlaceholder() + `)`
	rows := []*scopeEndpoints{}
	if err := db.Select(&rows, q, scopes.AnySlice()...); err != nil {
		return nil, her.NewError(http.StatusInternalServerError, err, nil)
	}

	result := map[string][]*Authorization{}
	for _, r := range rows {
		if _, ok := result[r.ScopeId]; !ok {
			result[r.ScopeId] = []*Authorization{}
		}

		result[r.ScopeId] = append(result[r.ScopeId], &Authorization{
			EndpointId:  r.EndpointId,
			CustodianId: custodianId,
			Ctime:       ct,
			Mtime:       ct,
			AccessRules: new(AccessRules),
		})
	}

	return result, nil
}

func (a Authorization) OnDuplicateKeyUpdate(mt xtime.Time, accessRules *AccessRules) *AuthorizationOnDuplicateKeyUpdate {
	return &AuthorizationOnDuplicateKeyUpdate{
		Authorization: &a,
		MMtime:        mt,
		MAccessRules:  accessRules,
	}
}

func (a *Authorization) AddSubset(rule string) {
	if rule != "*" {
		rule = path.Join("/", rule)
	}
	a.AccessRules.Subsets = append(a.AccessRules.Subsets, rule)
}

func (a *Authorization) AddException(rule string) {
	if rule != "*" {
		rule = path.Join("/", rule)
	}
	a.AccessRules.Exceptions = append(a.AccessRules.Exceptions, rule)
}
