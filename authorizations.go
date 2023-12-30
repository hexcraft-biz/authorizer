package authorizer

import (
	"path"

	"github.com/hexcraft-biz/xtime"
	"github.com/hexcraft-biz/xuuid"
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

func NewAuthorization(endpointId, custodianId xuuid.UUID, ct xtime.Time) *Authorization {
	return &Authorization{
		EndpointId:  endpointId,
		CustodianId: custodianId,
		Ctime:       ct,
		Mtime:       ct,
		AccessRules: new(AccessRules),
	}
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
