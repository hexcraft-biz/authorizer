package authorizer

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"

	"github.com/hexcraft-biz/feature"
	"github.com/hexcraft-biz/her"
	"github.com/hexcraft-biz/xuuid"
)

type Authorizer struct {
	AppCreeds   *url.URL
	HeaderInfix string
}

func New() (*Authorizer, error) {
	appCreeds, err := url.ParseRequestURI(os.Getenv("APP_CREEDS"))
	if err != nil {
		return nil, err
	}

	return &Authorizer{
		AppCreeds:   appCreeds,
		HeaderInfix: os.Getenv("HEADER_INFIX"),
	}, nil
}

func (a Authorizer) NewAmbit(eh *feature.EndpointHandler, custodianId, byCustodianId xuuid.UUID) *ambit {
	return &ambit{
		Authorizer:          &a,
		EndpointHandler:     eh,
		CustodianId:         custodianId,
		ByCustodianId:       byCustodianId,
		accessRulesToCommit: accessRulesToCommit{},
	}
}

type ambit struct {
	*Authorizer
	*feature.EndpointHandler
	CustodianId   xuuid.UUID
	ByCustodianId xuuid.UUID
	accessRulesToCommit
}

func (a *ambit) Assign(affectedEndpointId xuuid.UUID, rule string) {
	a.accessRulesToCommit.add(ActionAssign, rule, affectedEndpointId)
}

func (a *ambit) Grant(affectedEndpointId xuuid.UUID, rule string) {
	a.accessRulesToCommit.add(ActionGrant, rule, affectedEndpointId)
}

func (a *ambit) Revoke(affectedEndpointId xuuid.UUID, rule string) {
	a.accessRulesToCommit.add(ActionRevoke, rule, affectedEndpointId)
}

func (a ambit) Commit(headerInfix string) her.Error {
	if headerInfix == "" {
		return her.NewErrorWithMessage(http.StatusInternalServerError, "Header infix cannot be empty", nil)
	}

	rulesWithBehavior := a.toAccessRulesWithBehavior()

	if len(rulesWithBehavior) > 0 {
		jsonbytes, err := json.Marshal(rulesWithBehavior)
		if err != nil {
			return her.NewError(http.StatusInternalServerError, err, nil)
		}

		req, err := http.NewRequest("POST", a.AppCreeds.JoinPath("/permissions/v1/custodians", a.CustodianId.String()).String(), bytes.NewReader(jsonbytes))
		if err != nil {
			return her.NewError(http.StatusInternalServerError, err, nil)
		}

		req.Header.Set("X-"+a.HeaderInfix+"-Authenticated-User-Id", a.ByCustodianId.String())

		payload := her.NewPayload(nil)
		client := &http.Client{}

		if resp, err := client.Do(req); err != nil {
			return her.NewError(http.StatusInternalServerError, err, nil)
		} else if err := her.FetchHexcApiResult(resp, payload); err != nil {
			return err
		} else if resp.StatusCode != 201 {
			return her.NewErrorWithMessage(http.StatusInternalServerError, "Creeds: "+payload.Message, nil)
		}
	}

	return nil
}

// ================================================================
type accessRulesToCommit map[string]map[xuuid.UUID]*AccessRules

func (r *accessRulesToCommit) add(action int, rule string, affectedEndpointId xuuid.UUID) {
	behavior := ""
	switch action {
	case ActionGrant, ActionRevoke:
		behavior = WriteBehaviorOverwrite
	default:
		behavior = WriteBehaviorIdempotent
	}

	if _, ok := (*r)[behavior]; !ok {
		(*r)[behavior] = map[xuuid.UUID]*AccessRules{}
	}

	if _, ok := (*r)[behavior][affectedEndpointId]; !ok {
		(*r)[behavior][affectedEndpointId] = &AccessRules{}
	}

	switch action {
	case ActionAssign, ActionGrant:
		(*r)[behavior][affectedEndpointId].AddSubset(rule)
	case ActionRevoke:
		(*r)[behavior][affectedEndpointId].AddException(rule)
	}
}

func (r accessRulesToCommit) toAccessRulesWithBehavior() []*AccessRulesWithBehavior {
	rulesWithBehavior := []*AccessRulesWithBehavior{}
	for behavior, idAccessRules := range r {
		for affectedEndpointId, accessRules := range idAccessRules {
			accessRules.RemoveRedundant()
			rulesWithBehavior = append(rulesWithBehavior, &AccessRulesWithBehavior{
				Behavior: behavior,
				AuthorizationAction: &AuthorizationAction{
					AffectedEndpointId: affectedEndpointId,
					AccessRules:        accessRules,
				},
			})
		}
	}

	return rulesWithBehavior
}
