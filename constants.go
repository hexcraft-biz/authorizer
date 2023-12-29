package authorizer

const (
	ActionAssign int = iota
	ActionGrant
	ActionRevoke
)

const (
	WriteBehaviorCreate     = "CREATE"
	WriteBehaviorIdempotent = "IDEMPOTENT"
	WriteBehaviorOverwrite  = "OVERWRITE"
)
