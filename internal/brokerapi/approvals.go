package brokerapi

import (
	"errors"
	"regexp"
	"time"
)

// ApprovalDecision names the exact request a human reviewed, never a caller-supplied prompt.
type ApprovalDecision struct {
	Token    string `json:"token"`
	Digest   string `json:"digest"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// ApprovalEntry contains the request and review digest, without signing material.
type ApprovalEntry struct {
	Token       string    `json:"token"`
	Actor       string    `json:"actor"`
	Capability  string    `json:"capability"`
	Connection  string    `json:"connection"`
	Summary     string    `json:"summary"`
	RequestHash string    `json:"request_hash"`
	Digest      string    `json:"digest"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

var approvalToken = regexp.MustCompile(`^apv_[0-9a-f]{32}$`)

func (r Request) validateApproval() error {
	if r.Op == OpApprovalList {
		if r.Approval != nil {
			return errors.New("approval.list takes no decision")
		}
		return nil
	}
	d := r.Approval
	if d == nil || !approvalToken.MatchString(d.Token) || len(d.Digest) != 64 || !isHex(d.Digest) {
		return errors.New("approval.decide needs a token and reviewed request digest")
	}
	if d.Decision != "approve" && d.Decision != "deny" {
		return errors.New("decision must be approve or deny")
	}
	if len(d.Reason) > 2048 {
		return errors.New("approval reason is too long")
	}
	return nil
}
