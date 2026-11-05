package brokerapi

import (
	"strings"
	"testing"
)

func TestApprovalDecisionDecodeRequiresExactReview(t *testing.T) {
	valid := func() Request {
		return Request{Op: OpApprovalDecide, Approval: &ApprovalDecision{Token: "apv_" + strings.Repeat("a", 32), Digest: strings.Repeat("b", 64), Decision: "approve"}}
	}
	if _, err := Decode(frame(t, valid())); err != nil {
		t.Fatal(err)
	}
	deny := valid()
	deny.Approval.Decision = "deny"
	if _, err := Decode(frame(t, deny)); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(frame(t, Request{Op: OpApprovalList})); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Request){
		func(r *Request) { r.Approval = nil },
		func(r *Request) { r.Approval.Token = "../approval" },
		func(r *Request) { r.Approval.Digest = "" },
		func(r *Request) { r.Approval.Digest = strings.Repeat("z", 64) },
		func(r *Request) { r.Approval.Decision = "allow-all" },
		func(r *Request) { r.Approval.Reason = strings.Repeat("x", 2049) },
		func(r *Request) { r.Op = OpApprovalList },
	} {
		req := valid()
		mutate(&req)
		if _, err := Decode(frame(t, req)); err == nil {
			t.Fatalf("accepted malformed decision: %+v", req)
		}
	}
	if _, err := Decode([]byte(`{"op":"approval.decide","approval":{"token":"apv_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","decision":"approve","presence_digest":"forged"}}`)); err == nil {
		t.Fatal("accepted client-supplied presence proof")
	}
}
