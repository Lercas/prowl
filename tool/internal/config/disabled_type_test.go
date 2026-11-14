package config

import "testing"

func TestDisabledTypeSpellingsAndPrecedence(t *testing.T) {
	c := &Config{}
	c.Detectors.Disable = []string{"  AWS-Access_KEY-id  "}
	c.Detectors.Enable = []string{"aws_access_key_id", "stripe_secret_key"}
	for _, id := range []string{"aws_access_key_id", "aws-access-key-id", "AWS_ACCESS_KEY_ID"} {
		if !c.TypeDisabled(id) || c.TypeEnabled(id) {
			t.Fatalf("disable did not win over enable for %q", id)
		}
	}
	if !c.TypeEnabled("stripe_secret_key") || c.TypeDisabled("stripe-secret-key") {
		t.Fatal("unrelated detector disabled")
	}
	if c.TypeEnabled("STRIPE-SECRET-KEY") {
		t.Fatal("enable unexpectedly changed its exact-match contract")
	}
	if (*Config)(nil).TypeDisabled("aws_access_key_id") || !(*Config)(nil).TypeEnabled("aws_access_key_id") {
		t.Fatal("nil config changed defaults")
	}
}
