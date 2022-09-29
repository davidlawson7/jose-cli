package jwe

import (
	"testing"
)

// TestGetJWTClaimFromJWE calls jwe.GetJWTClaimFromJWE, checking for
// successfully decrypting and decoding a jwe containing a jwt.
func TestGetJWTClaimFromJWE(t *testing.T) {
	jwe := "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiZGlyIn0..BN37qb3lHvK0U09V.__jpm4K1q1fG5Yq-ExqkE13EgFYj6CZkPxl3YLBzAgM44GcH5Vpu3XFBDdEpCxu5etCjdfV1H2KdaB0tYWnIy9Bmz8Th2DsSTU3XuinIUE-E2pAJce9CF4EIE_4GdbNO7uDnkCJn92VUiUIDrrJ6nzrD0U-CNEnKTdueF3Ud6RHhN2EvEXTZv79XdI65ZtwiD0Tff4M1ZRCBiM6W7coIv05Be0wAYPNRKWmCSFgrJdOkhFUv9gg0AyGBeBmDZACNIE7hl0riC43Flr-WIggWS6dKTXcitFPzWDhZhDSzx3uaqVzb7XXdNtVzVeIYDQMjiS47hFgeyPkr6Q5s8v4S9C2Y3BgpGQ1ZLToYQWYUZ9FIs_HEDno8SugjwktRkxpZjykhzyb_gGZ6X9RzTZfMAbkyFresNKd7oT5zD8YqZpmKllseqgafWFZx7L7-zpA.RzAFrCvLQrRLoozsO3zCcg"
	secret := "8cjIS833RQ49lDtlWVoUURL8qyyLKeOb"
	claim, err := GetJWTClaimFromJWE(jwe, secret)

	if *claim != `{"sub":"202.56.61.2","appBrand":"BUDD","appName":"claims","backendApiAccessToken":"SSAQ_CHORH4G7BAVNXEDJCJ","iss":"\/authentication\/token","iat":1663855200,"jti":"2f85798f-27fd-4d8b-bfeb-be2d8459738c"}` || err != nil {
		t.Fatalf(`GetJWTClaimFromJWE threw a error, %v`, err)
	}
}