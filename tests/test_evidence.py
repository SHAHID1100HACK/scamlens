import asyncio, pytest
from app.evidence import analyze_evidence, evidence_score, lookalike, extract_urls


def sig(text):
    items, _ = asyncio.run(analyze_evidence(text, use_rdap=False))
    return {i.signal for i in items}, evidence_score(items)

@pytest.mark.parametrize("text,expected", [
    ("Pay Rs 1,500 refundable registration fee via UPI today to confirm.", "advance_fee"),
    ("A processing fee of Rs 4,500 is needed to claim your reward.", "advance_fee"),
    ("Please share your OTP to verify the refund.", "credential_request"),
    ("Download AnyDesk and share the 9 digit code so we can fix it.", "credential_request"),
    ("Pay with gift cards from the store, any amount is fine.", "risky_payment"),
    ("Scan this QR to receive your refund now.", "risky_payment"),
    ("Contact me on Telegram for the next steps of the job.", "off_platform_contact"),
    ("Act now, your account will be blocked within 2 hours.", "urgency_pressure"),
    ("This is the cyber crime department calling about your case.", "authority_claim"),
    ("Do not tell anyone about this call, stay on the call.", "secrecy_request"),
    ("Earn Rs 8000 per day working from home, no experience needed.", "too_good_to_be_true"),
])
def test_positive(text, expected):
    assert expected in sig(text)[0]

@pytest.mark.parametrize("text", [
    "Your interview is scheduled for Tuesday 11:00 AM on Google Meet. The link is in your calendar invite.",
    "Rs 2,400 debited from your account ending 1234 at a grocery store on 05-Oct. If not you, call the number on your card.",
    "Your electricity bill of Rs 1,120 is due on 12 Oct. Pay through the official app or authorised counter.",
    "Hi, is the sofa still available? Could you do 8000 if I pick it up on Saturday?",
    "Your OTP for login is 482913. Do not share it with anyone.",
    "Lunch at 1 pm tomorrow? The new cafe near the library looks nice.",
])
def test_genuine_has_no_hard_signals(text):
    s, score = sig(text)
    assert not s & {"advance_fee", "credential_request"}
    assert score < 30

def test_lookalikes():
    assert lookalike("amaz0n.com")[0]
    assert lookalike("sbi-kyc-update.xyz")[0]
    assert lookalike("paytm-offers.top")[0]
    assert not lookalike("amazon.in")[0]
    assert not lookalike("example.com")[0]

def test_url_signals():
    s, _ = sig("Verify now: http://192.168.4.2/login or http://bit.ly/abc123 or https://xn--pypal-4ve.com/x")
    assert {"url_ip_literal", "url_shortener", "url_homoglyph_punycode"} <= s

def test_defanged_urls_extracted():
    assert extract_urls("go to hxxp://bad-site[.]xyz/login now")

def test_regex_stress_is_fast():
    import time
    t = time.time(); sig("pay " + "rs " * 1500 + "fee " * 1500 + "a" * 3000)
    assert time.time() - t < 1.5
