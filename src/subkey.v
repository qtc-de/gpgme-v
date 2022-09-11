module gpgme

import time

// SubKey holds a pointer to a _gpgme_subkey struct and contains a
// reference to the parent Key object. Most other relevant properties
// from the subkey are available through attributes. The memory
// allocated for _gpgme_subkey is tied to the parent key. Subkeys
// do not need to be freed, but the parent Key object must stay alive
// as long as the Subkey is living.
struct SubKey {
mut:
	ptr &C._gpgme_subkey
pub mut:
	revoked          bool
	expired          bool
	disabled         bool
	invalid          bool
	secret           bool
	can_encrypt      bool
	can_sign         bool
	can_certify      bool
	can_authenticate bool
	is_qualified     bool
	is_cardkey       bool
	keyid            string
	fingerprint      string
	card_number      string
	created          time.Time
	expires          time.Time
	parent           &Key
}

// new_subkey creates a new Subkey from a _gpgme_subkey pointer.
fn new_subkey(ptr &C._gpgme_subkey, parent &Key) SubKey {
	return SubKey{
		ptr: ptr
		revoked: ptr.revoked.has(.revoked)
		expired: ptr.revoked.has(.expired)
		disabled: ptr.revoked.has(.disabled)
		invalid: ptr.revoked.has(.invalid)
		secret: ptr.revoked.has(.secret)
		can_encrypt: ptr.revoked.has(.can_encrypt)
		can_sign: ptr.revoked.has(.can_sign)
		can_certify: ptr.revoked.has(.can_certify)
		can_authenticate: ptr.revoked.has(.can_authenticate)
		is_qualified: ptr.revoked.has(.is_qualified)
		is_cardkey: ptr.revoked.has(.is_cardkey)
		keyid: ccp(ptr.keyid)
		fingerprint: ccp(ptr.fpr)
		card_number: ccp(ptr.card_number)
		created: time.unix(ptr.timestamp)
		expires: time.unix(ptr.expires)
		parent: parent
	}
}
