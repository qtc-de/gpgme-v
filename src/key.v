module gpgme

// Key holds a reference to a _gpgme_key structure and contains most
// of the relevant key properties at attributes. Key objects are
// intended to be freed by V's autofree mechanism.
[heap]
pub struct Key {
mut:
	ptr &C._gpgme_key
pub mut:
	revoked          bool
	expired          bool
	is_qualified     bool
	disabled         bool
	invalid          bool
	secret           bool
	can_encrypt      bool
	can_sign         bool
	can_certify      bool
	can_authenticate bool
	fingerprint      string
	issuer_name      string
	issuer_serial    string
	chain_id         string
	protocol         Protocol
	key_list_mode    KeyListMode
	owner_trust      Validity
}

// new_key creates a new key from a pointer to a _gpgme_key structure.
pub fn new_key(ptr &C._gpgme_key) Key {
	return Key{
		ptr: ptr
		revoked: ptr.revoked.has(.revoked)
		expired: ptr.revoked.has(.expired)
		is_qualified: ptr.revoked.has(.is_qualified)
		disabled: ptr.revoked.has(.disabled)
		invalid: ptr.revoked.has(.invalid)
		can_encrypt: ptr.revoked.has(.can_encrypt)
		can_sign: ptr.revoked.has(.can_sign)
		can_certify: ptr.revoked.has(.can_certify)
		can_authenticate: ptr.revoked.has(.can_authenticate)
		secret: ptr.revoked.has(.secret)
		fingerprint: ccp(ptr.fpr)
		key_list_mode: KeyListMode(ptr.keylist_mode)
		issuer_name: ccp(ptr.issuer_name)
		issuer_serial: ccp(ptr.issuer_serial)
		chain_id: ccp(ptr.chain_id)
		owner_trust: Validity(ptr.owner_trust)
		protocol: Protocol(ptr.protocol)
	}
}

// get_user_ids returns a list of UserID objects associated with the key.
// It is tempting to create this array during the key creation and store
// it along with the key. However, this would create a cyclic reference,
// probably blocking the autofree mechanism.
pub fn (key Key) get_user_ids() []UserID {
	mut user_ids := []UserID{}
	mut current_uid := key.ptr.uids

	for current_uid != 0 {
		user_ids << new_user_id(current_uid, &key)
		current_uid = current_uid.next
	}

	return user_ids
}

// get_subkeys returns a list of Subkey objects associated with the key.
// It is tempting to create this array during the key creation and store
// it along with the key. However, this would create a cyclic reference,
// probably blocking the autofree mechanism.
pub fn (key Key) get_subkeys() []SubKey {
	mut subkeys := []SubKey{}
	mut current_sub := key.ptr.subkeys

	for current_sub != 0 {
		subkeys << new_subkey(current_sub, &key)
		current_sub = current_sub.next
	}

	return subkeys
}

// get_subkey returns the subkey that matches the requested fingerprint.
// If the requested fingerprint does not exists within the key, none is
// returned.
pub fn (key Key) get_subkey(fingerprint string) ?SubKey {
	mut current_sub := key.ptr.subkeys

	for current_sub != 0 && ptos(current_sub.fpr) != fingerprint {
		current_sub = current_sub.next
	}

	if current_sub != 0 {
		return new_subkey(current_sub, &key)
	}

	return none
}

// ptr returns a pointer to the underlying _gpgme_key structure. Before
// returning the pointer, a nullpointer check is made.
pub fn (key &Key) ptr() &C._gpgme_key {
	if voidptr(key.ptr) == voidptr(&C._gpgme_key(0)) {
		panic('key.ptr() - nullpointer access.')
	}

	return key.ptr
}

// free decreases the reference count for the underlying _gpgme_key
// structure, which should free the memory as there is no possibility
// for increasing the reference count yet.
[unsafe]
pub fn (mut key Key) free() {
	if voidptr(key.ptr) == voidptr(&C._gpgme_key(0)) {
		C.gpgme_key_unref(key.ptr)
		key.ptr = &C._gpgme_key(0)
	}
}
