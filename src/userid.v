module gpgme

// UserID represents a user ID that is associated with a PGP key.
// One key can have multiple user IDs being assigned. The UserID
// struct makes a copy of most of it's associated data, but also
// stored the pointer to the original C data structure. Memory
// allocated within the C structure is bound to the parent Key
// and does not need to be freed. The parent Key needs to stay
// alive as long as the UserID object is living.
struct UserID {
mut:
	ptr &C._gpgme_user_id
pub mut:
	revoked  bool
	invalid  bool
	uid      string
	name     string
	email    string
	address  string
	comment  string
	uidhash  string
	validity Validity
	parent   &Key
}

// new_user_id creates a new UserID object from a reference to an
// &C._gpgme_user_id structure. The parent key is referenced to prevent
// it from being freed.
fn new_user_id(ptr &C._gpgme_user_id, parent &Key) UserID {
	return UserID{
		ptr: ptr
		revoked: ptr.revoked.has(.revoked)
		invalid: ptr.revoked.has(.invalid)
		uid: ccp(ptr.uid)
		name: ccp(ptr.name)
		email: ccp(ptr.email)
		address: ccp(ptr.address)
		comment: ccp(ptr.comment)
		uidhash: ccp(ptr.uidhash)
		validity: Validity(ptr.validity)
		parent: parent
	}
}
