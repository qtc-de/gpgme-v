module gpgme

// ptos convert a char pointer into a string. Returns an empty
// string if the pointer is nil. The newly created string type
// is only a reference to the location there the char pointer
// points to. The string is not copied. Use ccp for this.
fn ptos(p &char) string {
	if p == 0 {
		return ''
	}

	return unsafe { p.vstring() }
}

// ccp convert a char pointer into a string by making a copy of
// the underlying string data.
fn ccp(p &char) string {
	if p == 0 {
		return ''
	}

	return unsafe { cstring_to_vstring(p) }
}
