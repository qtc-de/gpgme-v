import gpgme

fn main() {
	mut context := gpgme.new_context()?
	context.set_key_list_mode(gpgme.KeyListMode.with_secret)?

	keys := context.find_keys('', false)?
	println('[+] Available PGP keys:')

	for key in keys {
		owner := key.get_user_ids()
		println('[+]')
		println('[+] Key Owner:   ${owner[0].name}')
		println('[+] Owner Email: ${owner[0].email}')
		println('[+] Subkeys:')

		for sub in key.get_subkeys() {
			println('[+]\t Fingerprint: $sub.fingerprint')
			println('[+]\t CanEncrypt:  $sub.can_encrypt')
			println('[+]\t CanSign:     $sub.can_sign')
			println('[+]\t Expires:     $sub.expires.clean()')
			println('[+]\t PrivateKey:  $sub.secret')
			println('[+]')
		}
	}

	context.release()
}
