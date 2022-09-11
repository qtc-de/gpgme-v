import gpgme
import time

// Example code for the sign and verify operations. First, two PGP keys
// for Harry Hirsch and Rebecca Reh are created. Both keys are then used
// to sign a message which is verified afterwards.
fn sign_and_verify() ? {
	mut context := gpgme.new_context()?
	defer {
		context.release()
	}

	context.set_armor(true)
	generate_keys(context)?

	mut key_one := context.find_key('Harry Hirsch', true)?
	mut key_two := context.find_key('Rebecca Reh', true)?

	defer {
		delete_key(context, mut key_one)
		delete_key(context, mut key_two)
	}

	context.add_signer(key_one)?
	context.add_signer(key_two)?

	signed := context.sign_data('Sign this please'.bytes(), gpgme.SignatureMode.clear)?
	println('[+] Signed Text: $signed.bytestr()')

	plaintext, signatures := context.verify_data(signed)?
	println('[+] Plaintext was: $plaintext.bytestr()')
	println('[+] Signed by:')

	for sig in signatures {
		println('[+]\t $sig.fingerprint ($sig.summary)')
	}
}

// ****************************************************************
// The function definitions from here are only helper functions for
// setting up the required keys and deleting them again. The actual
// example code ends here :)
// ****************************************************************
fn generate_keys(context gpgme.Context) ? {
	expires := time.parse('2044-01-01 12:00:00') or { time.now() }

	println('[+] Generating first key:')

	key_one := context.generate_key('Harry Hirsch <Harry.Hirsch@alleinim.wald>', 'default',
		expires, gpgme.KeyCreationFlags.sign | .cert | .nopasswd | .force)?
	println('[+]\t Generated primary key with fingerprint: $key_one.fingerprint')

	subkey_one := context.add_subkey(key_one, 'default', expires, gpgme.KeyCreationFlags.sign | .encr | .nopasswd)?
	println('[+]\t Generated subkey key with fingerprint:  $subkey_one.fingerprint')

	println('[+] Generating second key:')

	key_two := context.generate_key('Rebecca Reh <Rebecca.Reh@alleinim.wald>', 'default',
		expires, gpgme.KeyCreationFlags.sign | .cert | .nopasswd | .force)?
	println('[+]\t Generated primary key with fingerprint: $key_two.fingerprint')

	subkey_two := context.add_subkey(key_two, 'default', expires, gpgme.KeyCreationFlags.sign | .encr | .nopasswd)?
	println('[+]\t Generated subkey key with fingerprint:  $subkey_two.fingerprint')
}

fn delete_key(context gpgme.Context, mut key gpgme.Key) {
	println('[+] Deleting key with fingerprint: $key.fingerprint')
	context.delete_key(mut key, gpgme.KeyDeletionFlags.allow_secret | .force) or {}
}

// The actual example code is defined in a separate method to allow error
// handling via defer. This is required, since we do not handle errors in
// the example, but want to cleanup generated keys.
fn main() {
	sign_and_verify()?
}
