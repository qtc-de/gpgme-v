import gpgme
import os
import time

// Example code for a custom passphrase callback. Using a custom callback
// can be achievied by implemeting the corresponding gpgme.PassphraseCallback
// type, configuring it for the desired context and setting the PinEntryMode
// of the context to loopback.
fn sign_and_verify() ? {
	mut context := gpgme.new_context()?
	defer {
		context.release()
	}

	context.set_armor(true)
	context.set_passphrase_callback(callback)
	context.set_pin_entry_mode(gpgme.PinEntryMode.loopback)?

	println('[+] Generating new PGP key.')
	expires := time.parse('2044-01-01 12:00:00') or { time.now() }

	mut key := context.generate_key('Harry Hirsch <Harry.Hirsch@alleinim.wald>', 'default',
		expires, gpgme.KeyCreationFlags.sign | .force)?
	println('[+] Generated PGP key with fingerprint: $key.fingerprint')

	defer {
		println('[+] Deleting key with fingerprint: $key.fingerprint')
		context.delete_key(mut key, gpgme.KeyDeletionFlags.allow_secret | .force) or {}
	}

	context.add_signer(key)?
	println('[+] Signing data with the newly created key...')

	signed := context.sign_data('Sign this please'.bytes(), gpgme.SignatureMode.clear)?
	println('[+] Signed Text: $signed.bytestr()')
}

fn callback(uid_hint string, prev_was_bad bool, data gpgme.PassphraseCallbackData) gpgme.ErrorCode {
	passphrase := os.input_password('[!] Please enter your passphrase [$uid_hint]: ') or {
		return gpgme.ErrorCode.no_passphrase
	}

	data.write(passphrase)
	return gpgme.ErrorCode.no_error
}

// The actual example code is defined in a separate method to allow error
// handling via defer. This is required, since we do not handle errors in
// the example, but want to cleanup generated keys.
fn main() {
	sign_and_verify()?
}
