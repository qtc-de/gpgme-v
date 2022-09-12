module gpgme

import os
import io
import time

// PassphraseCallback specifies the general function signature that can be used to define
// a passphrase callback. uid_hint might contain an indication for which user ID the passphrase
// is requested, but might be empty. prev_was_bad indicates whether the previous password input
// was wrong. The data parameter can be used to return the actual callback data.
type PassphraseCallback = fn (uid_hint string, prev_was_bad bool, data PassphraseCallbackData) ErrorCode

// Context holds a reference to a gpgme_ctx_t structure allocated by gpgme.
// Code that creates a new context should release it using the release method
// once the context is no longer used. Context is the only struct that does
// currently not rely on autofree.
pub struct Context {
mut:
	ctx C.gpgme_ctx_t
}

// new_context creates a new Context object and requests an associated gpgme_ctx
// from the gpgme library.
pub fn new_context() ?&Context {
	context := &Context{
		ctx: &C.gpgme_ctx_t(0)
	}
	err := C.gpgme_new(&context.ctx)

	handle_error(err)?
	return context
}

// release frees the memory allocated by gpgme for the context.
// This will probably become the free method once autofree is ready.
pub fn (c Context) release() {
	C.gpgme_release(c.ctx)
}

// set_armor sets the format for crypto operations to armored.
pub fn (mut c Context) set_armor(yes bool) {
	C.gpgme_set_armor(c.ctx, yes)
}

// get_armor returns the current armor setting of the context.
pub fn (c Context) get_armor() bool {
	return C.gpgme_get_armor(c.ctx) != 0
}

// set_text_mode sets the text mode attribute of the context.
pub fn (mut c Context) set_text_mode(yes bool) {
	C.gpgme_set_textmode(c.ctx, yes)
}

// get_text_mode get the text mode attribute of the context.
pub fn (c Context) get_text_mode() bool {
	return C.gpgme_get_textmode(c.ctx) != 0
}

// set_protocol sets the desired protocol used by crypto operations.
pub fn (mut c Context) set_protocol(p Protocol) ? {
	return handle_error(C.gpgme_set_protocol(c.ctx, p))
}

// get_protocol returns the currently set protocol for crypto operations.
pub fn (c Context) get_protocol() Protocol {
	return Protocol(C.gpgme_get_protocol(c.ctx))
}

// set_key_list_mode sets the key list mode of the context.
pub fn (mut c Context) set_key_list_mode(m KeyListMode) ? {
	return handle_error(C.gpgme_set_keylist_mode(c.ctx, m))
}

// get_key_list_mode returns the currently set key list mode of the context.
pub fn (c Context) get_key_list_mode() KeyListMode {
	return KeyListMode(C.gpgme_get_keylist_mode(c.ctx))
}

// set_pin_entry_mode sets the pin entry mode of the context.
// Setting the PinEntryMode to loopback is required when using
// a custom password callback.
pub fn (mut c Context) set_pin_entry_mode(m PinEntryMode) ? {
	return handle_error(C.gpgme_set_pinentry_mode(c.ctx, m))
}

// get_pin_entry_mode returns the currently set pin entry mode of the context.
pub fn (c Context) get_pin_entry_mode() PinEntryMode {
	return PinEntryMode(C.gpgme_get_pinentry_mode(c.ctx))
}

// set_engine_info sets the backend engine used by the context.
pub fn (mut c Context) set_engine_info(proto Protocol, file_name string, home_dir string) ? {
	err := C.gpgme_ctx_set_engine_info(c.ctx, proto, file_name.str, home_dir.str)
	return handle_error(err)
}

// get_engine_info get available engines usable from the current context.
pub fn (c Context) get_engine_info() []EngineInfo {
	mut infos := []EngineInfo{}

	mut info := C.gpgme_ctx_get_engine_info(c.ctx)

	for info.next != 0 {
		infos << new_engine_info(info)
		info = info.next
	}

	return infos
}

// clear_signers remove currently set signers from the context.
pub fn (c Context) clear_signers() {
	C.gpgme_signers_clear(c.ctx)
}

// add_signer adds a signer key to the context. This key will be used for signature
// operations. When no signer was added to the context, signature operations will fail.
pub fn (mut c Context) add_signer(signer Key) ? {
	err := C.gpgme_signers_add(c.ctx, signer.ptr())
	handle_error(err)?
}

// count_signers returns the count of currently set signers for the context.
pub fn (c Context) count_signers() u32 {
	return C.gpgme_signers_count(c.ctx)
}

// enum_signers returns the nth signature key in the context. Keys obtained by this
// function should be released using the release method when no longer required.
pub fn (c Context) enum_signers(nth i32) Key {
	return new_key(C.gpgme_signers_enum(c.ctx, nth))
}

// get_key find a key by using it's fingerprint. If secret is true, only private
// keys are considered. If a subkey is searched, still the master key is returned.
// Keys obtained via this function should be released using the release method when
// no longer required.
pub fn (c Context) get_key(fingerprint string, secret bool) ?Key {
	key := &C._gpgme_key(0)
	handle_error(C.gpgme_get_key(c.ctx, fingerprint.str, &key, secret))?

	return new_key(key)
}

// get_subkey find a subkey by using it's fingerprint. If secret is true, only private
// keys are considered. The returned SubKey object contains a reference to it's parent
// key that should be released after it is no longer used.
pub fn (c Context) get_subkey(fingerprint string, secret bool) ?SubKey {
	key := c.get_key(fingerprint, secret)?
	return key.get_subkey(fingerprint) or {}
}

// key_list_start can be used to enumerate available keys on the system. This
// method allows low level access to key list operations. Applications should
// prefer using the high level find_keys method for listing keys.
pub fn (c Context) key_list_start(pattern string, secret_only bool) ? {
	err := C.gpgme_op_keylist_start(c.ctx, &char(pattern.str), secret_only)
	handle_error(err)?
}

// key_list_next return the next key within the key list. This method allows
// low level access to key list operations. Applications should prefer using
// the high level find_keys method for listing keys.
pub fn (c Context) key_list_next() ?Key {
	key := &C._gpgme_key(0)
	handle_error(C.gpgme_op_keylist_next(c.ctx, &key))?

	return new_key(key)
}

// key_list_end stop the key list operation. This method allows low level
// access to key list operations. Applications should prefer using the high
// level find_keys method for listing keys.
pub fn (c Context) key_list_end() ? {
	err := C.gpgme_op_keylist_end(c.ctx)
	handle_error(err)?
}

// find_keys returns a list of available keys matching the specified pattern.
// Keys obtained by this method should be released using the release method
// then they are no longer required.
pub fn (c Context) find_keys(pattern string, secret_only bool) ?[]Key {
	c.key_list_start(pattern, secret_only)?

	mut keys := []Key{}

	for {
		keys << c.key_list_next() or { break }
	}

	c.key_list_end()?
	return keys
}

// find_first searches available keys for the specified pattern and returns
// the first identified match. Keys obtained by this method should be released
// using the release method then they are no longer required.
pub fn (c Context) find_key(pattern string, secret_only bool) ?Key {
	c.key_list_start(pattern, secret_only)?

	key := c.key_list_next() or {
		C.gpgme_op_keylist_end(c.ctx)
		return err
	}

	c.key_list_end()?
	return key
}

// encrypt is the low level encryption operation that encrypts some plaintext Data
// into ciphertext Data. If the sign parameter is true, the encrypted text is also
// signed using the signer keys from the current context. Data objects passed to this
// method should generally not be used again. Reusing Data objects after calling this
// method might result in unexpected behavior. Applications should prefer to use the
// high level encrypt operations that allow to encrypt byte buffers or files directly
// instead of working with Data objects.
pub fn (c Context) encrypt(recp []Key, flags EncryptFlag, mut plaintext Data, mut ciphertext Data, sign bool) ? {
	if sign && c.count_signers() == 0 {
		return error('No signers are associated with the specified context')
	}

	mut pointer_array := recp.map(fn (key Key) &C._gpgme_key {
		return key.ptr()
	})

	if sign {
		err := C.gpgme_op_encrypt_sign(c.ctx, &&C._gpgme_key(&char(pointer_array.data)),
			flags, plaintext.ptr(), ciphertext.ptr())
		handle_error(err)?
	} else {
		err := C.gpgme_op_encrypt(c.ctx, &&C._gpgme_key(&char(pointer_array.data)), flags,
			plaintext.ptr(), ciphertext.ptr())
		handle_error(err)?
	}
}

// encrypt_data encrypts a byte array containing plaintext and returns the crypted result
// as byte array. If sign is true, the encrypted text is also signed using the signer keys set
// for the current context.
pub fn (c Context) encrypt_data(recp []Key, flags EncryptFlag, plaintext []u8, sign bool) ?[]u8 {
	mut plain := new_memory_data(plaintext)?
	mut crypted := empty_memory_data()?

	c.encrypt(recp, flags, mut plain, mut crypted, sign)?
	return Data(crypted).read_all()
}

// encrypt_data_to_file encrypts a byte array containing plaintext and writes the crypted result
// into the specified output file. If sign is true, the encrypted text is also signed using the
// signer keys set for the current context.
pub fn (c Context) encrypt_data_to_file(recp []Key, flags EncryptFlag, plaintext []u8, filename string, sign bool) ? {
	mut file := os.create(filename)?
	defer {
		file.close()
	}

	mut plain := new_memory_data(plaintext)?
	mut crypted := file_data(file)?

	c.encrypt(recp, flags, mut plain, mut crypted, sign)?
}

// encrypt_data_to_callback encrypts a byte array containing plaintext and writes the crypted result
// using the write method of the provided io.Writer. If sign is true, the encrypted text is also signed
// using the signer keys set for the current context.
pub fn (c Context) encrypt_data_to_callback(recp []Key, flags EncryptFlag, plaintext []u8, mut writer io.Writer, sign bool) ? {
	mut plain := new_memory_data(plaintext)?
	mut callback := callback_writer(mut writer)?

	c.encrypt(recp, flags, mut plain, mut callback, sign)?
}

// encrypt_file encrypts the specified file and returns the crypted data as byte array. If sign
// is true, the encrypted text is also signed using the signer keys set for the current context.
pub fn (c Context) encrypt_file(recp []Key, flags EncryptFlag, filename string, sign bool) ?[]u8 {
	mut file := os.open(filename)?
	defer {
		file.close()
	}

	mut plain := file_data(file)?
	mut crypted := empty_memory_data()?

	c.encrypt(recp, flags, mut plain, mut crypted, sign)?
	return Data(crypted).read_all()
}

// encrypt_file_to_file encrypts the specified file and writes the crypted data into the specified
// output file. If sign is true, the encrypted text is also signed using the signer keys set for
// the current context.
pub fn (c Context) encrypt_file_to_file(recp []Key, flags EncryptFlag, src string, dst string, sign bool) ? {
	mut source := os.open(src)?
	defer {
		source.close()
	}

	mut destination := os.create(dst)?
	defer {
		destination.close()
	}

	mut plain := file_data(source)?
	mut crypted := file_data(destination)?

	c.encrypt(recp, flags, mut plain, mut crypted, sign)?
}

// encrypt_file_to_callback encrypts the specified file and writes the crypted data using the write
// method of the provided io.Writer. If sign is true, the encrypted text is also signed using the
// signer keys set for the current context.
pub fn (c Context) encrypt_file_to_callback(recp []Key, flags EncryptFlag, src string, mut writer io.Writer, sign bool) ? {
	mut source := os.open(src)?
	defer {
		source.close()
	}

	mut plain := file_data(source)?
	mut callback := callback_writer(mut writer)?

	c.encrypt(recp, flags, mut plain, mut callback, sign)?
}

// encrypt_callback encrypts data by reading it from the specified io.Reader. If sign is true, the
// encrypted text is also signed using the signer keys set for the current context.
pub fn (c Context) encrypt_callback(recp []Key, flags EncryptFlag, mut reader io.Reader, sign bool) ?[]u8 {
	mut callback := callback_reader(mut reader)?
	mut crypted := empty_memory_data()?

	c.encrypt(recp, flags, mut callback, mut crypted, sign)?
	return Data(crypted).read_all()
}

// encrypt_callback_to_file encrypts data by reading it from the specified io.Reader. The encrypted
// data is written to the specified output file. If sign is true, the encrypted text is also signed
// using the signer keys set for the current context.
pub fn (c Context) encrypt_callback_to_file(recp []Key, flags EncryptFlag, mut reader io.Reader, filename string, sign bool) ? {
	mut file := os.open(filename)?
	defer {
		file.close()
	}

	mut data := file_data(file)?
	mut callback := callback_reader(mut reader)?

	c.encrypt(recp, flags, mut callback, mut data, sign)?
}

// encrypt_callback_to_callback encrypts data by reading it from the specified io.Reader and
// writing the result to the specified io.Writer. If sign is true, the encrypted text is also signed
// using the signer keys set for the current context.
pub fn (c Context) encrypt_callback_to_callback(recp []Key, flags EncryptFlag, mut reader io.Reader, mut writer io.Writer, sign bool) ? {
	mut write_data := callback_writer(mut writer)?
	mut read_data := callback_reader(mut reader)?

	c.encrypt(recp, flags, mut read_data, mut write_data, sign)?
}

// decrypt is the low level decryption operation that decrypts some ciphertext Data
// into plaintext Data. If the verify parameter is true, the encrypted text is verified
// too and fond signatures are returned as Signature array. Data objects passed to this
// method should generally not be used again. Reusing Data objects after calling this
// method might result in unexpected behavior. Applications should prefer to use the high
// level decrypt operations that allow to decrypt byte buffers or files directly instead
// of working with Data objects.
pub fn (c Context) decrypt(mut ciphertext Data, mut plaintext Data, verify bool) ?[]Signature {
	if verify {
		err := C.gpgme_op_decrypt_verify(c.ctx, ciphertext.ptr(), plaintext.ptr())
		handle_error(err)?
	} else {
		err := C.gpgme_op_decrypt(c.ctx, ciphertext.ptr(), plaintext.ptr())
		handle_error(err)?
	}

	if verify {
		return c.verify_result()
	} else {
		return []Signature{}
	}
}

// decrypt_data decrypts a ciphertext specified as byte array and returns the plaintext
// result as byte array. If verify is true, found signatures are returned as Signature
// array.
pub fn (c Context) decrypt_data(ciphertext []u8, verify bool) ?([]u8, []Signature) {
	mut crypted := new_memory_data(ciphertext)?
	mut plain := empty_memory_data()?

	sigs := c.decrypt(mut crypted, mut plain, verify)?
	return Data(plain).read_all(), sigs
}

// decrypt_data_to_file decrypts a ciphertext specified as byte array and writes the
// result into the specified file. If verify is true, found signatures are returned
// as Signature array.
pub fn (c Context) decrypt_data_to_file(ciphertext []u8, filename string, verify bool) ?[]Signature {
	mut file := os.create(filename)?
	defer {
		file.close()
	}

	mut crypted := new_memory_data(ciphertext)?
	mut plain := file_data(file)?

	sigs := c.decrypt(mut crypted, mut plain, verify)?
	return sigs
}

// decrypt_data_to_callback decrypts a ciphertext specified as byte array and writes the
// result using the specified io.Writer. If verify is true, found signatures are returned
// as Signature array.
pub fn (c Context) decrypt_data_to_callback(ciphertext []u8, mut writer io.Writer, verify bool) ?[]Signature {
	mut crypted := new_memory_data(ciphertext)?
	mut plain := callback_writer(mut writer)?

	sigs := c.decrypt(mut crypted, mut plain, verify)?
	return sigs
}

// decrypt_file decrypts an encrypted file and returns the plaintext result as byte
// array. If verify is true, found signatures are returned as Signature array.
pub fn (c Context) decrypt_file(filename string, verify bool) ?([]u8, []Signature) {
	mut file := os.open(filename)?
	defer {
		file.close()
	}

	mut crypted := file_data(file)?
	mut plain := empty_memory_data()?

	sigs := c.decrypt(mut crypted, mut plain, verify)?
	return Data(plain).read_all(), sigs
}

// decrypt_file_to_file decrypts an encrypted file and writes the plaintext into the
// specified output file. If verify is true, found signatures are returned as Signature
// array.
pub fn (c Context) decrypt_file_to_file(src string, dst string, verify bool) ?[]Signature {
	mut source := os.open(src)?
	defer {
		source.close()
	}

	mut destination := os.create(dst)?
	defer {
		destination.close()
	}

	mut crypted := file_data(source)?
	mut plain := file_data(destination)?

	sigs := c.decrypt(mut crypted, mut plain, verify)?
	return sigs
}

// decrypt_file_to_callback decrypts an encrypted file and writes the plaintext using the
// specified io.Writer. If verify is true, found signatures are returned as Signature
// array.
pub fn (c Context) decrypt_file_to_callback(src string, mut writer io.Writer, verify bool) ?[]Signature {
	mut source := os.open(src)?
	defer {
		source.close()
	}

	mut crypted := file_data(source)?
	mut plain := callback_writer(mut writer)?

	sigs := c.decrypt(mut crypted, mut plain, verify)?
	return sigs
}

// decrypt_callback decrypts data read in from the specified io.Reader and returns the decrypted
// result as a byte array. If verify is true, found signatures are returned as Signature array.
pub fn (c Context) decrypt_callback(mut reader io.Reader, verify bool) ?([]u8, []Signature) {
	mut plain := empty_memory_data()?
	mut crypted := callback_reader(mut reader)?

	sigs := c.decrypt(mut crypted, mut plain, verify)?
	return Data(plain).read_all(), sigs
}

// decrypt_callback_to_file decrypts data read in from the specified io.Reader and writes
// the decrypted result to a file. If verify is true, found signatures are returned as Signature
// array.
pub fn (c Context) decrypt_callback_to_file(mut reader io.Reader, filename string, verify bool) ?[]Signature {
	mut dst := os.create(filename)?
	defer {
		dst.close()
	}

	mut plain := file_data(dst)?
	mut crypted := callback_reader(mut reader)?

	sigs := c.decrypt(mut crypted, mut plain, verify)?
	return sigs
}

// decrypt_callback_to_callback decrypts data read in from the specified io.Reader and writes
// the result to the specified io.Writer. If verify is true, found signatures are returned as
// Signature array.
pub fn (c Context) decrypt_callback_to_callback(mut reader io.Reader, mut writer io.Writer, verify bool) ?[]Signature {
	mut plain := callback_writer(mut writer)?
	mut crypted := callback_reader(mut reader)?

	sigs := c.decrypt(mut crypted, mut plain, verify)?
	return sigs
}

// verify is the low level verify operation that verifies some signed Data. The set of
// required parameters depends on the signature type. In any case, the sig parameter
// is expected to hold the signature (either in form of a detached signature or together
// with the signed content). If the signature is a detached signature, signed_text should
// contain the signed text and the plain parameter should be empty. Otherwise, when the
// signature mode is normal or clear, signed_text should be empty and the plain parameter
// should be an Data object where the recovered plaintext can be stored after verification.
//
// Data objects passed to this method should not be used again after the method returns.
// Reusing Data objects after calling this method might result in unexpected behavior.
// Applications should prefer to use the high level verify operations that allow to verify
// byte buffers or files directly instead of working with Data objects.
pub fn (c Context) verify(mut sig Data, mut signed_text Data, mut plain Data) ?[]Signature {
	handle_error(C.gpgme_op_verify(c.ctx, sig.ptr(), signed_text.ptr(), plain.ptr()))?
	return c.verify_result()
}

// verify_data checks the signature on a signed byte array and returns the recovered
// plaintext as an byte array. Additionally, the identified signatures are returned as
// an array of Signature objects.
pub fn (c Context) verify_data(signed []u8) ?([]u8, []Signature) {
	mut sig := new_memory_data(signed)?
	mut plain := empty_memory_data()?
	mut unused := null_data()

	sigs := c.verify(mut sig, mut unused, mut plain)?
	return Data(plain).read_all(), sigs
}

// verify_data_to_file checks the signature on a signed byte array and writes the
// recovered plaintext into the specified output file. The identified signatures are
// returned as an array of Signature objects.
pub fn (c Context) verify_data_to_file(signed []u8, filename string) ?[]Signature {
	mut file := os.create(filename)?
	defer {
		file.close()
	}

	mut sig := new_memory_data(signed)?
	mut filedata := file_data(file)?
	mut unused := null_data()

	return c.verify(mut sig, mut unused, mut filedata)
}

// verify_data_to_callback checks the signature on a signed byte array and writes the
// recovered plaintext into the specified io.Writer. The identified signatures are
// returned as an array of Signature objects.
pub fn (c Context) verify_data_to_callback(signed []u8, mut writer io.Writer) ?[]Signature {
	mut sig := new_memory_data(signed)?
	mut callback := callback_writer(mut writer)?
	mut unused := null_data()

	return c.verify(mut sig, mut unused, mut callback)
}

// verify_file checks the signature on the specified file and returns the recovered
// plaintext data as an byte array. Additionally, the identified signatures are returned
// as an array of Signature objects.
pub fn (c Context) verify_file(filename string) ?([]u8, []Signature) {
	mut src := os.open(filename)?
	defer {
		src.close()
	}

	mut sig := file_data(src)?
	mut plain := empty_memory_data()?
	mut unused := null_data()

	sigs := c.verify(mut sig, mut unused, mut plain)?
	return Data(plain).read_all(), sigs
}

// verify_file_to_file checks the signature on the specified file and writes the recovered
// plaintext to the specified output file. The identified signatures are returned as an
// array of Signature objects.
pub fn (c Context) verify_file_to_file(src string, dst string) ?[]Signature {
	mut source := os.open(src)?
	defer {
		source.close()
	}

	mut destination := os.open(dst)?
	defer {
		destination.close()
	}

	mut sig := file_data(source)?
	mut plain := file_data(destination)?
	mut unused := null_data()

	return c.verify(mut sig, mut unused, mut plain)
}

// verify_file_to_callback checks the signature on the specified file and writes the
// recovered plaintext to the specified io.Writer. The identified signatures are
// returned as an array of Signature objects.
pub fn (c Context) verify_file_to_callback(src string, mut writer io.Writer) ?[]Signature {
	mut source := os.open(src)?
	defer {
		source.close()
	}

	mut sig := file_data(source)?
	mut plain := callback_writer(mut writer)?
	mut unused := null_data()

	return c.verify(mut sig, mut unused, mut plain)
}

// verify_callback checks the signature on data read from the specified io.Reader and
// returns the recovered plaintext as byte array. The identified signatures are returned
// as an array of Signature objects.
pub fn (c Context) verify_callback(mut reader io.Reader) ?([]u8, []Signature) {
	mut sig := callback_reader(mut reader)?
	mut plain := empty_memory_data()?
	mut unused := null_data()

	sigs := c.verify(mut sig, mut unused, mut plain)?
	return Data(plain).read_all(), sigs
}

// verify_callback_to_file checks the signature on data read from the specified io.Reader
// and writes recovered plaintext to the specified output file. The identified signatures are
// returned as an array of Signature objects.
pub fn (c Context) verify_callback_to_file(mut reader io.Reader, filename string) ?[]Signature {
	mut dst := os.open(filename)?
	defer {
		dst.close()
	}

	mut sig := callback_reader(mut reader)?
	mut plain := file_data(dst)?
	mut unused := null_data()

	return c.verify(mut sig, mut unused, mut plain)
}

// verify_callback_to_callback checks the signature on data read on the specified io.Reader
// and writes the recovered plaintext to the specified io.Writer. The identified signatures
// are returned as an array of Signature objects.
pub fn (c Context) verify_callback_to_callback(mut reader io.Reader, mut writer io.Writer) ?[]Signature {
	mut sig := callback_reader(mut reader)?
	mut plain := callback_writer(mut writer)?
	mut unused := null_data()

	return c.verify(mut sig, mut unused, mut plain)
}

// verify_detached verifies that the detached signature byte array is valid for the
// specified data byte array. Identified signatures are returned as an array of
// Signature objects.
pub fn (c Context) verify_detached(data []u8, signature []u8) ?[]Signature {
	mut sig := new_memory_data(signature)?
	mut text := new_memory_data(data)?
	mut unused := null_data()

	return c.verify(mut sig, mut text, mut unused)
}

// verify_detached_file verifies that the detached signature byte array is valid for the
// specified data file. Identified signatures are returned as an array of Signature objects.
pub fn (c Context) verify_detached_file(dat_file string, signature []u8) ?[]Signature {
	mut file := os.open(dat_file)?
	defer {
		file.close()
	}

	mut sig := new_memory_data(signature)?
	mut filedata := file_data(file)?
	mut unused := null_data()

	return c.verify(mut sig, mut filedata, mut unused)
}

// verify_detached_callback verifies that the detached signature byte array is valid for the
// data obtained via the specified io.Reader. Identified signatures are returned as an array
// of Signature objects.
pub fn (c Context) verify_detached_callback(mut reader io.Reader, signature []u8) ?[]Signature {
	mut sig := new_memory_data(signature)?
	mut callback := callback_reader(mut reader)?
	mut unused := null_data()

	return c.verify(mut sig, mut callback, mut unused)
}

// verify_detached_from_file verifies that the detached signature stored in the specified
// filename is valid for the specified data byte array. Identified signatures are returned
// as an array of Signature objects.
pub fn (c Context) verify_detached_from_file(data []u8, sig_file string) ?[]Signature {
	mut sign := os.open(sig_file)?
	defer {
		sign.close()
	}

	mut sig := file_data(sign)?
	mut text := new_memory_data(data)?
	mut unused := null_data()

	return c.verify(mut sig, mut text, mut unused)
}

// verify_detached_file_from_file verifies that the detached signature stored in the
// specified signature file is valid for the data within the specified data file.
// Identified signatures are returned as an array of Signature objects.
pub fn (c Context) verify_detached_file_from_file(dat_file string, sig_file string) ?[]Signature {
	mut src := os.open(dat_file)?
	defer {
		src.close()
	}

	mut sign := os.open(sig_file)?
	defer {
		sign.close()
	}

	mut sig := file_data(sign)?
	mut filedata := file_data(src)?
	mut unused := null_data()

	return c.verify(mut sig, mut filedata, mut unused)
}

// verify_detached_callback_from_file verifies that the detached signature stored in the
// specified signature file is valid for the data obtained via the specified io.Reader.
// Identified signatures are returned as an array of Signature objects.
pub fn (c Context) verify_detached_callback_from_file(mut reader io.Reader, sig_file string) ?[]Signature {
	mut sign := os.open(sig_file)?
	defer {
		sign.close()
	}

	mut sig := file_data(sign)?
	mut callback := callback_reader(mut reader)?
	mut unused := null_data()

	return c.verify(mut sig, mut callback, mut unused)
}

// verify_detached_from_callback verifies that the detached signature obtained via the
// specified io.Reader is valid for the byte array passed as first argument. Identified
// signatures are returned as an array of Signature objects.
pub fn (c Context) verify_detached_from_callback(data []u8, mut reader io.Reader) ?[]Signature {
	mut sig := callback_reader(mut reader)?
	mut dat := new_memory_data(data)?
	mut unused := null_data()

	return c.verify(mut sig, mut dat, mut unused)
}

// verify_detached_file_from_callback verifies that the detached signature obtained via the
// specified io.Reader is valid for the specified file. Identified signatures are returned
// as an array of Signature objects.
pub fn (c Context) verify_detached_file_from_callback(filename string, mut reader io.Reader) ?[]Signature {
	mut file := os.open(filename)?
	defer {
		file.close()
	}

	mut sig := callback_reader(mut reader)?
	mut data := file_data(file)?
	mut unused := null_data()

	return c.verify(mut sig, mut data, mut unused)
}

// verify_detached_callback_from_callback verifies that the detached signature obtained via
// the specified io.Reader is valid for the data obtained via the other io.Reader. Identified
// signatures are returned  as an array of Signature objects.
pub fn (c Context) verify_detached_callback_from_callback(mut data io.Reader, mut reader io.Reader) ?[]Signature {
	mut sig := callback_reader(mut reader)?
	mut dat := callback_reader(mut data)?
	mut unused := null_data()

	return c.verify(mut sig, mut dat, mut unused)
}

// sign is the low level sign operation that signs some Data. The data to be signed is
// passed as a Data object within the plain parameter. The signed result is stored within
// the Data object passed within the sig parameter. The mode parameter specifies how the
// signature should be made (normal, clear or detached). The sign operation uses the
// signer keys that were set for the current context and throws an error if no signer keys
// were set yet.
//
// Data objects passed to this method should not be used again after the method returns.
// Reusing Data objects after calling this method might result in unexpected behavior.
// Applications should prefer to use the high level sign operations that allow to sign
// byte buffers or files directly instead of working with Data objects.
pub fn (c Context) sign(mut plain Data, mut sig Data, mode SignatureMode) ? {
	if c.count_signers() == 0 {
		return error('No signers are associated with the specified context')
	}

	handle_error(C.gpgme_op_sign(c.ctx, plain.ptr(), sig.ptr(), mode))?
}

// sign_data signs the specified byte array and returns the signature as byte array.
// The sign_data operation uses the signer keys set for the current context and returns
// an error if no key was set yet.
pub fn (c Context) sign_data(data []u8, mode SignatureMode) ?[]u8 {
	mut sig := empty_memory_data()?
	mut plain := new_memory_data(data)?

	c.sign(mut plain, mut sig, mode)?
	return Data(sig).read_all()
}

// sign_data_to_file signs the specified byte array writes the signature into a file.
// The sign_data_to_file operation uses the signer keys set for the current context and
// returns an error if no key was set yet.
pub fn (c Context) sign_data_to_file(data []u8, filename string, mode SignatureMode) ? {
	mut file := os.create(filename)?
	defer {
		file.close()
	}

	mut sig := file_data(file)?
	mut plain := new_memory_data(data)?

	c.sign(mut plain, mut sig, mode)?
}

// sign_data_to_callback signs the specified byte array writes the signature using the
// specified io.Writer. The sign_data_to_callback operation uses the signer keys set for
// the current context and returns an error if no key was set yet.
pub fn (c Context) sign_data_to_callback(data []u8, mut writer io.Writer, mode SignatureMode) ? {
	mut sig := callback_writer(mut writer)?
	mut plain := new_memory_data(data)?

	c.sign(mut plain, mut sig, mode)?
}

// sign_file signs the specified file and returns the resulting signature as byte array.
// The sign_file operation uses the signer keys set for the current context and returns
// an error if no key was set yet.
pub fn (c Context) sign_file(filename string, mode SignatureMode) ?[]u8 {
	mut file := os.open(filename)?
	defer {
		file.close()
	}

	mut sig := empty_memory_data()?
	mut plain := file_data(file)?

	c.sign(mut plain, mut sig, mode)?
	return Data(sig).read_all()
}

// sign_file_to_file signs the specified file and writes the resulting signature into the
// specified output file. The sign_file_to_file operation uses the signer keys set for the
// current context and returns an error if no key was set yet.
pub fn (c Context) sign_file_to_file(src string, dst string, mode SignatureMode) ? {
	mut source := os.open(src)?
	defer {
		source.close()
	}

	mut destination := os.open(dst)?
	defer {
		destination.close()
	}

	mut sig := file_data(destination)?
	mut plain := file_data(source)?

	c.sign(mut plain, mut sig, mode)?
}

// sign_file_to_callback signs the specified file and writes the resulting signature using
// the specified io.Writer. The sign_file_to_callback operation uses the signer keys set for
// the current context and returns an error if no key was set yet.
pub fn (c Context) sign_file_to_callback(src string, mut writer io.Writer, mode SignatureMode) ? {
	mut source := os.open(src)?
	defer {
		source.close()
	}

	mut plain := file_data(source)?
	mut sig := callback_writer(mut writer)?

	c.sign(mut plain, mut sig, mode)?
}

// sign_callback signs the data read from the specified io.Reader. The sign_callback operation
// uses the signer keys set for the current context and returns an error if no key was set yet.
pub fn (c Context) sign_callback(mut reader io.Reader, mode SignatureMode) ?[]u8 {
	mut plain := callback_reader(mut reader)?
	mut sig := empty_memory_data()?

	c.sign(mut plain, mut sig, mode)?
	return Data(sig).read_all()
}

// sign_callback_to_file signs the data read from the specified io.Reader and writes the result
// to the specified output file. The sign_callback_to_file operation uses the signer keys set
// for the current context and returns an error if no key was set yet.
pub fn (c Context) sign_callback_to_file(mut reader io.Reader, filename string, mode SignatureMode) ? {
	mut file := os.open(filename)?
	defer {
		file.close()
	}

	mut plain := callback_reader(mut reader)?
	mut sig := file_data(file)?

	c.sign(mut plain, mut sig, mode)?
}

// sign_callback_to_callback signs the data read from the specified io.Reader and writes the
// result using the specified io.Writer. The sign_callback_to_callback operation uses the
// signer keys set for the current context and returns an error if no key was set yet.
pub fn (c Context) sign_callback_to_callback(mut reader io.Reader, mut writer io.Writer, mode SignatureMode) ? {
	mut plain := callback_reader(mut reader)?
	mut sig := callback_writer(mut writer)?

	c.sign(mut plain, mut sig, mode)?
}

// set_passphrase_callback can be used to configure a passphrase callback for the context.
// The callback is wrapped into a closure and passed to gpgme_set_passphrase_cb. Notice,
// that the PinEntryMode of the context needs to be set to loopback for the callback to
// work correctly.
pub fn (mut c Context) set_passphrase_callback(callback PassphraseCallback) {
	closure := fn [callback] (hook voidptr, uid_hint &char, passphrase_info &char, prev_was_bad int, fd int) C.gpgme_error_t {
		cb_data := PassphraseCallbackData{fd}
		err := callback(ccp(uid_hint), prev_was_bad != 0, cb_data)
		return C.gpgme_error(u32(err))
	}

	C.gpgme_set_passphrase_cb(c.ctx, closure, 0)
}

// unset_passphrase_callback removes the configured passphrase callback from the context.
pub fn (mut c Context) unset_passphrase_callback() {
	C.gpgme_set_passphrase_cb(c.ctx, 0, 0)
}

// generate_key generates a new gpg key. The algo argument should be an
// available algorithm for the currently used engine. If no special algorithm
// is required, the string 'default' can be used. The specified user string
// should set to the desired mail address or the combination of mail address
// and real name (e.g. Harry Hirsch <Harry.Hirsch@alleinim.wald>).
pub fn (c Context) generate_key(user string, algo string, expires time.Time, flags KeyCreationFlags) ?Key {
	err := C.gpgme_op_createkey(c.ctx, &char(user.str), &char(algo.str), u64(0), u64(expires.unix_time()),
		&C._gpgme_key(0), u32(flags))
	handle_error(err)?

	result := C.gpgme_op_genkey_result(c.ctx)
	if result == 0 {
		return error('Key generation failed.')
	}

	return c.get_key(ptos(result.fpr), true)
}

// add_subkey adds a subkey to the specified key and returns the newly created
// subkey. Notice that the key specified as argument can be considered outdated
// at this point, as it does not contain a reference to the newly created subkey.
// A new key object, that contains the reference to the subkey, can be obtained
// via subkey.parent.
pub fn (c Context) add_subkey(key Key, algo string, expires time.Time, flags KeyCreationFlags) ?SubKey {
	err := C.gpgme_op_createsubkey(c.ctx, key.ptr(), &char(algo.str), u64(0), u64(expires.unix_time()),
		u32(flags))
	handle_error(err)?

	result := C.gpgme_op_genkey_result(c.ctx)
	if result == 0 {
		return error('SubKey generation failed.')
	}

	new_key := c.get_key(ptos(result.fpr), false)?
	return new_key.get_subkey(ptos(result.fpr))
}

// delete_key deletes the specified key from the key ring of the crypto engine
// used by the current context. After the operation, the specified key is released
// and should no longer be used.
pub fn (c Context) delete_key(mut key Key, flags KeyDeletionFlags) ? {
	err := C.gpgme_op_delete_ext(c.ctx, key.ptr(), u32(flags))
	handle_error(err)?
}

// verify_result is an internally used function that obtains the gpgme verification result
// and creates Signature objects from it. It is called by other exported functions and it
// is not required to call this method from outside this module.
//
// The signature structure used by gpgme contains a bitfield with variable offsets. At the
// time of writing, there is no documentation how to achieve something like this from V.
// Therefore, the pka_trust and chain_model values are currently not included.
fn (c Context) verify_result() []Signature {
	res := C.gpgme_op_verify_result(c.ctx)
	mut sigs := []Signature{}

	for s := res.signatures; s != 0; s = s.next {
		signature := Signature{
			summary: SigSum(s.summary)
			fingerprint: ccp(s.fpr)
			status: new_gpgerror(s.status)
			timestamp: time.unix(i64(s.timestamp))
			exp_timestamp: time.unix(i64(s.exp_timestamp))
			wrong_key_usage: s.wrong_key_usage.has(.wrong_key_usage)
			// pka_trust:       currently not possible due to missing bitfield support
			// chain_model:     currently not possible due to missing bitfield support
			validity: s.validity
			validity_reason: new_gpgerror(s.validity_reason)
			pubkey_algo: s.pubkey_algo
			hash_algo: s.hash_algo
		}
		sigs << signature
	}

	return sigs
}
