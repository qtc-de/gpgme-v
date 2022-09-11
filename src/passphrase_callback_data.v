// Define a data type for PassphraseCallbacks. When implementing a custom password
// callback, this type needs to be used to provide the actual callback data.
module gpgme

// PassphraseCallbackData is a part of passphrase callbacks and should be
// used to write data to the callback. Optionally, a read operation was
// also implemented.
pub struct PassphraseCallbackData {
	fd int
}

// write writes data to the callback. Usually, this should be used to write the
// passphrase for a PGP key. The corresponding gpgme function blocks until a newline
// is encountered. Therefore, a newline is appended if the provided string does not
// already contain one.
pub fn (cd PassphraseCallbackData) write(content string) int {
	mut callback_data := content
	if !content.ends_with('\n') {
		callback_data += '\n'
	}

	return C.gpgme_io_writen(cd.fd, &char(callback_data.str), callback_data.len)
}

// read reads data from the callback.
pub fn (cd PassphraseCallbackData) read() []u8 {
	mut data := []u8{}

	buffer := []u8{len: 1024}
	for C.gpgme_io_read(cd.fd, voidptr(buffer.data), 1024) > 0 {
		data << buffer
	}

	return data
}
