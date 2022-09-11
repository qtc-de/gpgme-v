module gpgme

import io
import os
import arrays

// Data is an interface implemented by types that represent gpgme_data objects in V.
// Implementors must at least contain a pointer to the corresponding gpgme_data object.
interface Data {
mut:
	ptr &C.gpgme_data
}

// MemoryData represents a simple memory based data buffer. MemoryBuffers used for read
// operations need to be initialized with a byte array, where reading operations can
// take data from. MemoryBuffers used for write operations can be initialized as empty.
struct MemoryData {
mut:
	ptr &C.gpgme_data
pub mut:
	buf []u8
}

// NullData represents a Data object that contains nullpointer. This is requied for
// some gpgme operations.
struct NullData {
mut:
	ptr &C.gpgme_data
}

// FileData represents the file based data buffer from gpgme. When used in functions
// like encrypt, decrypt or sign, the required data is directly read from or written
// to the associated file contained in the file parameter. Callers have to provide the
// file handle in the first place and make sure that it got assigned the correct
// permission for the requested operation.
struct FileData {
mut:
	ptr &C.gpgme_data
pub mut:
	file os.File
}

// CallbackData represents a callback based data buffer and needs to be initialized with
// the io.Reader, io.Writer or io.ReaderWriter types. Depending on the requested operation,
// data is read from or written to the corresponding object.
struct CallbackData {
mut:
	ptr &C.gpgme_data
}

// ptr returns a pointer to the underlying C data structure of the Data
// object. Before returning the pointer, a nullpointer check is made. The
// nullpointer check is skipped, if the Data object is a NullData object.
pub fn (d Data) ptr() &C.gpgme_data {
    match d {
        NullData { return d.ptr }
        else {
            if voidptr(d.ptr) == voidptr(&C.gpgme_data(0)) {
                panic('data.ptr() - nullpointer access.')
            }
        }
    }

	return d.ptr
}

// read implements the low level gpgme_data_read operation. It is available for all
// types that implement the Data interface, but should only be used if really required.
// Most types implementing Data provide a more convenient ways for accessing the data.
pub fn (d Data) read() []u8 {
	mut data := []u8{}
	buffer := []u8{len: 1024}

	for {
		size := C.gpgme_data_read(d.ptr(), voidptr(buffer.data), 1024)

		if size <= 0 {
			break
		}

		data << buffer[0..size]
	}

	return data
}

// read_all implements the low level gpgme_data_read operation. It is available for all
// types that implement the Data interface, but should only be used if really required.
// Most types implementing Data provide a more convenient ways for accessing the data.
// In contrast to the read function, read_all sets the current data pointer position to
// the beginning before reading.
pub fn (d Data) read_all() []u8 {
	d.seek(0, 0)
	return d.read()
}

// seek implements the low level gpgme_data_seek operation. It is available for all
// types that implement the Data interface, but should only be used if really required.
pub fn (d Data) seek(offset usize, whence int) isize {
	return C.gpgme_data_seek(d.ptr(), offset, whence)
}

// write implements the low level gpgme_data_write operation. It is available for all
// types that implement the Data interface, but should only be used if really required.
// Most types implementing Data provide a more convenient ways for writing data.
pub fn (d Data) write(buf []u8) isize {
	return C.gpgme_data_write(d.ptr(), voidptr(buf.data), usize(buf.len))
}


// null_data creates a NulleData object.
pub fn null_data() NullData {
	return NullData{
		ptr: &C.gpgme_data(0)
	}
}

// new_memory_data is used to create MemoryData objects holding an initial value. This
// is used most of the time to create a Data object for read operations.
pub fn new_memory_data(content []u8) ?MemoryData {
	mut data := MemoryData{
		buf: content
		ptr: &C.gpgme_data(0)
	}

	data.update()?
	return data
}

// empty_memory_data is used to create MemoryData objects that do not contain an initial
// value. This is used most of the time to create Data objects for write operations.
pub fn empty_memory_data() ?MemoryData {
	data := MemoryData{
		buf: []u8{}
		ptr: &C.gpgme_data(0)
	}

	handle_error(C.gpgme_data_new(&data.ptr))?
	return data
}

// set sets the content of a MemoryData object to a new value and updates the associated
// gpgme_data object.
pub fn (mut d MemoryData) set(content []u8) ? {
	d.buf = content
	d.update()?
}

// append appends to the content of a MemoryData object and updates the associated
// gpgme_data object. Each append causes a new allocation of a gpgme_data buffer.
// Therefore, unnecessary calls should be prevented.
pub fn (mut d MemoryData) append(content []u8) ? {
	d.buf << content
	d.update()?
}

// clear clears the MemoryData object and brings it to the same state in which a new
// instance, created by empty_memory_data, would be.
pub fn (mut d MemoryData) clear() ? {
	if d.ptr != &C.gpgme_data(0) {
		C.gpgme_data_release(d.ptr)
	}

	d.buf = []u8{}
	handle_error(C.gpgme_data_new(&d.ptr))?
}

// update takes the current buffer and creates a new gpgme_data buffer from it. The old
// buffer, if one was assigned with the object, is freed.
pub fn (mut d MemoryData) update() ? {
	if d.ptr != &C.gpgme_data(0) {
		C.gpgme_data_release(d.ptr)
	}

	err := C.gpgme_data_new_from_mem(&d.ptr, &char(d.buf.data), d.buf.len, 1)
	handle_error(err)?
}

// free releases the gpgme_data object associated with the object. It is intended to
// be called by autofree once this feature is ready.
[unsafe]
pub fn (mut d MemoryData) free() {
	if voidptr(d.ptr) != voidptr(&C.gpgme_data(0)) {
		C.gpgme_data_release(d.ptr)
	}

	d.ptr = &C.gpgme_data(0)
}

// file_data creates a new FileData object. The access flags that were used to create
// the input file should match the purpose (read, write, readwrite) of the data object.
pub fn file_data(file os.File) ?FileData {
	mut data := FileData{
		file: file
		ptr: &C.gpgme_data(0)
	}

	data.update()?
	return data
}

// update resets the current file position back to the beginning and updates the gpgme_data
// buffer accordingly. The previous gpgme_data object, if not null, is freed before.
pub fn (mut d FileData) update() ? {
	if d.ptr != &C.gpgme_data(0) {
		C.gpgme_data_release(d.ptr)
	}

	d.file.seek(0, .start)?
	err := C.gpgme_data_new_from_fd(&d.ptr, d.file.fd)
	handle_error(err)?
}

// free releases the FileData object. This method flushes the associated file and frees
// the associated gpgme_data object. It does NOT close the associated file handle.
// This method is intended to be called by the autofree feature once it is ready.
[unsafe]
pub fn (mut d FileData) free() {
	if voidptr(d.ptr) != voidptr(&C.gpgme_data(0)) {
		C.gpgme_data_release(d.ptr)
		d.ptr = &C.gpgme_data(0)
	}

	d.file.flush()
}

// callback_reader creates a callback based data object from an object that
// implements the Reader interface. The resulting data object can be used for
// read operations only.
pub fn callback_reader(mut reader io.Reader) ?CallbackData {
	read_closure := fn [mut reader] (handle voidptr, buffer voidptr, size usize) isize {
		mut buf := []u8{len: int(size)}
		bytes_read := reader.read(mut buf) or { 0 }

		if bytes_read != 0 {
			unsafe { vmemcpy(buffer, buf.data, u32(bytes_read) * sizeof(u8)) }
		}

		return bytes_read
	}

	callbacks := &C.gpgme_data_cbs{
		read: read_closure
	}

	callback_data := CallbackData{
		ptr: &C.gpgme_data(0)
	}
	handle_error(C.gpgme_data_new_from_cbs(&callback_data.ptr, callbacks, 0))?

	return callback_data
}

// callback_writer creates a callback based data object from an object that
// implements the Writer interface. The resulting data object can be used for
// write operations only.
pub fn callback_writer(mut writer io.Writer) ?CallbackData {
	write_closure := fn [mut writer] (handle voidptr, buffer voidptr, size usize) isize {
		unsafe {
			array := arrays.carray_to_varray<u8>(buffer, int(size))
			bytes_written := writer.write(array) or { 0 }

			return bytes_written
		}
	}

	callbacks := &C.gpgme_data_cbs{
		write: write_closure
	}

	callback_data := CallbackData{
		ptr: &C.gpgme_data(0)
	}
	handle_error(C.gpgme_data_new_from_cbs(&callback_data.ptr, callbacks, 0))?

	return callback_data
}

// callback_reader_writer creates a callback based data object from an object
// that implements the ReaderWriter interface. The resulting data object can be
// used for read and write operations.
pub fn callback_reader_writer(mut rw io.ReaderWriter) ?CallbackData {
	read_closure := fn [mut rw] (handle voidptr, buffer voidptr, size usize) isize {
		mut buf := []u8{len: int(size)}
		bytes_read := rw.read(mut buf) or { 0 }

		if bytes_read != 0 {
			unsafe { vmemcpy(buffer, buf.data, u32(bytes_read) * sizeof(u8)) }
		}

		return bytes_read
	}

	write_closure := fn [mut rw] (handle voidptr, buffer voidptr, size usize) isize {
		unsafe {
			array := arrays.carray_to_varray<u8>(buffer, int(size))
			bytes_written := rw.write(array) or { 0 }

			return bytes_written
		}
	}

	callbacks := &C.gpgme_data_cbs{
		read: read_closure
		write: write_closure
	}

	callback_data := CallbackData{
		ptr: &C.gpgme_data(0)
	}
	handle_error(C.gpgme_data_new_from_cbs(&callback_data.ptr, callbacks, 0))?

	return callback_data
}

// free calls the gpgme_data_release method on the underlying data object.
[unsafe]
pub fn (mut d CallbackData) free() {
	if voidptr(d.ptr) != voidptr(&C.gpgme_data(0)) {
		C.gpgme_data_release(d.ptr)
		d.ptr = &C.gpgme_data(0)
	}
}
