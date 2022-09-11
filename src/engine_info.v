module gpgme

// EngineInfo stores information on one of the available gpg engines.
struct EngineInfo {
pub mut:
	protocol         Protocol
	file_name        string
	home_dir         string
	version          string
	required_version string
}

// engine_info create a new EngineInfo object from a _gpgme_engine_info struct.
// According to the gpgme documentation, _gpgme_engine_info is never freed once
// it was allocated. Therefore, we don't need a full copy of strings from the
// info.
fn new_engine_info(info C._gpgme_engine_info) EngineInfo {
	return EngineInfo{
		protocol: Protocol(info.protocol)
		file_name: ptos(info.file_name)
		home_dir: ptos(info.home_dir)
		version: ptos(info.version)
		required_version: ptos(info.req_version)
	}
}

// get_engine_info obtains information about available gpg engines and returns
// the result as a list of EngineInfo objects.
pub fn get_engine_info() ?[]EngineInfo {
	mut infos := []EngineInfo{}

	mut info := &C._gpgme_engine_info(0)
	handle_error(C.gpgme_get_engine_info(&info))?

	for info.next != 0 {
		infos << new_engine_info(info)
		info = info.next
	}

	return infos
}

// set_engine_info sets the engine that should be used for gpg operations.
pub fn set_engine_info(proto Protocol, file_name string, home_dir string) ? {
	err := C.gpgme_set_engine_info(proto, file_name.str, home_dir.str)
	return handle_error(err)
}
