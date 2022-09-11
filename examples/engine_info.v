import gpgme

// List available PGP engines that are available on the system.
fn main() {
	infos := gpgme.get_engine_info()?

	println('[+] Listing available gpg engines:')

	for info in infos {
		println('[+]')
		println('[+]\t Protocol: $info.protocol')
		println('[+]\t Version:  $info.version')
		println('[+]\t File:     $info.file_name')
		println('[+]\t HomeDir:  $info.home_dir')
	}
}
