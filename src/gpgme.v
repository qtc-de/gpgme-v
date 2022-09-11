// gpgme is a well known C library that provides access to gpg related functionalities.
// This library represents a V wrapper around gpgme, which is based on the go gpgme
// wrapper from James Fargher (https://github.com/proglottis/gpgme)
module gpgme

#flag -lgpgme
#flag -D_FILE_OFFSET_BITS=64
#include "gpgme.h"

// init has to be called according to the gpgme documentation. We do not really care
// about the result here, except a nullpointer is returned, which indicates an error.
fn init() {
	version := C.gpgme_check_version(0)

	if version == 0 {
		panic('GPGME initialization failed.')
	}
}

pub enum Protocol {
	open_pgp = C.GPGME_PROTOCOL_OpenPGP
	cms = C.GPGME_PROTOCOL_CMS
	gpg_conf = C.GPGME_PROTOCOL_GPGCONF
	assuan = C.GPGME_PROTOCOL_ASSUAN
	g13 = C.GPGME_PROTOCOL_G13
	ui_server = C.GPGME_PROTOCOL_UISERVER
	spawn = C.GPGME_PROTOCOL_SPAWN
	default = C.GPGME_PROTOCOL_DEFAULT
	unknown = C.GPGME_PROTOCOL_UNKNOWN
}

pub enum PinEntryMode {
	default = C.GPGME_PINENTRY_MODE_DEFAULT
	ask = C.GPGME_PINENTRY_MODE_ASK
	cancel = C.GPGME_PINENTRY_MODE_CANCEL
	error = C.GPGME_PINENTRY_MODE_ERROR
	loopback = C.GPGME_PINENTRY_MODE_LOOPBACK
}

pub enum SignatureMode {
	normal = C.GPGME_SIG_MODE_NORMAL
	detach = C.GPGME_SIG_MODE_DETACH
	clear = C.GPGME_SIG_MODE_CLEAR
}

pub enum Validity {
	unknown = C.GPGME_VALIDITY_UNKNOWN
	undefined = C.GPGME_VALIDITY_UNDEFINED
	never = C.GPGME_VALIDITY_NEVER
	marginal = C.GPGME_VALIDITY_MARGINAL
	full = C.GPGME_VALIDITY_FULL
	ultimate = C.GPGME_VALIDITY_ULTIMATE
}

pub enum PubkeyAlgo {
	rsa = C.GPGME_PK_RSA
	rsa_e = C.GPGME_PK_RSA_E
	rsa_s = C.GPGME_PK_RSA_S
	elg_e = C.GPGME_PK_ELG_E
	dsa = C.GPGME_PK_DSA
	ecc = C.GPGME_PK_ECC
	elg = C.GPGME_PK_ELG
	ecdsa = C.GPGME_PK_ECDSA
	ecdh = C.GPGME_PK_ECDH
	eddsa = C.GPGME_PK_EDDSA
}

pub enum HashAlgo {
	@none = C.GPGME_MD_NONE
	md5 = C.GPGME_MD_MD5
	sha1 = C.GPGME_MD_SHA1
	rmd160 = C.GPGME_MD_RMD160
	md2 = C.GPGME_MD_MD2
	tiger = C.GPGME_MD_TIGER
	haval = C.GPGME_MD_HAVAL
	sha256 = C.GPGME_MD_SHA256
	sha384 = C.GPGME_MD_SHA384
	sha512 = C.GPGME_MD_SHA512
	sha224 = C.GPGME_MD_SHA224
	md4 = C.GPGME_MD_MD4
	crc32 = C.GPGME_MD_CRC32
	crc32_rfc1510 = C.GPGME_MD_CRC32_RFC1510
	crc24_rfc2440 = C.GPGME_MD_CRC24_RFC2440
}

[flag]
pub enum EncryptFlag {
	always_trust
	no_encrypt_to
	prepare
	expect_sign
	no_compress
	symmetric
	throw_keyids
	wrap
	want_address
}

[flag]
pub enum KeyListMode {
	local
	extern
	sigs
	sig_notations
	with_secret
	with_tofu
	with_keygrip
	ephemeral
	validate
}

[flag]
pub enum SigSum {
	valid
	green
	red
	unused
	key_revoked
	key_expired
	sig_expired
	key_missing
	crl_missing
	crl_too_old
	bad_policy
	sys_error
	tofu_conflict
}

[flag]
pub enum KeyCreationFlags {
	sign
	encr
	cert
	auth
	unused1
	unused2
	unused3
	nopasswd
	selfsigned
	nostore
	wantpub
	wantsec
	force
	noexpire
}

[flag]
pub enum KeyDeletionFlags {
	allow_secret
	force
}

[flag]
pub enum MimeFlags {
	is_mime
}

[flag]
pub enum DecryptResultFlags {
	wrong_key_usage
	is_de_vs
	is_mime
	legacy_cipher_nomdc
	_unused
}

[flag]
pub enum SignatureFlags {
	wrong_key_usage
	pka_trust
	chain_model
	is_de_vs
	_unused
}

[flag]
pub enum KeyFlags {
	revoked
	expired
	disabled
	invalid
	can_encrypt
	can_sign
	can_certify
	secret
	can_authenticate
	is_qualified
	_unused
	origin
}

[flag]
pub enum SubKeyFlags {
	revoked
	expired
	disabled
	invalid
	can_encrypt
	can_sign
	can_certify
	secret
	can_authenticate
	is_qualified
	is_cardkey
	is_de_vs
	_unused
}

[flag]
pub enum UserFlags {
	revoked
	invalid
	_unused
	origin
}

[flag]
pub enum KeyResultFlags {
	primary
	sub
	uid
	_unused
}

[heap]
struct C._gpgme_engine_info {
mut:
	next        &C._gpgme_engine_info
	protocol    C.gpgme_protocol_t
	file_name   &char
	version     &char
	req_version &char
	home_dir    &char
}

[heap]
struct C._gpgme_key {
pub:
	_refs         u32
	revoked       KeyFlags
	protocol      Protocol
	issuer_serial &char
	issuer_name   &char
	chain_id      &char
	owner_trust   C.gpgme_validity_t
	subkeys       &C._gpgme_subkey
	uids          &C._gpgme_user_id
	_last_subkey  &C._gpgme_subkey
	_last_uid     &C._gpgme_user_id
	keylist_mode  C.gpgme_keylist_mode_t
	fpr           &char
	last_update   u64
}

[heap]
struct C._gpgme_subkey {
	next        &C._gpgme_subkey
	revoked     SubKeyFlags
	pubkey_algo &C.gpgme_pubkey_algo_t
	length      u32
	keyid       &char
	_keyid      [17]char
	fpr         &char
	timestamp   i64
	expires     i64
	card_number &char
	curve       &char
	keygrip     &char
}

[heap]
struct C._gpgme_user_id {
	next         &C._gpgme_user_id
	revoked      UserFlags
	validity     C.gpgme_validity_t
	uid          &char
	name         &char
	email        &char
	comment      &char
	signatures   C.gpgme_key_sig_t
	_last_keysig C.gpgme_key_sig_t
	address      &char
	tofu         C.gpgme_tofu_info_t
	last_update  u64
	uidhash      &char
}

[heap]
struct C._gpgme_op_verify_result {
	signatures &C._gpgme_signature
	file_name  &char
	is_mime    MimeFlags
}

[heap]
struct C._gpgme_signature {
	next            &C._gpgme_signature
	summary         C.gpgme_sigsum_t
	fpr             &char
	status          C.gpgme_error_t
	notations       C.gpgme_sig_notation_t
	timestamp       u64
	exp_timestamp   u64
	wrong_key_usage SignatureFlags
	validity        C.gpgme_validity_t
	validity_reason C.gpgme_error_t
	pubkey_algo     C.gpgme_pubkey_algo_t
	hash_algo       HashAlgo
	pka_address     &char
	key             C.gpgme_key_t
}

[heap]
struct C._gpgme_op_decrypt_result {
	unsupported_algorithm &char
	wrong_key_usage       DecryptResultFlags
	recipients            C._gpgme_recipient
	file_name             &char
	session_key           &char
	symkey_algo           &char
}

[heap]
struct C._gpgme_recipient {
	next        &C._gpgme_recipient
	keyid       &char
	_keyid      [17]char
	pubkey_algo C.gpgme_pubkey_algo_t
	status      C.gpgme_error_t
}

[heap]
struct C.gpgme_data_cbs {
	read    fn (voidptr, voidptr, usize) isize
	write   fn (voidptr, voidptr, usize) isize
	seek    fn (voidptr, usize, int) usize
	release fn (voidptr)
}

[heap]
struct C._gpgme_op_genkey_result {
	primary KeyResultFlags
	fpr     &char
	pubkey  &C.gpgme_data
	seckey  &C.gpgme_data
}

[heap]
struct C.gpgme_data {}

fn C.gpgme_check_version(&char) &char
fn C.gpgme_get_engine_info(&&C._gpgme_engine_info) C.gpgme_error_t
fn C.gpgme_err_code(err C.gpgme_error_t) ErrorCode
fn C.gpgme_strerror(err C.gpgme_error_t) &char
fn C.gpgme_new(&&C.gpgme_ctx_t) C.gpgme_error_t
fn C.gpgme_release(C.gpgme_ctx_t)
fn C.gpgme_key_unref(&C._gpgme_key)
fn C.gpgme_op_keylist_start(C.gpgme_ctx_t, &char, int) C.gpgme_error_t
fn C.gpgme_op_keylist_next(C.gpgme_ctx_t, &&C._gpgme_key) C.gpgme_error_t
fn C.gpgme_op_keylist_end(C.gpgme_ctx_t) C.gpgme_error_t
fn C.gpgme_set_engine_info(Protocol, &char, &char) C.gpgme_error_t
fn C.gpgme_set_armor(C.gpgme_ctx_t, int) C.gpgme_error_t
fn C.gpgme_get_armor(C.gpgme_ctx_t) int
fn C.gpgme_set_textmode(C.gpgme_ctx_t, int) C.gpgme_error_t
fn C.gpgme_get_textmode(C.gpgme_ctx_t) int
fn C.gpgme_set_protocol(C.gpgme_ctx_t, Protocol) C.gpgme_error_t
fn C.gpgme_get_protocol(C.gpgme_ctx_t) C.gpgme_protocol_t
fn C.gpgme_set_keylist_mode(C.gpgme_ctx_t, KeyListMode) C.gpgme_error_t
fn C.gpgme_get_keylist_mode(C.gpgme_ctx_t) C.gpgme_keylist_mode_t
fn C.gpgme_set_pinentry_mode(C.gpgme_ctx_t, PinEntryMode) C.gpgme_error_t
fn C.gpgme_get_pinentry_mode(C.gpgme_ctx_t) C.gpgme_pinentry_mode_t
fn C.gpgme_ctx_get_engine_info(C.gpgme_ctx_t) &C._gpgme_engine_info
fn C.gpgme_ctx_set_engine_info(C.gpgme_ctx_t, Protocol, &char, &char) C.gpgme_error_t
fn C.gpgme_get_key(C.gpgme_ctx_t, &char, &&C._gpgme_key, int) C.gpgme_error_t
fn C.gpgme_data_new(&&C.gpgme_data) C.gpgme_error_t
fn C.gpgme_data_new_from_mem(&&C.gpgme_data, &char, usize, int) C.gpgme_error_t
fn C.gpgme_data_new_from_fd(&&C.gpgme_data, int) C.gpgme_error_t
fn C.gpgme_data_release_and_get_mem(&C.gpgme_data, &usize) &char
fn C.gpgme_op_encrypt(C.gpgme_ctx_t, &&C._gpgme_key, EncryptFlag, &C.gpgme_data, &C.gpgme_data) C.gpgme_error_t
fn C.gpgme_op_encrypt_sign(C.gpgme_ctx_t, &&C._gpgme_key, EncryptFlag, &C.gpgme_data, &C.gpgme_data) C.gpgme_error_t
fn C.gpgme_op_decrypt(C.gpgme_ctx_t, &C.gpgme_data, &C.gpgme_data) C.gpgme_error_t
fn C.gpgme_op_verify(C.gpgme_ctx_t, &C.gpgme_data, &C.gpgme_data, &C.gpgme_data) C.gpgme_error_t
fn C.gpgme_op_decrypt_verify(C.gpgme_ctx_t, &C.gpgme_data, &C.gpgme_data) C.gpgme_error_t
fn C.gpgme_op_sign(C.gpgme_ctx_t, &C.gpgme_data, &C.gpgme_data, SignatureMode) C.gpgme_error_t
fn C.gpgme_data_read(&C.gpgme_data, voidptr, usize) isize
fn C.gpgme_data_write(&C.gpgme_data, voidptr, usize) isize
fn C.gpgme_data_seek(&C.gpgme_data, isize, int) isize
fn C.gpgme_data_release(&C.gpgme_data)
fn C.gpgme_free(voidptr)
fn C.gpgme_signers_clear(C.gpgme_ctx_t)
fn C.gpgme_signers_add(C.gpgme_ctx_t, &C._gpgme_key) C.gpgme_error_t
fn C.gpgme_signers_count(C.gpgme_ctx_t) u32
fn C.gpgme_signers_enum(C.gpgme_ctx_t, i32) &C._gpgme_key
fn C.gpgme_op_verify_result(C.gpgme_ctx_t) &C._gpgme_op_verify_result
fn C.gpgme_op_sign_result(C.gpgme_ctx_t) &C._gpgme_op_sign_result
fn C.gpgme_op_decrypt_result(C.gpgme_ctx_t) &C._gpgme_op_decrypt_result
fn C.gpgme_op_encrypt_result(C.gpgme_ctx_t) &C._gpgme_op_encrypt_result
fn C.gpgme_result_ref(voidptr)
fn C.gpgme_result_unref(voidptr)
fn C.gpgme_error(u32) C.gpgme_error_t
fn C.gpgme_io_writen(int, voidptr, u32) int
fn C.gpgme_io_read(int, voidptr, u32) i32
fn C.gpgme_set_passphrase_cb(C.gpgme_ctx_t, voidptr, voidptr)
fn C.gpgme_data_new_from_cbs(&&C.gpgme_data, &C.gpgme_data_cbs, voidptr) C.gpgme_error_t
fn C.gpgme_op_createkey(C.gpgme_ctx_t, &char, &char, u64, u64, &C._gpgme_key, u32) C.gpgme_error_t
fn C.gpgme_op_createsubkey(C.gpgme_ctx_t, &C._gpgme_key, &char, u64, u64, u32) C.gpgme_error_t
fn C.gpgme_op_delete_ext(C.gpgme_ctx_t, &C._gpgme_key, u32) C.gpgme_error_t
fn C.gpgme_op_genkey_result(C.gpgme_ctx_t) &C._gpgme_op_genkey_result
