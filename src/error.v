module gpgme

// ErrorCode is just a wrapper around possible gpgme error codes
// from the gpgme C library.
pub enum ErrorCode {
	no_error = C.GPG_ERR_NO_ERROR
	general = C.GPG_ERR_GENERAL
	unknown_packet = C.GPG_ERR_UNKNOWN_PACKET
	unknown_version = C.GPG_ERR_UNKNOWN_VERSION
	pubkey_algo = C.GPG_ERR_PUBKEY_ALGO
	digest_algo = C.GPG_ERR_DIGEST_ALGO
	bad_pubkey = C.GPG_ERR_BAD_PUBKEY
	bad_seckey = C.GPG_ERR_BAD_SECKEY
	bad_signature = C.GPG_ERR_BAD_SIGNATURE
	no_pubkey = C.GPG_ERR_NO_PUBKEY
	checksum = C.GPG_ERR_CHECKSUM
	bad_passphrase = C.GPG_ERR_BAD_PASSPHRASE
	cipher_algo = C.GPG_ERR_CIPHER_ALGO
	keyring_open = C.GPG_ERR_KEYRING_OPEN
	inv_packet = C.GPG_ERR_INV_PACKET
	inv_armor = C.GPG_ERR_INV_ARMOR
	no_user_id = C.GPG_ERR_NO_USER_ID
	no_seckey = C.GPG_ERR_NO_SECKEY
	wrong_seckey = C.GPG_ERR_WRONG_SECKEY
	bad_key = C.GPG_ERR_BAD_KEY
	compr_algo = C.GPG_ERR_COMPR_ALGO
	no_prime = C.GPG_ERR_NO_PRIME
	no_encoding_method = C.GPG_ERR_NO_ENCODING_METHOD
	no_encryption_scheme = C.GPG_ERR_NO_ENCRYPTION_SCHEME
	no_signature_scheme = C.GPG_ERR_NO_SIGNATURE_SCHEME
	inv_attr = C.GPG_ERR_INV_ATTR
	no_value = C.GPG_ERR_NO_VALUE
	not_found = C.GPG_ERR_NOT_FOUND
	value_not_found = C.GPG_ERR_VALUE_NOT_FOUND
	syntax = C.GPG_ERR_SYNTAX
	bad_mpi = C.GPG_ERR_BAD_MPI
	inv_passphrase = C.GPG_ERR_INV_PASSPHRASE
	sig_class = C.GPG_ERR_SIG_CLASS
	resource_limit = C.GPG_ERR_RESOURCE_LIMIT
	inv_keyring = C.GPG_ERR_INV_KEYRING
	trustdb = C.GPG_ERR_TRUSTDB
	bad_cert = C.GPG_ERR_BAD_CERT
	inv_user_id = C.GPG_ERR_INV_USER_ID
	unexpected = C.GPG_ERR_UNEXPECTED
	time_conflict = C.GPG_ERR_TIME_CONFLICT
	keyserver = C.GPG_ERR_KEYSERVER
	wrong_pubkey_algo = C.GPG_ERR_WRONG_PUBKEY_ALGO
	tribute_to_d_a = C.GPG_ERR_TRIBUTE_TO_D_A
	weak_key = C.GPG_ERR_WEAK_KEY
	inv_keylen = C.GPG_ERR_INV_KEYLEN
	inv_arg = C.GPG_ERR_INV_ARG
	bad_uri = C.GPG_ERR_BAD_URI
	inv_uri = C.GPG_ERR_INV_URI
	network = C.GPG_ERR_NETWORK
	unknown_host = C.GPG_ERR_UNKNOWN_HOST
	selftest_failed = C.GPG_ERR_SELFTEST_FAILED
	not_encrypted = C.GPG_ERR_NOT_ENCRYPTED
	not_processed = C.GPG_ERR_NOT_PROCESSED
	unusable_pubkey = C.GPG_ERR_UNUSABLE_PUBKEY
	unusable_seckey = C.GPG_ERR_UNUSABLE_SECKEY
	inv_value = C.GPG_ERR_INV_VALUE
	bad_cert_chain = C.GPG_ERR_BAD_CERT_CHAIN
	missing_cert = C.GPG_ERR_MISSING_CERT
	no_data = C.GPG_ERR_NO_DATA
	bug = C.GPG_ERR_BUG
	not_supported = C.GPG_ERR_NOT_SUPPORTED
	inv_op = C.GPG_ERR_INV_OP
	timeout = C.GPG_ERR_TIMEOUT
	internal = C.GPG_ERR_INTERNAL
	eof_gcrypt = C.GPG_ERR_EOF_GCRYPT
	inv_obj = C.GPG_ERR_INV_OBJ
	too_short = C.GPG_ERR_TOO_SHORT
	too_large = C.GPG_ERR_TOO_LARGE
	no_obj = C.GPG_ERR_NO_OBJ
	not_implemented = C.GPG_ERR_NOT_IMPLEMENTED
	conflict = C.GPG_ERR_CONFLICT
	inv_cipher_mode = C.GPG_ERR_INV_CIPHER_MODE
	inv_flag = C.GPG_ERR_INV_FLAG
	inv_handle = C.GPG_ERR_INV_HANDLE
	truncated = C.GPG_ERR_TRUNCATED
	incomplete_line = C.GPG_ERR_INCOMPLETE_LINE
	inv_response = C.GPG_ERR_INV_RESPONSE
	no_agent = C.GPG_ERR_NO_AGENT
	agent = C.GPG_ERR_AGENT
	inv_data = C.GPG_ERR_INV_DATA
	assuan_server_fault = C.GPG_ERR_ASSUAN_SERVER_FAULT
	assuan = C.GPG_ERR_ASSUAN
	inv_session_key = C.GPG_ERR_INV_SESSION_KEY
	inv_sexp = C.GPG_ERR_INV_SEXP
	unsupported_algorithm = C.GPG_ERR_UNSUPPORTED_ALGORITHM
	no_pin_entry = C.GPG_ERR_NO_PIN_ENTRY
	pin_entry = C.GPG_ERR_PIN_ENTRY
	bad_pin = C.GPG_ERR_BAD_PIN
	inv_name = C.GPG_ERR_INV_NAME
	bad_data = C.GPG_ERR_BAD_DATA
	inv_parameter = C.GPG_ERR_INV_PARAMETER
	wrong_card = C.GPG_ERR_WRONG_CARD
	no_dirmngr = C.GPG_ERR_NO_DIRMNGR
	dirmngr = C.GPG_ERR_DIRMNGR
	cert_revoked = C.GPG_ERR_CERT_REVOKED
	no_crl_known = C.GPG_ERR_NO_CRL_KNOWN
	crl_too_old = C.GPG_ERR_CRL_TOO_OLD
	line_too_long = C.GPG_ERR_LINE_TOO_LONG
	not_trusted = C.GPG_ERR_NOT_TRUSTED
	canceled = C.GPG_ERR_CANCELED
	bad_ca_cert = C.GPG_ERR_BAD_CA_CERT
	cert_expired = C.GPG_ERR_CERT_EXPIRED
	cert_too_young = C.GPG_ERR_CERT_TOO_YOUNG
	unsupported_cert = C.GPG_ERR_UNSUPPORTED_CERT
	unknown_sexp = C.GPG_ERR_UNKNOWN_SEXP
	unsupported_protection = C.GPG_ERR_UNSUPPORTED_PROTECTION
	corrupted_protection = C.GPG_ERR_CORRUPTED_PROTECTION
	ambiguous_name = C.GPG_ERR_AMBIGUOUS_NAME
	card = C.GPG_ERR_CARD
	card_reset = C.GPG_ERR_CARD_RESET
	card_removed = C.GPG_ERR_CARD_REMOVED
	inv_card = C.GPG_ERR_INV_CARD
	card_not_present = C.GPG_ERR_CARD_NOT_PRESENT
	no_pkcs15_app = C.GPG_ERR_NO_PKCS15_APP
	not_confirmed = C.GPG_ERR_NOT_CONFIRMED
	configuration = C.GPG_ERR_CONFIGURATION
	no_policy_match = C.GPG_ERR_NO_POLICY_MATCH
	inv_index = C.GPG_ERR_INV_INDEX
	inv_id = C.GPG_ERR_INV_ID
	no_scdaemon = C.GPG_ERR_NO_SCDAEMON
	scdaemon = C.GPG_ERR_SCDAEMON
	unsupported_protocol = C.GPG_ERR_UNSUPPORTED_PROTOCOL
	bad_pin_method = C.GPG_ERR_BAD_PIN_METHOD
	card_not_initialized = C.GPG_ERR_CARD_NOT_INITIALIZED
	unsupported_operation = C.GPG_ERR_UNSUPPORTED_OPERATION
	wrong_key_usage = C.GPG_ERR_WRONG_KEY_USAGE
	nothing_found = C.GPG_ERR_NOTHING_FOUND
	wrong_blob_type = C.GPG_ERR_WRONG_BLOB_TYPE
	missing_value = C.GPG_ERR_MISSING_VALUE
	hardware = C.GPG_ERR_HARDWARE
	pin_blocked = C.GPG_ERR_PIN_BLOCKED
	use_conditions = C.GPG_ERR_USE_CONDITIONS
	pin_not_synced = C.GPG_ERR_PIN_NOT_SYNCED
	inv_crl = C.GPG_ERR_INV_CRL
	bad_ber = C.GPG_ERR_BAD_BER
	inv_ber = C.GPG_ERR_INV_BER
	element_not_found = C.GPG_ERR_ELEMENT_NOT_FOUND
	identifier_not_found = C.GPG_ERR_IDENTIFIER_NOT_FOUND
	inv_tag = C.GPG_ERR_INV_TAG
	inv_length = C.GPG_ERR_INV_LENGTH
	inv_keyinfo = C.GPG_ERR_INV_KEYINFO
	unexpected_tag = C.GPG_ERR_UNEXPECTED_TAG
	not_der_encoded = C.GPG_ERR_NOT_DER_ENCODED
	no_cms_obj = C.GPG_ERR_NO_CMS_OBJ
	inv_cms_obj = C.GPG_ERR_INV_CMS_OBJ
	unknown_cms_obj = C.GPG_ERR_UNKNOWN_CMS_OBJ
	unsupported_cms_obj = C.GPG_ERR_UNSUPPORTED_CMS_OBJ
	unsupported_encoding = C.GPG_ERR_UNSUPPORTED_ENCODING
	unsupported_cms_version = C.GPG_ERR_UNSUPPORTED_CMS_VERSION
	unknown_algorithm = C.GPG_ERR_UNKNOWN_ALGORITHM
	inv_engine = C.GPG_ERR_INV_ENGINE
	pubkey_not_trusted = C.GPG_ERR_PUBKEY_NOT_TRUSTED
	decrypt_failed = C.GPG_ERR_DECRYPT_FAILED
	key_expired = C.GPG_ERR_KEY_EXPIRED
	sig_expired = C.GPG_ERR_SIG_EXPIRED
	encoding_problem = C.GPG_ERR_ENCODING_PROBLEM
	inv_state = C.GPG_ERR_INV_STATE
	dup_value = C.GPG_ERR_DUP_VALUE
	missing_action = C.GPG_ERR_MISSING_ACTION
	module_not_found = C.GPG_ERR_MODULE_NOT_FOUND
	inv_oid_string = C.GPG_ERR_INV_OID_STRING
	inv_time = C.GPG_ERR_INV_TIME
	inv_crl_obj = C.GPG_ERR_INV_CRL_OBJ
	unsupported_crl_version = C.GPG_ERR_UNSUPPORTED_CRL_VERSION
	inv_cert_obj = C.GPG_ERR_INV_CERT_OBJ
	unknown_name = C.GPG_ERR_UNKNOWN_NAME
	locale_problem = C.GPG_ERR_LOCALE_PROBLEM
	not_locked = C.GPG_ERR_NOT_LOCKED
	protocol_violation = C.GPG_ERR_PROTOCOL_VIOLATION
	inv_mac = C.GPG_ERR_INV_MAC
	inv_request = C.GPG_ERR_INV_REQUEST
	unknown_extn = C.GPG_ERR_UNKNOWN_EXTN
	unknown_crit_extn = C.GPG_ERR_UNKNOWN_CRIT_EXTN
	locked = C.GPG_ERR_LOCKED
	unknown_option = C.GPG_ERR_UNKNOWN_OPTION
	unknown_command = C.GPG_ERR_UNKNOWN_COMMAND
	not_operational = C.GPG_ERR_NOT_OPERATIONAL
	no_passphrase = C.GPG_ERR_NO_PASSPHRASE
	no_pin = C.GPG_ERR_NO_PIN
	not_enabled = C.GPG_ERR_NOT_ENABLED
	no_engine = C.GPG_ERR_NO_ENGINE
	missing_key = C.GPG_ERR_MISSING_KEY
	too_many = C.GPG_ERR_TOO_MANY
	limit_reached = C.GPG_ERR_LIMIT_REACHED
	not_initialized = C.GPG_ERR_NOT_INITIALIZED
	missing_issuer_cert = C.GPG_ERR_MISSING_ISSUER_CERT
	no_keyserver = C.GPG_ERR_NO_KEYSERVER
	inv_curve = C.GPG_ERR_INV_CURVE
	unknown_curve = C.GPG_ERR_UNKNOWN_CURVE
	dup_key = C.GPG_ERR_DUP_KEY
	ambiguous = C.GPG_ERR_AMBIGUOUS
	no_crypt_ctx = C.GPG_ERR_NO_CRYPT_CTX
	wrong_crypt_ctx = C.GPG_ERR_WRONG_CRYPT_CTX
	bad_crypt_ctx = C.GPG_ERR_BAD_CRYPT_CTX
	crypt_ctx_conflict = C.GPG_ERR_CRYPT_CTX_CONFLICT
	broken_pubkey = C.GPG_ERR_BROKEN_PUBKEY
	broken_seckey = C.GPG_ERR_BROKEN_SECKEY
	mac_algo = C.GPG_ERR_MAC_ALGO
	fully_canceled = C.GPG_ERR_FULLY_CANCELED
	unfinished = C.GPG_ERR_UNFINISHED
	buffer_too_short = C.GPG_ERR_BUFFER_TOO_SHORT
	sexp_inv_len_spec = C.GPG_ERR_SEXP_INV_LEN_SPEC
	sexp_string_too_long = C.GPG_ERR_SEXP_STRING_TOO_LONG
	sexp_unmatched_paren = C.GPG_ERR_SEXP_UNMATCHED_PAREN
	sexp_not_canonical = C.GPG_ERR_SEXP_NOT_CANONICAL
	sexp_bad_character = C.GPG_ERR_SEXP_BAD_CHARACTER
	sexp_bad_quotation = C.GPG_ERR_SEXP_BAD_QUOTATION
	sexp_zero_prefix = C.GPG_ERR_SEXP_ZERO_PREFIX
	sexp_nested_dh = C.GPG_ERR_SEXP_NESTED_DH
	sexp_unmatched_dh = C.GPG_ERR_SEXP_UNMATCHED_DH
	sexp_unexpected_punc = C.GPG_ERR_SEXP_UNEXPECTED_PUNC
	sexp_bad_hex_char = C.GPG_ERR_SEXP_BAD_HEX_CHAR
	sexp_odd_hex_numbers = C.GPG_ERR_SEXP_ODD_HEX_NUMBERS
	sexp_bad_oct_char = C.GPG_ERR_SEXP_BAD_OCT_CHAR
	subkeys_exp_or_rev = C.GPG_ERR_SUBKEYS_EXP_OR_REV
	db_corrupted = C.GPG_ERR_DB_CORRUPTED
	server_failed = C.GPG_ERR_SERVER_FAILED
	no_name = C.GPG_ERR_NO_NAME
	no_key = C.GPG_ERR_NO_KEY
	legacy_key = C.GPG_ERR_LEGACY_KEY
	request_too_short = C.GPG_ERR_REQUEST_TOO_SHORT
	request_too_long = C.GPG_ERR_REQUEST_TOO_LONG
	obj_term_state = C.GPG_ERR_OBJ_TERM_STATE
	no_cert_chain = C.GPG_ERR_NO_CERT_CHAIN
	cert_too_large = C.GPG_ERR_CERT_TOO_LARGE
	inv_record = C.GPG_ERR_INV_RECORD
	bad_mac = C.GPG_ERR_BAD_MAC
	unexpected_msg = C.GPG_ERR_UNEXPECTED_MSG
	compr_failed = C.GPG_ERR_COMPR_FAILED
	would_wrap = C.GPG_ERR_WOULD_WRAP
	fatal_alert = C.GPG_ERR_FATAL_ALERT
	no_cipher = C.GPG_ERR_NO_CIPHER
	missing_client_cert = C.GPG_ERR_MISSING_CLIENT_CERT
	close_notify = C.GPG_ERR_CLOSE_NOTIFY
	ticket_expired = C.GPG_ERR_TICKET_EXPIRED
	bad_ticket = C.GPG_ERR_BAD_TICKET
	unknown_identity = C.GPG_ERR_UNKNOWN_IDENTITY
	bad_hs_cert = C.GPG_ERR_BAD_HS_CERT
	bad_hs_cert_req = C.GPG_ERR_BAD_HS_CERT_REQ
	bad_hs_cert_ver = C.GPG_ERR_BAD_HS_CERT_VER
	bad_hs_change_cipher = C.GPG_ERR_BAD_HS_CHANGE_CIPHER
	bad_hs_client_hello = C.GPG_ERR_BAD_HS_CLIENT_HELLO
	bad_hs_server_hello = C.GPG_ERR_BAD_HS_SERVER_HELLO
	bad_hs_server_hello_done = C.GPG_ERR_BAD_HS_SERVER_HELLO_DONE
	bad_hs_finished = C.GPG_ERR_BAD_HS_FINISHED
	bad_hs_server_kex = C.GPG_ERR_BAD_HS_SERVER_KEX
	bad_hs_client_kex = C.GPG_ERR_BAD_HS_CLIENT_KEX
	bogus_string = C.GPG_ERR_BOGUS_STRING
	forbidden = C.GPG_ERR_FORBIDDEN
	key_disabled = C.GPG_ERR_KEY_DISABLED
	key_on_card = C.GPG_ERR_KEY_ON_CARD
	inv_lock_obj = C.GPG_ERR_INV_LOCK_OBJ
	err_true = C.GPG_ERR_TRUE
	err_false = C.GPG_ERR_FALSE
	ass_general = C.GPG_ERR_ASS_GENERAL
	ass_accept_failed = C.GPG_ERR_ASS_ACCEPT_FAILED
	ass_connect_failed = C.GPG_ERR_ASS_CONNECT_FAILED
	ass_inv_response = C.GPG_ERR_ASS_INV_RESPONSE
	ass_inv_value = C.GPG_ERR_ASS_INV_VALUE
	ass_incomplete_line = C.GPG_ERR_ASS_INCOMPLETE_LINE
	ass_line_too_long = C.GPG_ERR_ASS_LINE_TOO_LONG
	ass_nested_commands = C.GPG_ERR_ASS_NESTED_COMMANDS
	ass_no_data_cb = C.GPG_ERR_ASS_NO_DATA_CB
	ass_no_inquire_cb = C.GPG_ERR_ASS_NO_INQUIRE_CB
	ass_not_a_server = C.GPG_ERR_ASS_NOT_A_SERVER
	ass_not_a_client = C.GPG_ERR_ASS_NOT_A_CLIENT
	ass_server_start = C.GPG_ERR_ASS_SERVER_START
	ass_read_error = C.GPG_ERR_ASS_READ_ERROR
	ass_write_error = C.GPG_ERR_ASS_WRITE_ERROR
	ass_too_much_data = C.GPG_ERR_ASS_TOO_MUCH_DATA
	ass_unexpected_cmd = C.GPG_ERR_ASS_UNEXPECTED_CMD
	ass_unknown_cmd = C.GPG_ERR_ASS_UNKNOWN_CMD
	ass_syntax = C.GPG_ERR_ASS_SYNTAX
	ass_canceled = C.GPG_ERR_ASS_CANCELED
	ass_no_input = C.GPG_ERR_ASS_NO_INPUT
	ass_no_output = C.GPG_ERR_ASS_NO_OUTPUT
	ass_parameter = C.GPG_ERR_ASS_PARAMETER
	ass_unknown_inquire = C.GPG_ERR_ASS_UNKNOWN_INQUIRE
	engine_too_old = C.GPG_ERR_ENGINE_TOO_OLD
	window_too_small = C.GPG_ERR_WINDOW_TOO_SMALL
	window_too_large = C.GPG_ERR_WINDOW_TOO_LARGE
	missing_envvar = C.GPG_ERR_MISSING_ENVVAR
	user_id_exists = C.GPG_ERR_USER_ID_EXISTS
	name_exists = C.GPG_ERR_NAME_EXISTS
	dup_name = C.GPG_ERR_DUP_NAME
	too_young = C.GPG_ERR_TOO_YOUNG
	too_old = C.GPG_ERR_TOO_OLD
	unknown_flag = C.GPG_ERR_UNKNOWN_FLAG
	inv_order = C.GPG_ERR_INV_ORDER
	already_fetched = C.GPG_ERR_ALREADY_FETCHED
	try_later = C.GPG_ERR_TRY_LATER
	wrong_name = C.GPG_ERR_WRONG_NAME
	no_auth = C.GPG_ERR_NO_AUTH
	bad_auth = C.GPG_ERR_BAD_AUTH
	no_keyboxd = C.GPG_ERR_NO_KEYBOXD
	keyboxd = C.GPG_ERR_KEYBOXD
	no_service = C.GPG_ERR_NO_SERVICE
	service = C.GPG_ERR_SERVICE
	system_bug = C.GPG_ERR_SYSTEM_BUG
	dns_unknown = C.GPG_ERR_DNS_UNKNOWN
	dns_section = C.GPG_ERR_DNS_SECTION
	dns_address = C.GPG_ERR_DNS_ADDRESS
	dns_no_query = C.GPG_ERR_DNS_NO_QUERY
	dns_no_answer = C.GPG_ERR_DNS_NO_ANSWER
	dns_closed = C.GPG_ERR_DNS_CLOSED
	dns_verify = C.GPG_ERR_DNS_VERIFY
	dns_timeout = C.GPG_ERR_DNS_TIMEOUT
	ldap_general = C.GPG_ERR_LDAP_GENERAL
	ldap_attr_general = C.GPG_ERR_LDAP_ATTR_GENERAL
	ldap_name_general = C.GPG_ERR_LDAP_NAME_GENERAL
	ldap_security_general = C.GPG_ERR_LDAP_SECURITY_GENERAL
	ldap_service_general = C.GPG_ERR_LDAP_SERVICE_GENERAL
	ldap_update_general = C.GPG_ERR_LDAP_UPDATE_GENERAL
	ldap_e_general = C.GPG_ERR_LDAP_E_GENERAL
	ldap_x_general = C.GPG_ERR_LDAP_X_GENERAL
	ldap_other_general = C.GPG_ERR_LDAP_OTHER_GENERAL
	ldap_x_connecting = C.GPG_ERR_LDAP_X_CONNECTING
	ldap_referral_limit = C.GPG_ERR_LDAP_REFERRAL_LIMIT
	ldap_client_loop = C.GPG_ERR_LDAP_CLIENT_LOOP
	ldap_no_results = C.GPG_ERR_LDAP_NO_RESULTS
	ldap_control_not_found = C.GPG_ERR_LDAP_CONTROL_NOT_FOUND
	ldap_not_supported = C.GPG_ERR_LDAP_NOT_SUPPORTED
	ldap_connect = C.GPG_ERR_LDAP_CONNECT
	ldap_no_memory = C.GPG_ERR_LDAP_NO_MEMORY
	ldap_param = C.GPG_ERR_LDAP_PARAM
	ldap_user_cancelled = C.GPG_ERR_LDAP_USER_CANCELLED
	ldap_filter = C.GPG_ERR_LDAP_FILTER
	ldap_auth_unknown = C.GPG_ERR_LDAP_AUTH_UNKNOWN
	ldap_timeout = C.GPG_ERR_LDAP_TIMEOUT
	ldap_decoding = C.GPG_ERR_LDAP_DECODING
	ldap_encoding = C.GPG_ERR_LDAP_ENCODING
	ldap_local = C.GPG_ERR_LDAP_LOCAL
	ldap_server_down = C.GPG_ERR_LDAP_SERVER_DOWN
	ldap_success = C.GPG_ERR_LDAP_SUCCESS
	ldap_operations = C.GPG_ERR_LDAP_OPERATIONS
	ldap_protocol = C.GPG_ERR_LDAP_PROTOCOL
	ldap_timelimit = C.GPG_ERR_LDAP_TIMELIMIT
	ldap_sizelimit = C.GPG_ERR_LDAP_SIZELIMIT
	ldap_compare_false = C.GPG_ERR_LDAP_COMPARE_FALSE
	ldap_compare_true = C.GPG_ERR_LDAP_COMPARE_TRUE
	ldap_unsupported_auth = C.GPG_ERR_LDAP_UNSUPPORTED_AUTH
	ldap_strong_auth_rqrd = C.GPG_ERR_LDAP_STRONG_AUTH_RQRD
	ldap_partial_results = C.GPG_ERR_LDAP_PARTIAL_RESULTS
	ldap_referral = C.GPG_ERR_LDAP_REFERRAL
	ldap_adminlimit = C.GPG_ERR_LDAP_ADMINLIMIT
	ldap_unavail_crit_extn = C.GPG_ERR_LDAP_UNAVAIL_CRIT_EXTN
	ldap_confident_rqrd = C.GPG_ERR_LDAP_CONFIDENT_RQRD
	ldap_sasl_bind_inprog = C.GPG_ERR_LDAP_SASL_BIND_INPROG
	ldap_no_such_attribute = C.GPG_ERR_LDAP_NO_SUCH_ATTRIBUTE
	ldap_undefined_type = C.GPG_ERR_LDAP_UNDEFINED_TYPE
	ldap_bad_matching = C.GPG_ERR_LDAP_BAD_MATCHING
	ldap_const_violation = C.GPG_ERR_LDAP_CONST_VIOLATION
	ldap_type_value_exists = C.GPG_ERR_LDAP_TYPE_VALUE_EXISTS
	ldap_inv_syntax = C.GPG_ERR_LDAP_INV_SYNTAX
	ldap_no_such_obj = C.GPG_ERR_LDAP_NO_SUCH_OBJ
	ldap_alias_problem = C.GPG_ERR_LDAP_ALIAS_PROBLEM
	ldap_inv_dn_syntax = C.GPG_ERR_LDAP_INV_DN_SYNTAX
	ldap_is_leaf = C.GPG_ERR_LDAP_IS_LEAF
	ldap_alias_deref = C.GPG_ERR_LDAP_ALIAS_DEREF
	ldap_x_proxy_auth_fail = C.GPG_ERR_LDAP_X_PROXY_AUTH_FAIL
	ldap_bad_auth = C.GPG_ERR_LDAP_BAD_AUTH
	ldap_inv_credentials = C.GPG_ERR_LDAP_INV_CREDENTIALS
	ldap_insufficient_acc = C.GPG_ERR_LDAP_INSUFFICIENT_ACC
	ldap_busy = C.GPG_ERR_LDAP_BUSY
	ldap_unavailable = C.GPG_ERR_LDAP_UNAVAILABLE
	ldap_unwill_to_perform = C.GPG_ERR_LDAP_UNWILL_TO_PERFORM
	ldap_loop_detect = C.GPG_ERR_LDAP_LOOP_DETECT
	ldap_naming_violation = C.GPG_ERR_LDAP_NAMING_VIOLATION
	ldap_obj_cls_violation = C.GPG_ERR_LDAP_OBJ_CLS_VIOLATION
	ldap_not_allow_nonleaf = C.GPG_ERR_LDAP_NOT_ALLOW_NONLEAF
	ldap_not_allow_on_rdn = C.GPG_ERR_LDAP_NOT_ALLOW_ON_RDN
	ldap_already_exists = C.GPG_ERR_LDAP_ALREADY_EXISTS
	ldap_no_obj_class_mods = C.GPG_ERR_LDAP_NO_OBJ_CLASS_MODS
	ldap_results_too_large = C.GPG_ERR_LDAP_RESULTS_TOO_LARGE
	ldap_affects_mult_dsas = C.GPG_ERR_LDAP_AFFECTS_MULT_DSAS
	ldap_vlv = C.GPG_ERR_LDAP_VLV
	ldap_other = C.GPG_ERR_LDAP_OTHER
	ldap_cup_resource_limit = C.GPG_ERR_LDAP_CUP_RESOURCE_LIMIT
	ldap_cup_sec_violation = C.GPG_ERR_LDAP_CUP_SEC_VIOLATION
	ldap_cup_inv_data = C.GPG_ERR_LDAP_CUP_INV_DATA
	ldap_cup_unsup_scheme = C.GPG_ERR_LDAP_CUP_UNSUP_SCHEME
	ldap_cup_reload = C.GPG_ERR_LDAP_CUP_RELOAD
	ldap_cancelled = C.GPG_ERR_LDAP_CANCELLED
	ldap_no_such_operation = C.GPG_ERR_LDAP_NO_SUCH_OPERATION
	ldap_too_late = C.GPG_ERR_LDAP_TOO_LATE
	ldap_cannot_cancel = C.GPG_ERR_LDAP_CANNOT_CANCEL
	ldap_assertion_failed = C.GPG_ERR_LDAP_ASSERTION_FAILED
	ldap_prox_auth_denied = C.GPG_ERR_LDAP_PROX_AUTH_DENIED
	user_1 = C.GPG_ERR_USER_1
	user_2 = C.GPG_ERR_USER_2
	user_3 = C.GPG_ERR_USER_3
	user_4 = C.GPG_ERR_USER_4
	user_5 = C.GPG_ERR_USER_5
	user_6 = C.GPG_ERR_USER_6
	user_7 = C.GPG_ERR_USER_7
	user_8 = C.GPG_ERR_USER_8
	user_9 = C.GPG_ERR_USER_9
	user_10 = C.GPG_ERR_USER_10
	user_11 = C.GPG_ERR_USER_11
	user_12 = C.GPG_ERR_USER_12
	user_13 = C.GPG_ERR_USER_13
	user_14 = C.GPG_ERR_USER_14
	user_15 = C.GPG_ERR_USER_15
	user_16 = C.GPG_ERR_USER_16
	sql_ok = C.GPG_ERR_SQL_OK
	sql_error = C.GPG_ERR_SQL_ERROR
	sql_internal = C.GPG_ERR_SQL_INTERNAL
	sql_perm = C.GPG_ERR_SQL_PERM
	sql_abort = C.GPG_ERR_SQL_ABORT
	sql_busy = C.GPG_ERR_SQL_BUSY
	sql_locked = C.GPG_ERR_SQL_LOCKED
	sql_nomem = C.GPG_ERR_SQL_NOMEM
	sql_readonly = C.GPG_ERR_SQL_READONLY
	sql_interrupt = C.GPG_ERR_SQL_INTERRUPT
	sql_ioerr = C.GPG_ERR_SQL_IOERR
	sql_corrupt = C.GPG_ERR_SQL_CORRUPT
	sql_notfound = C.GPG_ERR_SQL_NOTFOUND
	sql_full = C.GPG_ERR_SQL_FULL
	sql_cantopen = C.GPG_ERR_SQL_CANTOPEN
	sql_protocol = C.GPG_ERR_SQL_PROTOCOL
	sql_empty = C.GPG_ERR_SQL_EMPTY
	sql_schema = C.GPG_ERR_SQL_SCHEMA
	sql_toobig = C.GPG_ERR_SQL_TOOBIG
	sql_constraint = C.GPG_ERR_SQL_CONSTRAINT
	sql_mismatch = C.GPG_ERR_SQL_MISMATCH
	sql_misuse = C.GPG_ERR_SQL_MISUSE
	sql_nolfs = C.GPG_ERR_SQL_NOLFS
	sql_auth = C.GPG_ERR_SQL_AUTH
	sql_format = C.GPG_ERR_SQL_FORMAT
	sql_range = C.GPG_ERR_SQL_RANGE
	sql_notadb = C.GPG_ERR_SQL_NOTADB
	sql_notice = C.GPG_ERR_SQL_NOTICE
	sql_warning = C.GPG_ERR_SQL_WARNING
	sql_row = C.GPG_ERR_SQL_ROW
	sql_done = C.GPG_ERR_SQL_DONE
	missing_errno = C.GPG_ERR_MISSING_ERRNO
	unknown_errno = C.GPG_ERR_UNKNOWN_ERRNO
	eof = C.GPG_ERR_EOF
	e2big = C.GPG_ERR_SYSTEM_ERROR | 0
	eacces = C.GPG_ERR_SYSTEM_ERROR | 1
	eaddrinuse = C.GPG_ERR_SYSTEM_ERROR | 2
	eaddrnotavail = C.GPG_ERR_SYSTEM_ERROR | 3
	eadv = C.GPG_ERR_SYSTEM_ERROR | 4
	eafnosupport = C.GPG_ERR_SYSTEM_ERROR | 5
	eagain = C.GPG_ERR_SYSTEM_ERROR | 6
	ealready = C.GPG_ERR_SYSTEM_ERROR | 7
	eauth = C.GPG_ERR_SYSTEM_ERROR | 8
	ebackground = C.GPG_ERR_SYSTEM_ERROR | 9
	ebade = C.GPG_ERR_SYSTEM_ERROR | 10
	ebadf = C.GPG_ERR_SYSTEM_ERROR | 11
	ebadfd = C.GPG_ERR_SYSTEM_ERROR | 12
	ebadmsg = C.GPG_ERR_SYSTEM_ERROR | 13
	ebadr = C.GPG_ERR_SYSTEM_ERROR | 14
	ebadrpc = C.GPG_ERR_SYSTEM_ERROR | 15
	ebadrqc = C.GPG_ERR_SYSTEM_ERROR | 16
	ebadslt = C.GPG_ERR_SYSTEM_ERROR | 17
	ebfont = C.GPG_ERR_SYSTEM_ERROR | 18
	ebusy = C.GPG_ERR_SYSTEM_ERROR | 19
	ecanceled = C.GPG_ERR_SYSTEM_ERROR | 20
	echild = C.GPG_ERR_SYSTEM_ERROR | 21
	echrng = C.GPG_ERR_SYSTEM_ERROR | 22
	ecomm = C.GPG_ERR_SYSTEM_ERROR | 23
	econnaborted = C.GPG_ERR_SYSTEM_ERROR | 24
	econnrefused = C.GPG_ERR_SYSTEM_ERROR | 25
	econnreset = C.GPG_ERR_SYSTEM_ERROR | 26
	ed = C.GPG_ERR_SYSTEM_ERROR | 27
	edeadlk = C.GPG_ERR_SYSTEM_ERROR | 28
	edeadlock = C.GPG_ERR_SYSTEM_ERROR | 29
	edestaddrreq = C.GPG_ERR_SYSTEM_ERROR | 30
	edied = C.GPG_ERR_SYSTEM_ERROR | 31
	edom = C.GPG_ERR_SYSTEM_ERROR | 32
	edotdot = C.GPG_ERR_SYSTEM_ERROR | 33
	edquot = C.GPG_ERR_SYSTEM_ERROR | 34
	eexist = C.GPG_ERR_SYSTEM_ERROR | 35
	efault = C.GPG_ERR_SYSTEM_ERROR | 36
	efbig = C.GPG_ERR_SYSTEM_ERROR | 37
	eftype = C.GPG_ERR_SYSTEM_ERROR | 38
	egratuitous = C.GPG_ERR_SYSTEM_ERROR | 39
	egregious = C.GPG_ERR_SYSTEM_ERROR | 40
	ehostdown = C.GPG_ERR_SYSTEM_ERROR | 41
	ehostunreach = C.GPG_ERR_SYSTEM_ERROR | 42
	eidrm = C.GPG_ERR_SYSTEM_ERROR | 43
	eieio = C.GPG_ERR_SYSTEM_ERROR | 44
	eilseq = C.GPG_ERR_SYSTEM_ERROR | 45
	einprogress = C.GPG_ERR_SYSTEM_ERROR | 46
	eintr = C.GPG_ERR_SYSTEM_ERROR | 47
	einval = C.GPG_ERR_SYSTEM_ERROR | 48
	eio = C.GPG_ERR_SYSTEM_ERROR | 49
	eisconn = C.GPG_ERR_SYSTEM_ERROR | 50
	eisdir = C.GPG_ERR_SYSTEM_ERROR | 51
	eisnam = C.GPG_ERR_SYSTEM_ERROR | 52
	el2hlt = C.GPG_ERR_SYSTEM_ERROR | 53
	el2nsync = C.GPG_ERR_SYSTEM_ERROR | 54
	el3hlt = C.GPG_ERR_SYSTEM_ERROR | 55
	el3rst = C.GPG_ERR_SYSTEM_ERROR | 56
	elibacc = C.GPG_ERR_SYSTEM_ERROR | 57
	elibbad = C.GPG_ERR_SYSTEM_ERROR | 58
	elibexec = C.GPG_ERR_SYSTEM_ERROR | 59
	elibmax = C.GPG_ERR_SYSTEM_ERROR | 60
	elibscn = C.GPG_ERR_SYSTEM_ERROR | 61
	elnrng = C.GPG_ERR_SYSTEM_ERROR | 62
	eloop = C.GPG_ERR_SYSTEM_ERROR | 63
	emediumtype = C.GPG_ERR_SYSTEM_ERROR | 64
	emfile = C.GPG_ERR_SYSTEM_ERROR | 65
	emlink = C.GPG_ERR_SYSTEM_ERROR | 66
	emsgsize = C.GPG_ERR_SYSTEM_ERROR | 67
	emultihop = C.GPG_ERR_SYSTEM_ERROR | 68
	enametoolong = C.GPG_ERR_SYSTEM_ERROR | 69
	enavail = C.GPG_ERR_SYSTEM_ERROR | 70
	eneedauth = C.GPG_ERR_SYSTEM_ERROR | 71
	enetdown = C.GPG_ERR_SYSTEM_ERROR | 72
	enetreset = C.GPG_ERR_SYSTEM_ERROR | 73
	enetunreach = C.GPG_ERR_SYSTEM_ERROR | 74
	enfile = C.GPG_ERR_SYSTEM_ERROR | 75
	enoano = C.GPG_ERR_SYSTEM_ERROR | 76
	enobufs = C.GPG_ERR_SYSTEM_ERROR | 77
	enocsi = C.GPG_ERR_SYSTEM_ERROR | 78
	enodata = C.GPG_ERR_SYSTEM_ERROR | 79
	enodev = C.GPG_ERR_SYSTEM_ERROR | 80
	enoent = C.GPG_ERR_SYSTEM_ERROR | 81
	enoexec = C.GPG_ERR_SYSTEM_ERROR | 82
	enolck = C.GPG_ERR_SYSTEM_ERROR | 83
	enolink = C.GPG_ERR_SYSTEM_ERROR | 84
	enomedium = C.GPG_ERR_SYSTEM_ERROR | 85
	enomem = C.GPG_ERR_SYSTEM_ERROR | 86
	enomsg = C.GPG_ERR_SYSTEM_ERROR | 87
	enonet = C.GPG_ERR_SYSTEM_ERROR | 88
	enopkg = C.GPG_ERR_SYSTEM_ERROR | 89
	enoprotoopt = C.GPG_ERR_SYSTEM_ERROR | 90
	enospc = C.GPG_ERR_SYSTEM_ERROR | 91
	enosr = C.GPG_ERR_SYSTEM_ERROR | 92
	enostr = C.GPG_ERR_SYSTEM_ERROR | 93
	enosys = C.GPG_ERR_SYSTEM_ERROR | 94
	enotblk = C.GPG_ERR_SYSTEM_ERROR | 95
	enotconn = C.GPG_ERR_SYSTEM_ERROR | 96
	enotdir = C.GPG_ERR_SYSTEM_ERROR | 97
	enotempty = C.GPG_ERR_SYSTEM_ERROR | 98
	enotnam = C.GPG_ERR_SYSTEM_ERROR | 99
	enotsock = C.GPG_ERR_SYSTEM_ERROR | 100
	enotsup = C.GPG_ERR_SYSTEM_ERROR | 101
	enotty = C.GPG_ERR_SYSTEM_ERROR | 102
	enotuniq = C.GPG_ERR_SYSTEM_ERROR | 103
	enxio = C.GPG_ERR_SYSTEM_ERROR | 104
	eopnotsupp = C.GPG_ERR_SYSTEM_ERROR | 105
	eoverflow = C.GPG_ERR_SYSTEM_ERROR | 106
	eperm = C.GPG_ERR_SYSTEM_ERROR | 107
	epfnosupport = C.GPG_ERR_SYSTEM_ERROR | 108
	epipe = C.GPG_ERR_SYSTEM_ERROR | 109
	eproclim = C.GPG_ERR_SYSTEM_ERROR | 110
	eprocunavail = C.GPG_ERR_SYSTEM_ERROR | 111
	eprogmismatch = C.GPG_ERR_SYSTEM_ERROR | 112
	eprogunavail = C.GPG_ERR_SYSTEM_ERROR | 113
	eproto = C.GPG_ERR_SYSTEM_ERROR | 114
	eprotonosupport = C.GPG_ERR_SYSTEM_ERROR | 115
	eprototype = C.GPG_ERR_SYSTEM_ERROR | 116
	erange = C.GPG_ERR_SYSTEM_ERROR | 117
	eremchg = C.GPG_ERR_SYSTEM_ERROR | 118
	eremote = C.GPG_ERR_SYSTEM_ERROR | 119
	eremoteio = C.GPG_ERR_SYSTEM_ERROR | 120
	erestart = C.GPG_ERR_SYSTEM_ERROR | 121
	erofs = C.GPG_ERR_SYSTEM_ERROR | 122
	erpcmismatch = C.GPG_ERR_SYSTEM_ERROR | 123
	eshutdown = C.GPG_ERR_SYSTEM_ERROR | 124
	esocktnosupport = C.GPG_ERR_SYSTEM_ERROR | 125
	espipe = C.GPG_ERR_SYSTEM_ERROR | 126
	esrch = C.GPG_ERR_SYSTEM_ERROR | 127
	esrmnt = C.GPG_ERR_SYSTEM_ERROR | 128
	estale = C.GPG_ERR_SYSTEM_ERROR | 129
	estrpipe = C.GPG_ERR_SYSTEM_ERROR | 130
	etime = C.GPG_ERR_SYSTEM_ERROR | 131
	etimedout = C.GPG_ERR_SYSTEM_ERROR | 132
	etoomanyrefs = C.GPG_ERR_SYSTEM_ERROR | 133
	etxtbsy = C.GPG_ERR_SYSTEM_ERROR | 134
	euclean = C.GPG_ERR_SYSTEM_ERROR | 135
	eunatch = C.GPG_ERR_SYSTEM_ERROR | 136
	eusers = C.GPG_ERR_SYSTEM_ERROR | 137
	ewouldblock = C.GPG_ERR_SYSTEM_ERROR | 138
	exdev = C.GPG_ERR_SYSTEM_ERROR | 139
	exfull = C.GPG_ERR_SYSTEM_ERROR | 140
	code_dim = 6553
}

// GpgError stores the error code and the associated message for
// a gpgme error.
pub struct GpgError {
	Error
pub:
	error_code ErrorCode
	error_msg  string
}

// code returns the ErrorCode as integer.
pub fn (e GpgError) code() int {
	return int(e.error_code)
}

// msg returns the error message as string
pub fn (e GpgError) msg() string {
	return e.error_msg
}

// new_gpgerror creates a GpgError instance from an C.gpgme_error_t
// structure. TODO: Do we need to free the error struct here?
pub fn new_gpgerror(e C.gpgme_error_t) GpgError {
	return GpgError{
		error_code: C.gpgme_err_code(e)
		error_msg: ccp(C.gpgme_strerror(e))
	}
}

// handle_error can be used to wrap gpgme_error_t. If gpgme_error_t
// does not contain an error (status .no_error), none is returned.
// Otherwise, the corresponding error is raised.
pub fn handle_error(e C.gpgme_error_t) ? {
	err := new_gpgerror(e)

	match err.error_code {
		.no_error { return }
		else { return IError(err) }
	}
}