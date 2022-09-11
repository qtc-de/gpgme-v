module gpgme

import time

// Signature stores the relevant information from a  _gpgme_signature structure.
struct Signature {
pub mut:
	summary         SigSum
	fingerprint     string
	status          GpgError
	timestamp       time.Time
	exp_timestamp   time.Time
	wrong_key_usage bool
	pka_trust       u32
	chain_model     bool
	validity        Validity
	validity_reason GpgError
	pubkey_algo     PubkeyAlgo
	hash_algo       HashAlgo
	filename        string
}
