### gpgme-v

----

This repository contains a V wrapper around the well known [GPGME](https://gnupg.org/software/gpgme/index.html)
library and allows to perform basic gpg operations from V.

```console
[qtc@devbox gpgme-v]$ v run examples/encrypt_and_decrypt.v
[+] Generating first key:
[+]	 Generated primary key with fingerprint: 8DAE0F86EB9B1AAFE852CBFD8D750663A9A66DD5
[+]	 Generated subkey key with fingerprint:  AA056060024F908B6DA4F3FEFAEBADC230A12443
[+] Generating second key:
[+]	 Generated primary key with fingerprint: 73CB57D5C00CF96DA39ED240C5B65101CD27FA07
[+]	 Generated subkey key with fingerprint:  DD4366821C67E3021EE4B6722C92DF531845E635
[+] Crypted Text: -----BEGIN PGP MESSAGE-----

hQGMA4yLY2ibSeFPAQwAqaJBk/qVKBF/6UxgNjPdCRC9qsKOgZ2HdqmcKGtUoxRt
qCnmBtqXWPtGPcXJQhPRRjv4n6ZYa0DQn183wopMFcQXqSnF+NGha6cmFLtAeCOa
HiqoiirOy1arWxUjk+T8Usw/HT0jduQAEYPVsPrmY4QSbSqd86iSXYBJlXuZeg4A
pTPTzMPaD2r2TMAJwsYc+fc9RVKa8fdazTlXpFsdqDBRydAMAj3iIg21hq5rlp9u
4HDYFVtAZj4PJtoAIsmXK2B4/8z0o2Upcv+Fp38EKBb5LqXRS3X1m1I6HGSyK4dP
+49rLszTZztnBsrH/vWobNQEez+/uPSwPxjwJUx/HF17h8tlf40h5zYdizYj2Qic
tKISG5bI+wG8cJNN/KYTIaIs3TT3zgzuPaunXKsRmQjL06v+M5rZqSzET3E4c6TR
Spk9sizkFRs/qlOUHs1cQU/ClT5CcDP3ORxj4PbR7WNZuzJFoBiwrJwJogMHMzX4
jpIJLGiC7qqM+egKSWEl0ukBQHXOIKNmjJWqetImr9l5CPCPDeXXa//WtGCE/8tS
TwFx0C40Ul4u0arT2uWb7yAq4AqQF6jVccthKepudcwcnn1FrtryzTp8jtHTUOzg
VKAvUF2DlLaUgtnaheKmS2Ptcb4XRu+XjZdzWJ5mejtD+lqHqAWfghdFjGYl3ZI4
93XvRT3KCz0p4bfp2vjTEEp9fMNQtyp5cbgX/fck3dRyKzft+F5j8UjHjrtFKeBk
uhHkaekMSgGr32oNCII0W0MRfMdVINW0cunyHit4T/tlQ27kgCxass3/LtI/a2NE
BzwmMvxuiuM4Qmc28FDISg5RZg2j5t73z8klohwlKUOkAfOxvY2FrEKntw233Bnt
bLTu5rrhyhbx650xMSTlMBG9D2Pa6m10C4VEEK9/5A6XMtUxnZlR4h+0UTIX+DGz
Xq5qC9r1DR5JtpVsqGUW29KU7Gcmd+oRLjmhVHpOLVmTPaPuJR4MH7T05nl/tb6P
NHhrTOXTEigPp2+2hIFyO7P9vzoDCvQZzjSnCnVnMJViNyY1G3LLLt4rVoEW9j10
YH53m4uUX6FDV0zkh1Mf6/ZEg54lVtH3kK5ZPa1R0fkdiTxkjp8eGaoq3v0XTZmg
tfAcPT3vIsCbB9AQz5k9k8DRNGumqMgOwk/bat5Ix5nNZXc2VzaXSIvXLNXx9uql
RxGkkyDOHZMztVJtIL87dDsgeg==
=4e5/
-----END PGP MESSAGE-----

[+] Plaintext was: Secret Message
[+] Signed by:
[+]	 A69FE14DB459C729F2129F12DE63A74F66E8D05C (gpgme.SigSum{.valid | .green})
[+] Deleting key with fingerprint: 1BBE4151998F933072D6C40B1851C2134EBEC1D4
[+] Deleting key with fingerprint: 8F0ADACA2CFC181D8311C107780223D20AF21897
```


### Usage

----

The usual workflow is to instantiate the `gpgme.Context` structure and to perform
the desired operations on it. The structure should be released after usage:

```v
import gpgme

// obtain a list of available PGP keys on the system.
fn main()
{
    mut context := gpgme.new_context()?
    context.set_key_list_mode(gpgme.KeyListMode.with_secret)?

    keys := context.find_keys('', false)?
    println('[+] Available PGP keys:')

    for key in keys {
        owner := key.get_user_ids()
        println('[+]')
        println('[+] Key Owner:   ${owner[0].name}')
        println('[+] Owner Email: ${owner[0].email}')
        println('[+] Subkeys:')

        for sub in key.get_subkeys() {
            println('[+]\t Fingerprint: ${sub.fingerprint}')
            println('[+]\t CanEncrypt:  ${sub.can_encrypt}')
            println('[+]\t CanSign:     ${sub.can_sign}')
            println('[+]\t Expires:     ${sub.expires.clean()}')
            println('[+]\t PrivateKey:  ${sub.secret}')
            println('[+]')
        }
    }

    context.release()
}
```


### Current Library Status

----

The library is not complete yet. It supports basic operations like encryption,
decryption, signing and verifying. However, support for trust relationships and
other features of *GPGME* are currently not implemented.

The library currently contains some intentional memory leaks. Structures like Key
or Data are not freed manually, but already rely on V's *autofree* mechanism. However,
since *autofree* does not work correctly at the time of writing, these structures
are effectively never freed.


### Disclaimer

----

This software comes with absolutely no warranty. It was created as a funny side project
to learn more about the V language. Development has been stopped for now, but probably
continues once *autofree* becomes production ready. Pull requests, contributions and
feedback are welcome anyways :)
