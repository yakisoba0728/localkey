# v0.64.0 release snapshot

`security-key-emulator.zip` is the exact frozen package copied from the verified workspace release. Its SHA-256 is `4ad6f2b91996c025cd9bbfbe5b71a8326de91c8a273d82011b080ac05291d960`. `reextract-result.json` confirms every one of the 2,234 manifest-listed files and representative SDK flows from a clean extraction. The ZIP is tracked with Git LFS. `disk-recovery.json` lists four old, reproducible v45 guest images removed from the original temporary work tree after their hashes and raw logs were preserved.

The ZIP and this Git checkout are complementary: the checkout has additional repository documentation and historical release scripts, while the ZIP represents the immutable validated v0.64.0 package. Its first integrated USB guest attempt failed and the identical-image retry passed; see `../evidence/v64-integration/guest/result.json` and both raw consoles.
