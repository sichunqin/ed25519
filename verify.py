import ed25519

# Test Vector
# Private key: e59964067f8da772aa66db8bb4c990103203feccce3cf7e24b38da82c43100f5
# Public key:  5c4af42f8dc436036d0e0a0010a064e139222858b79e8c1c0be061dd7f8ae4fd
# Message:  Hello
# Signature: 4ac329357f7cc2141255561bbed326ad5ab1582c4c93197eeec79ecf00ac01eb35293b365ff1431c10d40bd028c39fae185c86931fc51a8eeff40ed533f5ad05

def testSign():
    pub_key = bytes.fromhex("5c4af42f8dc436036d0e0a0010a064e139222858b79e8c1c0be061dd7f8ae4fd")
    prv_key = bytes.fromhex("e59964067f8da772aa66db8bb4c990103203feccce3cf7e24b38da82c43100f5")
    msg = b'Hello'
    expected_sig = bytes.fromhex("4ac329357f7cc2141255561bbed326ad5ab1582c4c93197eeec79ecf00ac01eb35293b365ff1431c10d40bd028c39fae185c86931fc51a8eeff40ed533f5ad05")

    signing_key = ed25519.SigningKey(prv_key)
    sig = signing_key.sign(msg)

    verify_key = ed25519.VerifyingKey(pub_key)
    verify_key.verify(expected_sig,msg)

    print(sig.hex())

def main():
    testSign();
    return

if __name__ == "__main__":
    main()

