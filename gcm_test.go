// from http://tools.ietf.org/html/draft-mcgrew-gcm-test-01
package gcm

import (
    "bytes"
    "crypto/aes"
    "encoding/hex"
    "testing"
)

type gcmTestInput struct {
    algorithm string
    key       []byte
    nonce     []byte
    plaintext []byte
    aad       []byte
    ctext     []byte
    tag       []byte
}

func hexMustDecode(s string) []byte {
    b, err := hex.DecodeString(s)
    if err != nil {
        panic(err)
    }
    return b
}

var tests = [14]*gcmTestInput{
    &gcmTestInput{
        algorithm: "AES-GCM",
        key:       hexMustDecode("4c80cdefbb5d10da906ac73c3613a634"),
        nonce:     hexMustDecode("2e443b684956ed7e3b244cfe"),
        plaintext: hexMustDecode("45000048699a000080114db7c0a80102c0a801010a9bf15638d301000001000000000000045f736970045f756470037369700963796265726369747902646b000021000101020201"),
        aad:       hexMustDecode("000043218765432100000000"),
        ctext:     hexMustDecode("fecf537e729d5b07dc30df528dd22b768d1b98736696a6fd348509fa13ceac34cfa2436f14a3f3cf65925bf1f4a13c5d15b21e1884f5ff6247aeabb786b93bce61bc17d768fd9732"),
        tag:       hexMustDecode("459018148f6cbe722fd04796562dfdb4"),
    },
    {
        algorithm: "AES-GCM",
        key:       hexMustDecode("feffe9928665731c6d6a8f9467308308"),
        nonce:     hexMustDecode("cafebabefacedbaddecaf888"),
        plaintext: hexMustDecode("4500003e698f000080114dccc0a80102c0a801010a980035002a2343b2d001000001000000000000037369700963796265726369747902646b00000100010001"),
        aad:       hexMustDecode("0000a5f80000000a"),
        ctext:     hexMustDecode("deb22cd9b07c72c16e3a65beeb8df304a5a5897d33ae530f1ba76d5d114d2a5c3de81827c10e9a4f51330d0eec416642cfbb85a5b47e48a4ec3b9ba95d918bd1"),
        tag:       hexMustDecode("83b70d3aa8bc6ee4c309e9d85a41ad4a"),
    },
    {
        algorithm: "AES-GCM",
        key:       hexMustDecode("abbccddef00112233445566778899aababbccddef00112233445566778899aab"),
        nonce:     hexMustDecode("112233440102030405060708"),
        plaintext: hexMustDecode("4500003069a6400080062690c0a801029389155e0a9e008b2dc57ee0000000007002400020bf0000020405b40101040201020201"),
        aad:       hexMustDecode("4a2cbfe300000002"),
        ctext:     hexMustDecode("ff425c9b724599df7a3bcd510194e00d6a78107f1b0b1cbf06efae9d65a5d763748a637985771d347f0545659f14e99def842d8e"),
        tag:       hexMustDecode("b335f4eecfdbf831824b4c4915956c96"),
    },
    {
        algorithm: "AES-GCM",
        key:       hexMustDecode("00000000000000000000000000000000"),
        nonce:     hexMustDecode("000000000000000000000000"),
        plaintext: hexMustDecode("4500003c99c500008001cb7a40679318010101010800075c020044006162636465666768696a6b6c6d6e6f707172737475767761626364656667686901020201"),
        aad:       hexMustDecode("0000000000000001"),
        ctext:     hexMustDecode("4688daf2f973a392732909c331d56d60f694abaa414b5e7ff5fdcdfff5e9a284456476492719ffb64de7d9dca1e1d894bc3bd57873ed4d181d19d4d5c8c18af3"),
        tag:       hexMustDecode("f821d496eeb096e98ad2b69e4799c71d"),
    },
    {
        algorithm: "AES-GCM",
        key:       hexMustDecode("3de09874b388e6491988d0c3607eae1f"),
        nonce:     hexMustDecode("57690e434e280000a2fca1a3"),
        plaintext: hexMustDecode("4500003c99c300008001cb7c40679318010101010800085c020043006162636465666768696a6b6c6d6e6f707172737475767761626364656667686901020201"),
        aad:       hexMustDecode("42f67e3f1010101010101010"),
        ctext:     hexMustDecode("fba2caa4853cf9f0f22cb10d86dd83b0fec75691cf1a04b00d1138ec9c35791765acbd8701ad79845bf9fe3fba487bc91755e6662b4c8d0d1f5e22739530320a"),
        tag:       hexMustDecode("e0d731cc978ecafaeae88f00e80d6e48"),
    },
    {
        algorithm: "AES-GCM",
        key:       hexMustDecode("3de09874b388e6491988d0c3607eae1f"),
        nonce:     hexMustDecode("57690e434e280000a2fca1a3"),
        plaintext: hexMustDecode("4500001c42a200008001441f406793b6e00000020a00f5ff01020201"),
        aad:       hexMustDecode("42f67e3f1010101010101010"),
        ctext:     hexMustDecode("fba2ca845e5df9f0f22c3e6e86dd831e1fc65792cd1af9130e1379ed"),
        tag:       hexMustDecode("369f071f35e034be95f112e4e7d05d35"),
    },
    {
        algorithm: "AES-GCM",
        key:       hexMustDecode("feffe9928665731c6d6a8f9467308308feffe9928665731c"),
        nonce:     hexMustDecode("cafebabefacedbaddecaf888"),
        plaintext: hexMustDecode("45000028a4ad4000400678800a01038f0a010612802306b8cb712602dd6bb03e501016d075680001"),
        aad:       hexMustDecode("0000a5f80000000a"),
        ctext:     hexMustDecode("a5b1f8066029aea40e598b8122de02420938b3ab33f828e687b8858b5bfbdbd0315b27452144cc77"),
        tag:       hexMustDecode("95457b9652037f5318027b5b4cd7a636"),
    },
    {
        algorithm: "AES-GCM",
        key:       hexMustDecode("abbccddef00112233445566778899aab"),
        nonce:     hexMustDecode("decaf888cafedebaceface74"),
        plaintext: hexMustDecode("4500004933ba00007f119106c3fb1d10c2b1d326c02831ce0035dd7b800302d500004e20001e8c18d75b81dc91baa0476b91b924b280389d92c963bac046ec959b6266c04722b14923010101"),
        aad:       hexMustDecode("000001000000000000000001"),
        ctext:     hexMustDecode("18a6fd42f72cbf4ab2a2ea901f73d814e3e7f243d95412e1c349c1d2fbec168f9190feebaf2cb01984e65863965d7472b79da345e0e780191f0d2f0e0f496c226f2127b27db35724e7845d68"),
        tag:       hexMustDecode("651f57e65f354f75ff17015769623436"),
    },
    {
        algorithm: "AES-GCM",
        key:       hexMustDecode("abbccddef00112233445566778899aababbccddef00112233445566778899aab"),
        nonce:     hexMustDecode("73616c74616e640169766563"),
        plaintext: hexMustDecode("45080028732c00004006e9f90a0106120a01038f06b88023dd6bafbecb71260250101f646d540001"),
        aad:       hexMustDecode("17405e67156f3126dd0db99b"),
        ctext:     hexMustDecode("f2d69ecdbd5a0d5b8d5ef38bad4da58d1f278fde98ef67549d524a3018d9a57ff4d3a31ce673119e"),
        tag:       hexMustDecode("451626c2415771e3b7eebca614c89b35"),
    },
    {
        algorithm: "AES-GCM",
        key:       hexMustDecode("3de09874b388e6491988d0c3607eae1f"),
        nonce:     hexMustDecode("57690e434e280000a2fca1a3"),
        plaintext: hexMustDecode("45000049333e00007f119182c3fb1d10c2b1d326c02831ce0035cb458003025b000001e0001e8c18d65759d52284a0352c71475c8880391c764d6e5ee0496b325ae270c03899493915010101"),
        aad:       hexMustDecode("42f67e3f1010101010101010"),
        ctext:     hexMustDecode("fba2cad12fc1f9f00d3cebf305410db83d7784b607323d220f24b0a97d54182800cadb0f68d99ef0e0c0c89ae9bea8884e52d65bc1afd0740f742444747b5b39ab533163aad4550ee5160975"),
        tag:       hexMustDecode("cdb608c5769189609763b8e18caa81e2"),
    },
    {
        algorithm: "AES-GCM",
        key:       hexMustDecode("abbccddef00112233445566778899aababbccddef00112233445566778899aab"),
        nonce:     hexMustDecode("73616c74616e640169766563"),
        plaintext: hexMustDecode("636973636f0172756c657301746865016e6574776501646566696e6501746865746563686e6f6c6f67696573017468617477696c6c01646566696e65746f6d6f72726f7701020201"),
        aad:       hexMustDecode("17405e67156f3126dd0db99b"),
        ctext:     hexMustDecode("d4b7ed86a1777f2ea13d6973d324c69e7b43f826fb56831226508bebd2dceb18d0a6df10e5487df074113e14c641024e3e6773d91a62ee429b043a10e3efe6b012a49363412364f8"),
        tag:       hexMustDecode("c0cac587f249e56b11e24f30e44ccc76"),
    },
    {
        algorithm: "AES-GCM",
        key:       hexMustDecode("7d773d00c144c525ac619d18c84a3f47"),
        nonce:     hexMustDecode("d966426743457e9182443bc6"),
        plaintext: hexMustDecode("01020201"),
        aad:       hexMustDecode("335467aeffffffff"),
        ctext:     hexMustDecode("437f866b"),
        tag:       hexMustDecode("cb3f699fe9b0822bac961c4504bef270"),
    },
    {
        algorithm: "AES-GCM",
        key:       hexMustDecode("abbccddef00112233445566778899aab"),
        nonce:     hexMustDecode("decaf888cafedebaceface74"),
        plaintext: hexMustDecode("746f016265016f72016e6f7401746f0162650001"),
        aad:       hexMustDecode("000001000000000000000001"),
        ctext:     hexMustDecode("29c9fc69a197d038ccdd14e2ddfcaa0543332164"),
        tag:       hexMustDecode("412503524303ed3c6c5f283843af8c3e"),
    },
    {
        algorithm: "AES-GCM",
        key:       hexMustDecode("6c6567616c697a656d6172696a75616e61616e64646f69746265666f72656961"),
        nonce:     hexMustDecode("7475726e333021696765746d"),
        plaintext: hexMustDecode("45000030da3a00008001df3bc0a80005c0a800010800c6cd020007006162636465666768696a6b6c6d6e6f707172737401020201"),
        aad:       hexMustDecode("796b6963ffffffffffffffff"),
        ctext:     hexMustDecode("f97ab2aa356d8edce17644ac8c78e25dd24dedbb29ebf1b64a274b39b49c3a864cd3d78ca4ae68a32b42458fb57dbe821dcc63b9"),
        tag:       hexMustDecode("d0937ba2945f669368661a329fb4c053"),
    },
}

func TestGCM(t *testing.T) {
    for i, test := range tests {
        blockCipher, err := aes.NewCipher(test.key)
        if err != nil {
            t.Error(err)
            continue
        }

        gcm, err := NewGCM(blockCipher, 128, test.nonce)
        if err != nil {
            t.Error(err)
            continue
        }

        // test encryption
        ciph, tag := gcm.Encrypt(bytes.NewBuffer(test.plaintext), test.aad)
        if bytes.Compare(tag, test.tag) != 0 {
            t.Errorf("Test %d: Encrypt() produced incorrect tag %s", i, hex.EncodeToString(tag))
        } else if bytes.Compare(ciph, test.ctext) != 0 {
            t.Errorf("Test %d: Encrypt() produced incorrect ciphertext %s", i, hex.EncodeToString(ciph))
        }

        // now test decryption
        plain, err := gcm.Decrypt(ciph, test.aad, tag)
        if err != nil {
            t.Errorf("Test %d: %v", i, err)
        }
        if bytes.Compare(plain, test.plaintext) != 0 {
            t.Errorf("Test %d: Decrypt() produced incorrect plaintext %s", i, hex.EncodeToString(plain))
        }
    }
}

func BenchmarkEncryption(b *testing.B) {
    b.StopTimer()
    blockCipher, err := aes.NewCipher(tests[10].key)
    if err != nil {
        b.Error(err)
		return
    }
	
	gcm, err := NewGCM(blockCipher, 128, tests[10].nonce)
	if err != nil {
		b.Error(err)
		return
	}
	
	inbuf := bytes.NewBuffer(tests[10].plaintext)
	aad := tests[10].aad
    b.StartTimer()
	
	for i := 0; i < b.N; i++ {
		gcm.Encrypt(inbuf, aad)
	}
}
