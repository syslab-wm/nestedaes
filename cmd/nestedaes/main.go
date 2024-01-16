package main

import (
	"flag"
	"fmt"
	"os"

	"nestedaes/internal/aesx"
	"nestedaes/internal/header"
	"nestedaes/internal/mu"
)

const usage = `Usage: nestedaes [options]

Encrypt/decrypt a file using nested AES.

positional arguments:
  MSG_FILE
    The file to encrypt or decrypt
    
options:

  Must specify exactly one of {-encrypt, -reencrypt, -decrypt}.

  -encrypt
    Encrypt MSG the first time

  -reencrypt
    Reencrypt MSG.  MSG should already be encrypted.

  -decrypt
    Decrypt MSG.

  -in-msg INPUT_MSG_FILE       
    The input message file to either encrypt, reencrypt, or decrypt.
      Must always be specified.

  -out-msg OUTPUT_MSG_FILE      
    The output msg file.  If this is the same as -in-msg, the file is overwritten.
      Must always be specified.

  -in-hdr INPUT_HDR_FILE
    The cipher's input header.  
      Must be specified for -reencrypt and -decrypt.
      Must not be specified for -encrypt.

  -out-hdr OUTPUT_HDR_FILE  
    The cipher's output header.  If this is the same as -in-hdr, the file is overwritten.
      Must be specified for -encrypt and -reencrypt.
      Must not be specified for -decrypt.

  -in-kek INPUT_KEK_FILE
    The key-encrypting key file.
      Must be specified for -reencrypt and -decrypt.
      Must not be specified for -encrypt.

  -out-kek OUTPUT_KEK_FILE
    The output key-encrypting key file.  The new KEK is written to this file.
    If this is the same as -in-kek, the file is overwritten.
      Must be specified for -encrypt and -reencrypt.
      Must not be specified for -decrypt.

  -out-dek OUTPUT_DEK_FILE
    When re-encrypting, output the new data-encrypting key (aka, the token).
      Must be specified for -reencrypt.
      Must not be specified for -encrypt and -decrypt.

  -in-tag INPUT_TAG_FILE
    The cipher's authentication tag.
      Must be specified for -decrypt.
      Must not be specified for -encrypt or -reencrypt.
 
  -out-tag OUTPUT_TAG_FILE
    The cipher's authentication tag.  The is file is created when using
    -encrypt.
      Must be specified for -encrypt.
      Must not be specified for -reencrypt or -decrypt.

examples
  $ nestedaes -encrypt -in-msg foo.txt -out-msg foo.enc -out-hdr hdr.bin -out-kek kek.key -out-tag tag.bin
  $ nestedaes -reencrypt -in-msg foo.enc -out-msg foo.enc -in-hdr hdr.bin -out-hdr hdr.bin -in-kek kek.key -out-kek kek.key -out-dek dek.key
  $ nestedaes -decrypt -in-msg foo.enc -out-msg foo.dec -in-hdr hdr.bin -in-kek kek.key -in-tag tag.bin
`

func printUsage() {
	fmt.Fprintf(os.Stderr, "%s", usage)
}

func main() {
	options := parseOptions()

	if options.encrypt {
		doEncrypt(options)
	} else if options.reencrypt {
		doReencrypt(options)
	} else {
		doDecrypt(options)
	}
}

type Options struct {
	encrypt    bool
	reencrypt  bool
	decrypt    bool
	inMsgFile  string
	outMsgFile string
	inHdrFile  string
	outHdrFile string
	inKEKFile  string
	outKEKFile string
	outDEKFile string
	inTagFile  string
	outTagFile string
}

func parseOptions() *Options {
	options := Options{}

	flag.Usage = printUsage
	flag.BoolVar(&options.encrypt, "encrypt", false, "")
	flag.BoolVar(&options.reencrypt, "reencrypt", false, "")
	flag.BoolVar(&options.decrypt, "decrypt", false, "")
	flag.StringVar(&options.inMsgFile, "in-msg", "", "")
	flag.StringVar(&options.outMsgFile, "out-msg", "", "")
	flag.StringVar(&options.inHdrFile, "in-hdr", "", "")
	flag.StringVar(&options.outHdrFile, "out-hdr", "", "")
	flag.StringVar(&options.inKEKFile, "in-kek", "", "")
	flag.StringVar(&options.outKEKFile, "out-kek", "", "")
	flag.StringVar(&options.outDEKFile, "out-dek", "", "")
	flag.StringVar(&options.inTagFile, "in-tag", "", "")
	flag.StringVar(&options.outTagFile, "out-tag", "", "")

	flag.Parse()

	if flag.NArg() != 0 {
		mu.Die("extra arguments specified")
	}

	numCmds := mu.BoolToInt(options.encrypt) + mu.BoolToInt(options.reencrypt) + mu.BoolToInt(options.decrypt)
	if numCmds == 0 {
		mu.Die("must specify one of -encrypt, -reencrypt, or -decrypt")
	}
	if numCmds > 1 {
		mu.Die("must specify exactly one of -encrypt, -reencrypt, or -decrypt")
	}

	if options.inMsgFile == "" {
		mu.Die("must specify -in-msg")
	}

	if options.outMsgFile == "" {
		mu.Die("must specify -out-msg")
	}

	if options.encrypt {
		if options.outHdrFile == "" {
			mu.Die("-encrypt requires -out-hdr")
		}
		if options.outKEKFile == "" {
			mu.Die("-encrypt requires -out-kek")
		}
		if options.outTagFile == "" {
			mu.Die("-encrypt requires -out-tag")
		}

		if options.inHdrFile != "" {
			mu.Die("-encrypt doesn't use -in-hdr")
		}
		if options.inKEKFile != "" {
			mu.Die("-encrypt doesn't use -in-kek")
		}
		if options.outDEKFile != "" {
			mu.Die("-encrypt doesn't use -out-dek")
		}
		if options.inTagFile != "" {
			mu.Die("-encrypt doesn't use -in-tag")
		}
	}

	if options.reencrypt {
		if options.inHdrFile == "" {
			mu.Die("-reencrypt requires -in-hdr")
		}
		if options.outHdrFile == "" {
			mu.Die("-reencrypt requires -out-hdr")
		}
		if options.inKEKFile == "" {
			mu.Die("-reencrypt requires -in-kek")
		}
		if options.outKEKFile == "" {
			mu.Die("-reencrypt requires -out-kek")
		}
		if options.outDEKFile == "" {
			mu.Die("-reencrypt requires -out-dek")
		}

		if options.inTagFile != "" {
			mu.Die("-reencrypt doesn't use -in-tag")

		}
		if options.outTagFile != "" {
			mu.Die("-reencrypt doesn't use -out-tag")
		}
	}

	if options.decrypt {
		if options.inHdrFile == "" {
			mu.Die("-decrypt requires -in-hdr")
		}
		if options.inKEKFile == "" {
			mu.Die("-decrypt requires -in-kek")
		}
		if options.inTagFile == "" {
			mu.Die("-decrypt requires -in-tag")
		}

		if options.outHdrFile != "" {
			mu.Die("-decrypt doesn't use -out-hdr")
		}
		if options.outKEKFile != "" {
			mu.Die("-decrypt doesn't use -out-kek")
		}
		if options.outDEKFile != "" {
			mu.Die("-decrypt doesn't use -out-dek")
		}
		if options.outTagFile != "" {
			mu.Die("-decrypt doesn't use -out-tag")
		}
	}

	return &options
}

func doEncrypt(options *Options) {
	// encrypt the plaintext message
	dek := aesx.GenKey()
	aesgcm := aesx.NewGCM(dek)

	plaintext, err := os.ReadFile(options.inMsgFile)
	if err != nil {
		mu.Die("encrypt failed: can't read input message file: %v", err)
	}

	nonce := aesx.GenZeroNonce()
	ciphertext := aesgcm.Seal(plaintext[:0], nonce, plaintext, nil)

	// cut the tag from the ciphertext and write each to their respective file
	tag := ciphertext[len(ciphertext)-aesx.TagSize:]
	ciphertext = ciphertext[:len(ciphertext)-aesx.TagSize]

	err = os.WriteFile(options.outMsgFile, ciphertext, 0644)
	if err != nil {
		mu.Die("encrypt failed: can't write output message file: %v:", err)
	}

	err = os.WriteFile(options.outTagFile, tag, 0644)
	if err != nil {
		mu.Die("encrypt failed: can't write to output tag file: %v:", err)
	}

	// create the header, which is simply the DEK encrypted with the KEK.
	kek := aesx.GenKey()
	iv := aesx.GenIVWithValue(0)
	aesctr := aesx.NewCTR(kek, iv)
	ent := &header.Entry{}
	ent.SetDEK(dek)
	entData := ent.ToBytes()
	aesctr.XORKeyStream(entData, entData)

	err = os.WriteFile(options.outHdrFile, entData, 0644)
	if err != nil {
		mu.Die("encrypt failed: can't write output header file: %v:", err)
	}

	// write the output KEK file
	err = os.WriteFile(options.outKEKFile, kek, 0644)
	if err != nil {
		mu.Die("encrypt failed: can't write output KEK file: %v:", err)
	}
}

func doReencrypt(options *Options) {
	inKEK, err := aesx.ReadKeyFile(options.inKEKFile)
	if err != nil {
		mu.Die("re-encrypt failed: %v", err)
	}

	outDEK := aesx.GenKey()
	outKEK := aesx.GenKey()

	hdr, numEntries, err := header.ReadFileRaw(options.inHdrFile)
	if err != nil {
		mu.Die("re-encrypt failed: %v", err)
	}

	// re-encrypt message
	iv := aesx.GenIVWithValue(uint64(numEntries))
	err = aesx.CTREncryptFile(outDEK, iv, options.inMsgFile, options.outMsgFile)
	if err != nil {
		mu.Die("re-encrypt failed: %v", err)
	}

	// update header */
	entry := header.NewEntry(inKEK, outDEK)
	entryData := entry.ToBytes()
	hdr = append(hdr, entryData...)
	aesctr := aesx.NewCTR(outKEK, iv)
	aesctr.XORKeyStream(hdr, hdr)

	err = os.WriteFile(options.outHdrFile, hdr, 0644)
	if err != nil {
		mu.Die("re-encrypt failed: can't write output header file: %v:", err)
	}

	err = os.WriteFile(options.outKEKFile, outKEK, 0644)
	if err != nil {
		mu.Die("re-encrypt failed: can't write output KEK file: %v:", err)
	}

	err = os.WriteFile(options.outDEKFile, outDEK, 0644)
	if err != nil {
		mu.Die("re-encrypt failed: can't write output DEK file: %v:", err)
	}
}

func doDecrypt(options *Options) {
	kek, err := aesx.ReadKeyFile(options.inKEKFile)
	if err != nil {
		mu.Die("decrypt failed: can't read key file: %v", err)
	}

	tag, err := aesx.ReadTagFile(options.inTagFile)
	if err != nil {
		mu.Die("decrypt failed: can't read tag file: %v", err)
	}

	hdr, numEntries, err := header.ReadFileRaw(options.inHdrFile)
	if err != nil {
		mu.Die("decrypt failed: can't read header file: %v", err)
	}

	fmt.Printf("num entries: %d\n", numEntries)

	ciphertext, err := os.ReadFile(options.inMsgFile)
	if err != nil {
		mu.Die("decrypt failed: can't read input message file: %v", err)
	}

	fmt.Printf("original header: % x\n", hdr)
	fmt.Printf("original ciphertext: % x\n", ciphertext)

	for i := numEntries - 1; i >= 0; i-- {
		iv := aesx.GenIVWithValue(uint64(i))
		eidx := header.EntrySize * (i + 1)
		aesx.CTRDecrypt(kek, iv, hdr[:eidx])
		fmt.Printf("header: % x\n", hdr)
		sidx := header.EntrySize * i
		entryData := hdr[sidx:eidx]
		kek = entryData[:aesx.KeySize]
		dek := entryData[aesx.KeySize:]

		if i != 0 {
			aesx.CTRDecrypt(dek, iv, ciphertext)
			fmt.Printf("ciphertext: % x\n", ciphertext)
		} else {
			aesgcm := aesx.NewGCM(dek)
			nonce := aesx.GenZeroNonce()
			ciphertext = append(ciphertext, tag...)
			plaintext, err := aesgcm.Open(ciphertext[:0], nonce, ciphertext, nil)
			if err != nil {
				mu.Die("decrypt failed: AES-GCM decrypt message file failed: %v", err)
			}

			err = os.WriteFile(options.outMsgFile, plaintext, 0644)
			if err != nil {
				mu.Die("decrypt failed: can't write output message file: %v:", err)
			}
		}
	}
}
