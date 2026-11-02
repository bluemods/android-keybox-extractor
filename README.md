# Android Keybox Extractor

This is a utility for extracting Android factory attestation keys / certs from binary files to converting them back to the standard `<AndroidAttestation>` XML representation.

## Motivation

There are already keybox extractors that exist online, but most of them use a primitive strategy;
they only check for the XML representation of a keybox.xml in a partition.

This is an incorrect approach, as most paths / methods that result in extracted key material will output the certs and private keys in binary format instead of the ready-to-use XML format.

This library does not look for keybox files in XML format (you can do that yourself easily with something like ```grep -ir "<AndroidAttestation"``` against dumped partitions) it instead scans raw binary files looking for encoded X.509 certificates as well as RSA and EC private keys.

When it finds them, it will reconstruct the chains in order, match the private keys to them, and check to see if they chain to Google's [attestation root keys](https://android.googleapis.com/attestation/root).

If it does, it will reconstruct them into a valid keybox.xml and output it.

This tool also checks if the key is [revoked](https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status) and outputs the result in the XML file.

## Advantages of the key carving approach
- Detect and extract keyboxes from binary format, which is often necessary for most extraction methods:
    - Key material extracted from the TEE is in binary format
    - Key material dumped from partitions is usually in binary format
- Extract ECDSA keys efficiently by doing a window search near an RSA key 
    - ECDSA keys are slow / difficult to scan for, missed by generic tools like `binwalk`

## Usage

```bash
go mod tidy && go build && ./android-keybox-extractor path/to/file.bin
```

If successful, a keybox file will be output.

## TODO
- Currently, Windows reads the full bin file into memory while Linux uses `mmap()`, so Windows will run out of memory on large files.
- `CDI_Leaf` extraction

## Disclaimer
- For research purposes only
- Do not share extracted key material / keyboxes, never commit them to any repository
- Important: in most cases, key material won't be sitting in plain text in a partition.
  - In those cases it will require extra work to extract the plaintext (e.g. by finding flaws in the boot chain / TEE, highly dependent on the device), which is out of scope for this repository.