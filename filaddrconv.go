package main

import (
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/minio/blake2b-simd"
	"github.com/multiformats/go-varint"
)

func convertToEthereumStyle(address string) (string, error) {
	if strings.HasPrefix(address, "f0") {
		actorID := strings.TrimPrefix(address, "f0")
		actorIDInt, err := strconv.ParseUint(actorID, 10, 64)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("0xff0000000000000000000000%016x", actorIDInt), nil
	} else if strings.HasPrefix(address, "f410f") {
		addressWithoutPrefix := strings.TrimPrefix(address, "f410f")
		decodedAddress, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(addressWithoutPrefix))
		if err != nil {
			return "", err
		}

		// Trim off last 4 bytes
		trimmedAddress := decodedAddress[:len(decodedAddress)-4]
		if len(trimmedAddress) != 20 && len(trimmedAddress) != 16 {
			return "", fmt.Errorf("invalid address length")
		}

		return fmt.Sprintf("0x%040x", new(big.Int).SetBytes(trimmedAddress)), nil
	}
	return "", fmt.Errorf("invalid address format")
}

func convertToFILStyle(address string) (string, error) {
	if strings.HasPrefix(address, "0xff00") {
		actorIDHex := strings.TrimPrefix(address, "0xff00")
		decimalID, err := strconv.ParseInt(actorIDHex, 16, 64)
		if err != nil {
			return "", err
		}
		fStyleAddress := fmt.Sprintf("f0%d", decimalID)
		return fStyleAddress, nil
	} else if strings.HasPrefix(address, "0x") {
		addressWithoutPrefix := strings.TrimPrefix(address, "0x")
		addressBytes, err := hex.DecodeString(addressWithoutPrefix)
		if err != nil {
			return "", err
		}

		// Get the addrPayload for f410 address, for checksum calculation
		addrPayload := append(varint.ToUvarint(10), addressBytes...)
		checksumHashConfig := &blake2b.Config{Size: 4}
		hasher, err := blake2b.New(checksumHashConfig)
		if err != nil {
			// If this happens sth is very wrong.
			panic(fmt.Sprintf("invalid address hash configuration: %v", err)) // ok
		}

		if _, err := hasher.Write(append([]byte{4}, []byte(addrPayload)...)); err != nil {
			// blake2bs Write implementation never returns an error in its current
			// setup. So if this happens sth went very wrong.
			panic(fmt.Sprintf("blake2b is unable to process hashes: %v", err)) // ok
		}

		encodedAddress := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(append(addressBytes, hasher.Sum(nil)...))
		fStyleAddress := fmt.Sprintf("f410f%s", strings.ToLower(encodedAddress))
		return fStyleAddress, nil
	}
	return "", fmt.Errorf("invalid address format")
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: filAddrConvertor <address>")
		return
	}

	inputAddress := os.Args[1]

	var outputAddress string
	var err error

	if strings.HasPrefix(inputAddress, "0x") {
		outputAddress, err = convertToFILStyle(inputAddress)
	} else {
		outputAddress, err = convertToEthereumStyle(inputAddress)
	}

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println(outputAddress)
}
