package blsgen

import (
	"fmt"
	"os"
	"path/filepath"
	"github.com/harmony-one/harmony/multibls"
	"github.com/harmony-one/harmony/crypto/bls_interface"
)

// loadHelper defines the helper interface to load bls keys. Implemented by
//   multiKeyLoader - load key files with a slice of target key files
//   blsDirLoader   - load key files from a directory
type loadHelper interface {
	loadKeys() (multibls.PrivateKeys, error)
}

// multiKeyLoader load keys from multiple bls key files
type multiKeyLoader struct {
	keyFiles   []string
	decrypters map[string]keyDecrypter

	loadedSecrets []*bls_interface.BlsSecretKey
}

func newMultiKeyLoader(keyFiles []string, decrypters []keyDecrypter) (*multiKeyLoader, error) {
	dm := make(map[string]keyDecrypter)
	for _, decrypter := range decrypters {
		dm[decrypter.extension()] = decrypter
	}
	for _, keyFile := range keyFiles {
		ext := filepath.Ext(keyFile)
		if _, supported := dm[ext]; !supported {
			return nil, fmt.Errorf("unsupported key extension: %v", ext)
		}
	}
	return &multiKeyLoader{
		keyFiles:      keyFiles,
		decrypters:    dm,
		loadedSecrets: make([]*bls_interface.BlsSecretKey, 0, len(keyFiles)),
	}, nil
}

func (loader *multiKeyLoader) loadKeys() (multibls.PrivateKeys, error) {
	for _, keyFile := range loader.keyFiles {
		decrypter := loader.decrypters[filepath.Ext(keyFile)]
		secret, err := decrypter.decryptFile(keyFile)
		if err != nil {
			return multibls.PrivateKeys{}, err
		}
		loader.loadedSecrets = append(loader.loadedSecrets, secret)
	}
	return multibls.GetPrivateKeys(loader.loadedSecrets...), nil
}

type blsDirLoader struct {
	keyDir     string
	decrypters map[string]keyDecrypter

	loadedSecrets []*bls_interface.BlsSecretKey
}

func newBlsDirLoader(keyDir string, decrypters []keyDecrypter) (*blsDirLoader, error) {
	dm := make(map[string]keyDecrypter)
	for _, decrypter := range decrypters {
		dm[decrypter.extension()] = decrypter
	}
	if err := checkIsDir(keyDir); err != nil {
		return nil, err
	}
	return &blsDirLoader{
		keyDir:     keyDir,
		decrypters: dm,
	}, nil
}

func (loader *blsDirLoader) loadKeys() (multibls.PrivateKeys, error) {
	filepath.Walk(loader.keyDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		decrypter, exist := loader.decrypters[filepath.Ext(path)]
		if !exist {
			return nil
		}
		secret, err := decrypter.decryptFile(path)
		if err != nil {
			return err
		}
		loader.loadedSecrets = append(loader.loadedSecrets, secret)
		return nil
	})
	return multibls.GetPrivateKeys(loader.loadedSecrets...), nil
}
