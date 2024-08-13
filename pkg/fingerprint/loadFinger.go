package fingerprint

import (
	"encoding/json"
)

type Packjson struct {
	Fingerprint []Fingerprint
}

type PackjsonSubdomain struct {
	Fingerprint []FingerprintRecord
}

type Fingerprint struct {
	Cms      string
	Method   string
	Location string
	Keyword  []string
}

type FingerprintRecord struct {
	Cname       []string
	Discussion  string
	Fingerprint string
	Service     string
	Status      string
}

var (
	Webfingerprint       *Packjson
	Subdomainfingerprint *PackjsonSubdomain
)

func LoadWebfingerprintEhole() error {
	var config Packjson
	err := json.Unmarshal([]byte(eHoleFinger), &config)
	if err != nil {
		return err
	}
	Webfingerprint = &config
	return nil
}

func LoadWebfingerprintLocal() error {
	var config Packjson
	err := json.Unmarshal([]byte(localFinger), &config)
	if err != nil {
		return err
	}
	Webfingerprint = &config
	return nil
}

func LoadSubdomainfingerprint() error {
	var config PackjsonSubdomain
	err := json.Unmarshal([]byte(subdomainFinger), &config)
	if err != nil {
		return err
	}
	Subdomainfingerprint = &config
	return nil
}

func GetWebfingerprintLocal() *Packjson {
	return Webfingerprint
}

func GetWebfingerprintEhole() *Packjson {
	return Webfingerprint
}

func GetWebfingerprintSubdomain() *PackjsonSubdomain {
	return Subdomainfingerprint
}
