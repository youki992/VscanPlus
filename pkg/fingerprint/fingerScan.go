package fingerprint

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

var EholeFinpx *Packjson
var LocalFinpx *Packjson
var SubdomainFinpx *PackjsonSubdomain

func New() error {
	err := LoadWebfingerprintEhole()
	if err != nil {
		return err
	}
	EholeFinpx = GetWebfingerprintEhole()

	err = LoadWebfingerprintLocal()
	if err != nil {
		return err
	}
	LocalFinpx = GetWebfingerprintLocal()
	return nil

	err = LoadSubdomainfingerprint()
	if err != nil {
		return err
	}
	SubdomainFinpx = GetWebfingerprintSubdomain()
	return nil
}

func mapToJson(param map[string][]string) string {
	dataType, _ := json.Marshal(param)
	dataString := string(dataType)
	return dataString
}

// 提取URL中的域名
func extractDomain(url string) string {
	re := regexp.MustCompile(`(?i)^(?:https?://)?([^/]+)`)
	matches := re.FindStringSubmatch(url)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// 记录匹配的域名到文件
func logMatchedDomain(domain string) {
	file, err := os.OpenFile("matched_domains.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(domain + "\n"); err != nil {
		fmt.Println("Error writing to file:", err)
	}
}

// 执行DNS查询并返回CNAME记录值
func dnsCNAME(domain string) (string, error) {
	resolver := new(net.Resolver)
	answers, err := resolver.LookupCNAME(nil, domain)
	if err != nil {
		return "", err
	}
	return answers, nil
}

func FingerScan(headers map[string][]string, body []byte, title string, url string) []string {
	bodyString := string(body)
	headersjson := mapToJson(headers)
	favhash := getfavicon(bodyString, url)
	var cms []string
	for _, finp := range EholeFinpx.Fingerprint {
		if finp.Location == "body" {
			if finp.Method == "keyword" {
				if iskeyword(bodyString, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
				// 记录匹配的域名
				domain := extractDomain(url)
				recordValue, err := dnsCNAME(domain)
				if err == nil {
					for _, dinp := range SubdomainFinpx.Fingerprint {
						for _, cname := range dinp.Cname {
							fmt.Println(dinp.Fingerprint)
							if strings.Contains(recordValue, cname) && strings.Contains(bodyString, dinp.Fingerprint) {
								// 如果DNS记录值中包含Cname中的关键词，记录域名
								logMatchedDomain(domain + " / " + dinp.Service + " " + dinp.Discussion)
							}
						}
					}
				}
			}
			if finp.Method == "faviconhash" {
				if favhash == finp.Keyword[0] {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(bodyString, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
		if finp.Location == "header" {
			if finp.Method == "keyword" {
				if iskeyword(headersjson, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(headersjson, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
		if finp.Location == "title" {
			if finp.Method == "keyword" {
				if iskeyword(title, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(title, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
	}
	for _, finp := range LocalFinpx.Fingerprint {
		if finp.Location == "body" {
			if finp.Method == "keyword" {
				if iskeyword(bodyString, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "faviconhash" {
				if favhash == finp.Keyword[0] {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(bodyString, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
		if finp.Location == "header" {
			if finp.Method == "keyword" {
				if iskeyword(headersjson, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(headersjson, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
		if finp.Location == "title" {
			if finp.Method == "keyword" {
				if iskeyword(title, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(title, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
	}
	return cms
}
