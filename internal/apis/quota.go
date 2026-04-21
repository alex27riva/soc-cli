/*
Copyright © 2026 Alessandro Riva

Licensed under the MIT License.
See the LICENSE file for details.
*/
package apis

import (
	"fmt"
	"log"

	vt "github.com/VirusTotal/vt-go"
	"resty.dev/v3"
)

type VirusTotalQuota struct {
	Daily   QuotaInfo
	Hourly  QuotaInfo
	Monthly QuotaInfo
}

type QuotaInfo struct {
	User   QuotaValues
	Group  QuotaValues
}

type QuotaValues struct {
	Allowed int
	Used    int
}

type AbuseIPDBQuotaResponse struct {
	HourlyLimit     int
	HourlyRemaining int
	DailyLimit      int
	DailyRemaining  int
}

type UrlscanQuotaResponse struct {
	Limits struct {
		Search struct {
			Day struct {
				Limit     int `json:"limit"`
				Remaining int `json:"remaining"`
				Used      int `json:"used"`
			} `json:"day"`
			Hour struct {
				Limit     int `json:"limit"`
				Remaining int `json:"remaining"`
				Used      int `json:"used"`
			} `json:"hour"`
		} `json:"search"`
		Retrieve struct {
			Day struct {
				Limit     int `json:"limit"`
				Remaining int `json:"remaining"`
				Used      int `json:"used"`
			} `json:"day"`
			Hour struct {
				Limit     int `json:"limit"`
				Remaining int `json:"remaining"`
				Used      int `json:"used"`
			} `json:"hour"`
		} `json:"retrieve"`
		Public struct {
			Day struct {
				Limit     int `json:"limit"`
				Remaining int `json:"remaining"`
				Used      int `json:"used"`
			} `json:"day"`
		} `json:"public"`
		Private struct {
			Day struct {
				Limit     int `json:"limit"`
				Remaining int `json:"remaining"`
				Used      int `json:"used"`
			} `json:"day"`
			Hour struct {
				Limit     int `json:"limit"`
				Remaining int `json:"remaining"`
				Used      int `json:"used"`
			} `json:"hour"`
		} `json:"private"`
	} `json:"limits"`
}

func GetUrlscanQuota(apiKey string) (*UrlscanQuotaResponse, error) {
	client := resty.New()
	defer client.Close()

	client.SetBaseURL("https://urlscan.io")

	headers := map[string]string{
		"Content-Type": "application/json",
		"API-Key":    apiKey,
	}

	result := &UrlscanQuotaResponse{}

	_, err := client.R().
		SetHeaders(headers).
		SetResult(result).
		Get("/user/quotas/")
	if err != nil {
		return nil, err
	}

	return result, nil
}

func GetAbuseIPDBQuota(apiKey string) *AbuseIPDBQuotaResponse {
	client := resty.New()
	defer client.Close()

	client.SetBaseURL(abuseIPBaseURL)

	headers := map[string]string{
		"Key":    apiKey,
		"Accept": "application/json",
	}

	resp, err := client.R().
		SetHeaders(headers).
		Get("/check")
	if err != nil {
		log.Fatalf("Error fetching AbuseIPDB quota: %v", err)
	}

	result := &AbuseIPDBQuotaResponse{}

	if limit := resp.Header().Get("X-RateLimit-Limit"); limit != "" {
		fmt.Sscanf(limit, "%d", &result.DailyLimit)
	}
	if remaining := resp.Header().Get("X-RateLimit-Remaining"); remaining != "" {
		fmt.Sscanf(remaining, "%d", &result.DailyRemaining)
	}

	return result
}

func GetVirusTotalQuota(apiKey string) (*VirusTotalQuota, error) {
	client := vt.NewClient(apiKey)

	obj, err := client.GetObject(vt.URL("users/me/overall_quotas"))
	if err != nil {
		return nil, err
	}

	result := &VirusTotalQuota{}

	parseQuota(obj, "api_requests_daily", &result.Daily)
	parseQuota(obj, "api_requests_hourly", &result.Hourly)
	parseQuota(obj, "api_requests_monthly", &result.Monthly)

	return result, nil
}

func parseQuota(obj *vt.Object, key string, info *QuotaInfo) {
	getInt := func(path string) int {
		val, _ := obj.Get(path)
		if m, ok := val.(map[string]interface{}); ok {
			if v, ok := m["allowed"].(float64); ok {
				return int(v)
			}
		}
		if v, ok := val.(float64); ok {
			return int(v)
		}
		return 0
	}

	getUsed := func(path string) int {
		val, _ := obj.Get(path)
		if m, ok := val.(map[string]interface{}); ok {
			if v, ok := m["used"].(float64); ok {
				return int(v)
			}
		}
		return 0
	}

	userVal, _ := obj.Get(key + ".user")
	if m, ok := userVal.(map[string]interface{}); ok {
		if v, ok := m["allowed"].(float64); ok {
			info.User.Allowed = int(v)
		}
		if v, ok := m["used"].(float64); ok {
			info.User.Used = int(v)
		}
	}

	groupVal, _ := obj.Get(key + ".group")
	if m, ok := groupVal.(map[string]interface{}); ok {
		if v, ok := m["allowed"].(float64); ok {
			info.Group.Allowed = int(v)
		}
		if v, ok := m["used"].(float64); ok {
			info.Group.Used = int(v)
		}
	}

	_ = getInt
	_ = getUsed
}