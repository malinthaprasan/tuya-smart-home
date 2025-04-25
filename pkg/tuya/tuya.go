package tuya

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

var (
	Host           string
	Token          string
	ExpireTime     int64
	ClientId       string
	Secret         string
	ExpireTimeDiff int64 = 60
)

type DeviceStatus struct {
	Result []struct {
		Code  string      `json:"code"`
		Value interface{} `json:"value"`
	} `json:"result"`
	Success bool   `json:"success"`
	T       int64  `json:"t"`
	Tid     string `json:"tid"`
}

type TokenResponse struct {
	Result struct {
		AccessToken  string `json:"access_token"`
		ExpireTime   int    `json:"expire_time"`
		RefreshToken string `json:"refresh_token"`
		UID          string `json:"uid"`
	} `json:"result"`
	Success bool  `json:"success"`
	T       int64 `json:"t"`
}

type Command struct {
	Code  string      `json:"code"`
	Value interface{} `json:"value"`
}
type CommandRequest struct {
	Commands []Command `json:"commands"`
}

type CommandResponse struct {
	Result  bool   `json:"result"`
	Success bool   `json:"success"`
	T       int64  `json:"t"`
	Tid     string `json:"tid"`
}

func Init(host string, clientId string, clientSecret string) {
	Host = host
	ClientId = clientId
	Secret = clientSecret
	getToken()
}

func getToken() error {
	if Token == "" || ExpireTime-time.Now().Unix() < ExpireTimeDiff {
		method := "GET"
		body := []byte(``)
		req, _ := http.NewRequest(method, Host+"/v1.0/token?grant_type=1", bytes.NewReader(body))

		buildHeader(req, body)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to execute token request: %w", err)
		}
		defer resp.Body.Close()
		bs, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read token response: %w", err)
		}
		ret := TokenResponse{}
		json.Unmarshal(bs, &ret)

		if v := ret.Result.AccessToken; v != "" {
			Token = v
			ExpireTime = time.Now().Unix() + int64(ret.Result.ExpireTime)
		}
	}
	return nil
}

func GetDevice(deviceId string) error {
	getToken()
	method := "GET"
	body := []byte(``)
	req, _ := http.NewRequest(method, Host+"/v1.0/devices/"+deviceId, bytes.NewReader(body))

	buildHeader(req, body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get device: %w", err)
	}
	defer resp.Body.Close()
	bs, _ := io.ReadAll(resp.Body)
	log.Println("resp:", string(bs))
	return nil
}

func GetDeviceStatus(deviceId string) (DeviceStatus, error) {
	getToken()
	method := "GET"
	body := []byte(``)
	req, _ := http.NewRequest(method, Host+"/v1.0/devices/"+deviceId+"/status", bytes.NewReader(body))

	buildHeader(req, body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return DeviceStatus{}, fmt.Errorf("failed to get device status: %w", err)
	}
	defer resp.Body.Close()
	bs, _ := io.ReadAll(resp.Body)
	ret := DeviceStatus{}
	json.Unmarshal(bs, &ret)
	return ret, nil
}

func ChangeStatusOfDevice(deviceId string, code string, value bool) (CommandResponse, error) {
	getToken()
	method := "POST"
	body, _ := json.Marshal(CommandRequest{
		Commands: []Command{
			{
				Code:  code,
				Value: value,
			},
		},
	})
	req, _ := http.NewRequest(method, Host+"/v1.0/devices/"+deviceId+"/commands", bytes.NewReader(body))

	buildHeader(req, body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return CommandResponse{}, fmt.Errorf("failed to change status of device: %w", err)
	}
	defer resp.Body.Close()
	bs, _ := io.ReadAll(resp.Body)
	ret := CommandResponse{}
	json.Unmarshal(bs, &ret)
	return ret, nil
}

func buildHeader(req *http.Request, body []byte) {
	req.Header.Set("client_id", ClientId)
	req.Header.Set("sign_method", "HMAC-SHA256")

	ts := fmt.Sprint(time.Now().UnixNano() / 1e6)
	req.Header.Set("t", ts)

	if Token != "" {
		req.Header.Set("access_token", Token)
	}

	sign := buildSign(req, body, ts)
	req.Header.Set("sign", sign)
}

func buildSign(req *http.Request, body []byte, t string) string {
	headers := getHeaderStr(req)
	urlStr := getUrlStr(req)
	contentSha256 := Sha256(body)
	stringToSign := req.Method + "\n" + contentSha256 + "\n" + headers + "\n" + urlStr
	signStr := ClientId + Token + t + stringToSign
	sign := strings.ToUpper(HmacSha256(signStr, Secret))
	return sign
}

func Sha256(data []byte) string {
	sha256Contain := sha256.New()
	sha256Contain.Write(data)
	return hex.EncodeToString(sha256Contain.Sum(nil))
}

func getUrlStr(req *http.Request) string {
	url := req.URL.Path
	keys := make([]string, 0, 10)

	query := req.URL.Query()
	for key, _ := range query {
		keys = append(keys, key)
	}
	if len(keys) > 0 {
		url += "?"
		sort.Strings(keys)
		for _, keyName := range keys {
			value := query.Get(keyName)
			url += keyName + "=" + value + "&"
		}
	}

	if url[len(url)-1] == '&' {
		url = url[:len(url)-1]
	}
	return url
}

func getHeaderStr(req *http.Request) string {
	signHeaderKeys := req.Header.Get("Signature-Headers")
	if signHeaderKeys == "" {
		return ""
	}
	keys := strings.Split(signHeaderKeys, ":")
	headers := ""
	for _, key := range keys {
		headers += key + ":" + req.Header.Get(key) + "\n"
	}
	return headers
}

func HmacSha256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}
