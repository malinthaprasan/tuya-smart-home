package tuyaapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"tuya-home/pkg/tuya"
	"tuya-home/pkg/tuyautil"

	"github.com/gorilla/mux"
)

var (
	Host     = "https://openapi.tuyaeu.com"
	ClientID string
	Secret   string
	DeviceID string
)

func init() {
	ClientID = os.Getenv("TUYA_CLIENT_ID")
	Secret = os.Getenv("TUYA_SECRET")
	DeviceID = os.Getenv("TUYA_DEVICE_ID")
}

// SwitchState represents the current state and metrics of a socket
type SwitchState struct {
	Switch  bool    `json:"switch"`
	Current float64 `json:"current"`
	Power   float64 `json:"power"`
	Voltage float64 `json:"voltage"`
}

// ChangeSwitchStateResponse represents the response for switch state change
type ChangeSwitchStateResponse struct {
	Success bool `json:"success"`
}

func Start() {
	tuya.Init(Host, ClientID, Secret)

	r := mux.NewRouter()

	// Register routes
	r.HandleFunc("/home/{homeId}/sockets/{socketId}/status", getSocketStatus).Methods("GET")
	r.HandleFunc("/home/{homeId}/sockets/{socketId}/change-status", changeSocketStatus).Methods("POST")

	fmt.Println("Successfully started the server")
	fmt.Println(`
Sample curls:
  get status: 
    curl -X GET localhost:8080/home/new-home/sockets/exhaust-fan/status
  change status: 
    curl -X POST localhost:8080/home/new-home/sockets/exhaust-fan/change-status?switch=on
    curl -X POST localhost:8080/home/new-home/sockets/exhaust-fan/change-status?switch=off`)

	http.ListenAndServe(":8080", r)
}

func getSocketStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	homeId := vars["homeId"]
	socketId := vars["socketId"]

	// Validate homeId and socketId
	if homeId != "new-home" || socketId != "exhaust-fan" {
		http.Error(w, "Invalid homeId or socketId", http.StatusBadRequest)
		return
	}

	deviceId := tuyautil.Lookup(socketId)
	status, err := tuya.GetDeviceStatus(deviceId)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		http.Error(w, "Failed to get device status", http.StatusInternalServerError)
	}
	var switchStatus bool
	var current float64
	var power float64
	var voltage float64
	for _, result := range status.Result {
		if result.Code == "switch_1" {
			switchStatus = result.Value.(bool)
			continue
		}
		if result.Code == "cur_current" {
			current = result.Value.(float64)
			continue
		}
		if result.Code == "cur_power" {
			power = result.Value.(float64)
			break
		}
		if result.Code == "cur_voltage" {
			voltage = result.Value.(float64)
			break
		}
	}

	// Mock response - in real implementation, you would get actual values
	state := SwitchState{
		Switch:  switchStatus,
		Current: current,
		Power:   power,
		Voltage: voltage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state)
}

func changeSocketStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	homeId := vars["homeId"]
	socketId := vars["socketId"]
	switchState := r.URL.Query().Get("switch")
	deviceId := tuyautil.Lookup(socketId)

	// Validate parameters
	if homeId != "new-home" || socketId != "exhaust-fan" {
		http.Error(w, "Invalid homeId or socketId", http.StatusBadRequest)
		return
	}

	if switchState != "on" && switchState != "off" {
		http.Error(w, "Invalid switch state", http.StatusBadRequest)
		return
	}

	value := false
	if switchState == "on" {
		value = true
	}
	response, _ := tuya.ChangeStatusOfDevice(deviceId, "switch_1", value)

	// Mock response - in real implementation, you would actually change the device state
	ret := ChangeSwitchStateResponse{
		Success: response.Success,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ret)
}
