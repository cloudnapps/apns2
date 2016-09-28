package main

import (
	"fmt"
	"log"

	apns "github.com/sideshow/apns2"
	"github.com/sideshow/apns2/token"
)

func main() {

	authKey, err := token.AuthKeyFromFile("../APNSAuthKey_T64N7W47U9.p8")
	if err != nil {
		log.Fatal("token error:", err)
	}

	token := &token.Token{
		AuthKey: authKey,
		KeyID:   "T64N7W47U9",
		TeamID:  "264H7447N5",
	}

	notification := &apns.Notification{}
	notification.DeviceToken = "cb7262544176c3f15efdcdcf9dd03418dfca82ba710c54ab6b1352350d442cb4"
	notification.Topic = "com.Apns2"
	notification.Payload = []byte(`{
			"aps" : {
				"alert" : "Hello!"
			}
		}
	`)

	client := apns.NewTokenClient(token)
	res, err := client.Push(notification)

	if err != nil {
		log.Fatal("error: ", err)
	} else {
		fmt.Printf("%v %v %v\n", res.StatusCode, res.ApnsID, res.Reason)
	}
}
