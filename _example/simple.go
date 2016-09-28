package main

import (
	"fmt"
	"log"

	apns "github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
)

func main() {

	cert, pemErr := certificate.FromP12File("../cert.p12", "")
	if pemErr != nil {
		log.Println("Cert Error:", pemErr)
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

	client := apns.NewClient(cert).Production()
	res, err := client.Push(notification)

	if err != nil {
		log.Fatal("Error: ", err)
	} else {
		fmt.Printf("%v %v %v\n", res.StatusCode, res.ApnsID, res.Reason)
	}
}
