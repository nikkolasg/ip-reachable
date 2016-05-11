package ipreach

import "fmt"

func TestHostCheckNet() {
	checker := HostCheckNet{}

	valid_ip := "128.30.52.45:80" // w3.org
	if err := checker.CheckTCP(valid_ip); err != nil {
		fmt.Println("Should be valid")
	}

	invalid_ip := "128.30.52.45:678"
	if err := checker.CheckTCP(invalid_ip); err == nil {
		fmt.Println("Should be invalid")
	}
}

func TestWhatsMyIP() {
	checker := WhatsMyIp{}
	if err := checker.CheckTCP("127.0.0.1:3100"); err == nil {
		fmt.Println("Should not work if port not open")
	}
	if err := checker.CheckTCP("127.0.0.1:3000"); err == nil {
		fmt.Println("Should not work if port not open")
	}
}

func main() {
	TestWhatsMyIP()
}