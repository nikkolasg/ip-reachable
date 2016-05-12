package ipreach

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type Checker interface {
	CheckTCP(ip string) error
}

type HostCheckNet struct {
}

const HOST_CHECK_NET = "https://check-host.net/"
const WHATS_MY_IP = "http://www.whatsmyip.org/"

var ErrUnreachable = errors.New("Unreachable IP:PORT by the service")
var ErrUnknownResponse = errors.New("Unable to make sense of the response from the service")

// WhatsMyIp will only be able to check for your own IP address
type WhatsMyIp struct{}

func (w *WhatsMyIp) CheckTCP(ip string) error {
	_, port, err := net.SplitHostPort(ip)
	if err != nil {
		return err
	}
	values := url.Values{}
	values.Set("port", port)
	values.Set("timeout", "default")

	// ask the check
	url := WHATS_MY_IP + "port-scanner/scan.php"
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Host", "www.whatsmyip.org")
	req.Header.Set("Referer", "http://www.whatsmyip.org/port-scanner/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	client := &http.Client{}
	fmt.Println("Created request for ", ip)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	buffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	requestBuff := &bytes.Buffer{}
	err = req.Write(requestBuff)
	fmt.Println(requestBuff, err)
	fmt.Println("Response:", string(buffer))
	if !bytes.Contains(buffer, []byte("1")) {
		return ErrUnreachable
	}
	return nil
}

// CheckTCP will check if the given IP address is reachable from the internet
// for TCP connection using https://check-host.net/
func (h *HostCheckNet) CheckTCP(ip string) error {
	// ask the check
	url := HOST_CHECK_NET + "check-tcp?host=" + ip + "&max_nodes=1"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	fmt.Println("Created request for ", ip)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	fmt.Println("Requested for", ip, " sent to checker.")

	// get the request id and ask for the results
	buffResponse, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response: ", string(buffResponse))
	reader := bytes.NewBuffer(buffResponse)
	dec := json.NewDecoder(reader)
	checkResp := &checkResponse{}
	if err := dec.Decode(checkResp); err != nil {
		return err
	}
	resp.Body.Close()

	fmt.Println("Decoded PermanentLink", checkResp.PermanentLink)
	req, err = http.NewRequest("GET", checkResp.PermanentLink, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// get the response
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	fmt.Println("Got response from the check")
	buff, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if strings.Contains(string(buff), "error") {
		return ErrUnreachable
	}
	return nil
}

type checkResponse struct {
	Ok            int    `json:"ok"`
	PermanentLink string `json:"permanent_link"`
	RequestId     string `json:"request_id"`
}
