package nessus

import (
	"os"
	"net/http"
	"encoding/json"
	"bytes"
	"log"
	"github.com/buger/jsonparser"
	"crypto/tls"
	"io/ioutil"
	"text/template"
	"fmt"
	"regexp"
)


type Nessus struct {
	Username string
	Password string
	Url string
	Token string
	ApiKey string
	HttpClient *http.Client

}

type config struct {
	Name string
	Targets string
}

func (n *Nessus) EnvCredentials() {
	n.Username = os.Getenv("NESSUS_USERNAME")
	n.Password = os.Getenv("NESSUS_PASSWORD")
}

func (n *Nessus) Credentials(username string, password string) {
	n.Username = username
	n.Password = password
}

func NewNessus(url string) Nessus {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	nessus := Nessus{
		Username: "",
		Password: "",
		Url: url,
		Token: "",
		ApiKey: "",
		HttpClient: client,
	}

	nessus.GetApiKey()
	return nessus
}


func (n *Nessus) GetApiKey() {
	resp, err := n.HttpClient.Get(n.Url + "/nessus6.js")
	regex := regexp.MustCompile(`(?m)[0-9A-F]{8}\-[0-9A-F]{4}\-4[0-9A-F]{3}\-[89AB][0-9A-F]{3}\-[0-9A-F]{12}`)

	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Fatal(err)
	}

	apiKey := regex.FindString(string(body))

	n.ApiKey = apiKey
}


func (n *Nessus) Authenticate() {
	values := map[string]string{
		"username": n.Username,
		"password": n.Password,
	}

	jsonValues, _ := json.Marshal(values)

	resp, err := n.HttpClient.Post(n.Url + "/session", "application/json", bytes.NewBuffer(jsonValues))

	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Fatal(err)
	}

	token, err := jsonparser.GetString(body, "token")

	if err != nil {
		log.Fatal("Authention Failure")
	}

	n.Token = token
}

func (n *Nessus) LaunchScan(name string, targets string) {
	config := config{
		Name: name,
		Targets: targets,
	}

	t, err := template.New("scan").Parse(BasicTemplate)
	if err != nil {
		log.Fatal(err)
	}

	var tpl bytes.Buffer

	if err := t.Execute(&tpl, config); err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest("POST", n.Url + "/scans", bytes.NewReader(tpl.Bytes()))

	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("X-Cookie", "token=" + n.Token)
	req.Header.Set("X-API-Token", n.ApiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err  := n.HttpClient.Do(req)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Response Status: ", resp.Status)
}
