package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/codegangsta/cli"
	"github.com/levigross/grequests"
	"github.com/parnurzeal/gorequest"
)

// Version stores the plugin's version
var Version string

// BuildTime stores the plugin's build time
var BuildTime string

type TotalHashAnalysis struct {
	Where string `xml:"where,attr"`
	Addr  string
}
type Address struct {
	City, State string
}
type Result struct {
	XMLName xml.Name `xml:"Person"`
	Name    string   `xml:"FullName"`
	Phone   string
	Groups  []string `xml:"Group>Value"`
	Address
}

func getopt(name, dfault string) string {
	value := os.Getenv(name)
	if value == "" {
		value = dfault
	}
	return value
}

func assert(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func doSearch(query string, userid string, sign string) {
	ro := &grequests.RequestOptions{
		InsecureSkipVerify: true,
		Params: map[string]string{
			"id":   userid,
			"sign": sign,
		},
	}
	resp, err := grequests.Get("https://api.totalhash.com/usage/", ro)

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	fmt.Println(resp.String())
}

func getAnalysis(sha1 string, userid string, sign string) TotalHashAnalysis {
	ro := &grequests.RequestOptions{
		InsecureSkipVerify: true,
		Params: map[string]string{
			"id":   userid,
			"sign": sign,
		},
	}
	resp, err := grequests.Get("http://api.totalhash.com/analysis/"+sha1, ro)

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	fmt.Println(resp.String())
	tha := TotalHashAnalysis{}
	return tha
}

func getUsage(userid string, sign string) {
	ro := &grequests.RequestOptions{
		InsecureSkipVerify: true,
		Params: map[string]string{
			"id":  userid,
			"sig": sign,
		},
	}
	resp, err := grequests.Get("https://api.totalhash.com/usage/", ro)

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	fmt.Println(resp.String())
}

func uploadSample(path string, userid string, sign string) {
	fd, err := grequests.FileUploadFromDisk(path)

	if err != nil {
		log.Println("Unable to open file: ", err)
	}

	// This will upload the file as a multipart mime request
	resp, err := grequests.Post("https://api.totalhash.com/upload/",
		&grequests.RequestOptions{
			InsecureSkipVerify: true,
			Files:              fd,
			Params: map[string]string{
				"id":  userid,
				"sig": sign,
			},
		})

	if err != nil {
		log.Println("Unable to make request", resp.Error)
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	fmt.Println(resp.String())
}

func getHmac256Signature(message string, secret string) string {
	key := []byte(secret)
	sig := hmac.New(sha256.New, key)
	sig.Write([]byte(message))
	return hex.EncodeToString(sig.Sum(nil))
}

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(resp.Status)
}

func printMarkDownTable(tha TotalHashAnalysis) {
	fmt.Println("#### totalhash")
}

var appHelpTemplate = `Usage: {{.Name}} {{if .Flags}}[OPTIONS] {{end}}COMMAND [arg...]

{{.Usage}}

Version: {{.Version}}{{if or .Author .Email}}

Author:{{if .Author}}
  {{.Author}}{{if .Email}} - <{{.Email}}>{{end}}{{else}}
  {{.Email}}{{end}}{{end}}
{{if .Flags}}
Options:
  {{range .Flags}}{{.}}
  {{end}}{{end}}
Commands:
  {{range .Commands}}{{.Name}}{{with .ShortName}}, {{.}}{{end}}{{ "\t" }}{{.Usage}}
  {{end}}
Run '{{.Name}} COMMAND --help' for more information on a command.
`

func main() {
	cli.AppHelpTemplate = appHelpTemplate
	app := cli.NewApp()
	app.Name = "totalhash"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice totalhash Plugin"
	var thuser string
	var thkey string
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:   "post, p",
			Usage:  "POST results to Malice webhook",
			EnvVar: "MALICE_ENDPOINT",
		},
		cli.BoolFlag{
			Name:   "proxy, x",
			Usage:  "proxy settings for Malice webhook endpoint",
			EnvVar: "MALICE_PROXY",
		},
		cli.BoolFlag{
			Name:  "table, t",
			Usage: "output as Markdown table",
		},
		cli.StringFlag{
			Name:        "user",
			Value:       "",
			Usage:       "totalhash user",
			EnvVar:      "MALICE_TH_USER",
			Destination: &thuser,
		},
		cli.StringFlag{
			Name:        "key",
			Value:       "",
			Usage:       "totalhash key",
			EnvVar:      "MALICE_TH_KEY",
			Destination: &thkey,
		},
	}
	app.ArgsUsage = "SHA1 hash of file"
	app.Action = func(c *cli.Context) {
		if c.Args().Present() {
			sign := getHmac256Signature(c.Args().First(), thkey)
			thashReport := getAnalysis(c.Args().First(), thuser, sign)

			if c.Bool("table") {
				printMarkDownTable(thashReport)
			} else {
				thashJSON, err := json.Marshal(thashReport)
				assert(err)
				fmt.Println(string(thashJSON))
			}
		} else {
			cli.ShowAppHelp(c)
		}
	}

	err := app.Run(os.Args)
	assert(err)
}
