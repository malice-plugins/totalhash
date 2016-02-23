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

// TotalHashAnalysis object
type TotalHashAnalysis struct {
	Found            bool
	XMLName          xml.Name         `xml:"analysis"`
	Version          string           `xml:"version,attr"`
	SHA1             string           `xml:"sha1,attr"`
	MD5              string           `xml:"md5,attr"`
	Time             string           `xml:"time,attr"`
	Static           static           `xml:"static"`
	Calltree         calltree         `xml:"calltree"`
	Processes        processes        `xml:"processes"`
	RunningProcesses runningProcesses `xml:"running_processes"`
	NetworkPcap      networkPcap      `xml:"network_pcap"`
}
type static struct {
	StringsSHA1 string    `xml:"strings_sha1,attr"`
	StringsMD5  string    `xml:"strings_md5,attr"`
	Magic       magic     `xml:"magic"`
	Sections    []section `xml:"section"`
	Imports     imports   `xml:"imports"`
	PEHash      pehash    `xml:"pehash"`
	Imphash     imphash   `xml:"imphash"`
	Timestamp   timestamp `xml:"timestamp"`
	Packer      packer    `xml:"packer"`
	AVs         []av      `xml:"av"`
}
type imports struct {
	Dll string `xml:"dll,attr"`
}
type pehash struct {
	Value string `xml:"value,attr"`
}
type imphash struct {
	Value string `xml:"value,attr"`
}
type timestamp struct {
	Value string `xml:"value,attr"`
}
type packer struct {
	Value string `xml:"value,attr"`
}
type magic struct {
	Value string `xml:"value,attr"`
}
type section struct {
	Name string `xml:"name,attr"`
	MD5  string `xml:"md5,attr"`
	SHA1 string `xml:"sha1,attr"`
	Size string `xml:"size,attr"`
}
type av struct {
	Scanner   string `xml:"scanner,attr"`
	Timestamp string `xml:"timestamp,attr"`
	AVProduct string `xml:"av_product,attr"`
	Version   string `xml:"version,attr"`
	Update    string `xml:"update,attr"`
	Info      string `xml:"info,attr"`
	Signature string `xml:"signature,attr"`
}
type calltree struct {
	ProcessCall processCall `xml:"process_call"`
}
type processCall struct {
	Index       string `xml:"index,attr"`
	Filename    string `xml:"filename,attr"`
	Pid         string `xml:"pid,attr"`
	StartReason string `xml:"startreason,attr"`
}
type processes struct {
	ScrShotSHA1 string  `xml:"scr_shot_sha1,attr"`
	ScrShotMD5  string  `xml:"scr_shot_md5,attr"`
	Process     process `xml:"process"`
}
type process struct {
	Index              string             `xml:"index,attr"`
	Pid                string             `xml:"pid,attr"`
	Filename           string             `xml:"filename,attr"`
	Executionstatus    string             `xml:"executionstatus,attr"`
	DllHandlingSection dllHandlingSection `xml:"dll_handling_section"`
}
type dllHandlingSection struct {
	LoadDlls []loadDll `xml:"load_dll"`
}
type loadDll struct {
	Filename string `xml:"filename,attr"`
}
type runningProcesses struct {
	RunningProcess []runningProcess `xml:"running_process"`
}
type runningProcess struct {
	Pid      string `xml:"pid,attr"`
	Filename string `xml:"filename,attr"`
	PPid     string `xml:"ppid,attr"`
}
type networkPcap struct {
	SHA1 string `xml:"sha1,attr"`
	MD5  string `xml:"md5,attr"`
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

// http://api.totalhash.com/analysis/<sha1>&id=<userid>&sign=<sign>
func getAnalysis(sha1 string, userid string, sign string) TotalHashAnalysis {
	fmt.Println("http://api.totalhash.com/analysis/" + sha1 + "&id=" + userid + "&sign=" + sign)
	tha := TotalHashAnalysis{}

	ro := &grequests.RequestOptions{
		InsecureSkipVerify: true,
	}
	resp, err := grequests.Get("http://api.totalhash.com/analysis/"+sha1+"&id="+userid+"&sign="+sign, ro)

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.StatusCode == 404 {
		tha.Found = false
		return tha
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	// fmt.Println(resp.String())

	err = xml.Unmarshal(resp.Bytes(), &tha)
	assert(err)

	tha.Found = true

	return tha
}

func getUsage(userid string, key string) {
	sign := getHmac256Signature("usage", key)

	ro := &grequests.RequestOptions{InsecureSkipVerify: true}
	resp, err := grequests.Get("https://api.totalhash.com/usage/id="+userid+"&sign="+sign, ro)

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
