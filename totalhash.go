package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fatih/structs"

	"github.com/levigross/grequests"
	"github.com/maliceio/go-plugin-utils/utils"
	"github.com/maliceio/malice/malice/database/elasticsearch"
	"github.com/parnurzeal/gorequest"
	"github.com/urfave/cli"
)

// Version stores the plugin's version
var Version string

// BuildTime stores the plugin's build time
var BuildTime string

const (
	name     = "totalhash"
	category = "intel"
)

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
	Imports     []imports `xml:"imports"`
	PEHash      pehash    `xml:"pehash"`
	Imphash     imphash   `xml:"imphash"`
	Pdb         pdb       `xml:"pdb"`
	Version     version   `xml:"version"`
	Language    language  `xml:"language"`
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
type pdb struct {
	Value string `xml:"value,attr"`
}
type version struct {
	Value string `xml:"value,attr"`
}
type language struct {
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
	ProcessCall []processCall `xml:"process_call"`
}
type processCall struct {
	Index       string `xml:"index,attr"`
	Filename    string `xml:"filename,attr"`
	Pid         string `xml:"pid,attr"`
	StartReason string `xml:"startreason,attr"`
}
type processes struct {
	ScrShotSHA1 string    `xml:"scr_shot_sha1,attr"`
	ScrShotMD5  string    `xml:"scr_shot_md5,attr"`
	Process     []process `xml:"process"`
}
type process struct {
	Index              string             `xml:"index,attr"`
	Pid                string             `xml:"pid,attr"`
	Filename           string             `xml:"filename,attr"`
	Executionstatus    string             `xml:"executionstatus,attr"`
	RegistrySection    registrySection    `xml:"registry_section"`
	MutexSection       mutexSection       `xml:"mutex_section"`
	DllHandlingSection dllHandlingSection `xml:"dll_handling_section"`
	FilesystemSection  filesystemSection  `xml:"filesystem_section"`
	// system_info_section  system_info_section  `xml:"system_info_section"`
	// service_section  service_section  `xml:"service_section"`
	// windows_hook_section  windows_hook_section  `xml:"windows_hook_section"`
}
type registrySection struct {
	SetValues []setValue `xml:"set_value"`
}
type setValue struct {
	Key   string `xml:"key,attr"`
	Value string `xml:"value,attr"`
}
type mutexSection struct {
	CreateMutex []createMutex `xml:"create_mutex"`
}
type createMutex struct {
	Name string `xml:"name,attr"`
}
type dllHandlingSection struct {
	LoadDlls []loadDll `xml:"load_dll"`
}
type loadDll struct {
	Filename string `xml:"filename,attr"`
}
type filesystemSection struct {
	CreateFile []secFile `xml:"create_file"`
	DeleteFile []secFile `xml:"delete_file"`
}
type secFile struct {
	FileType string `xml:"filetype,attr"`
	SrcFile  string `xml:"srcfile,attr"`
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
type notFound struct {
	Found bool   `json:"found"`
	SHA1  string `json:"sha1"`
}

// IsEmpty checks if ResultsData is empty
// func (r ResultsData) IsEmpty() bool {
// 	return reflect.DeepEqual(r, ResultsData{})
// }

func hashType(hash string) *grequests.RequestOptions {
	hashTyp, err := utils.GetHashType(hash)
	if err != nil {
		return &grequests.RequestOptions{}
	}

	return &grequests.RequestOptions{Params: map[string]string{hashTyp: hash}}
}

// http://api.totalhash.com/search/$query&id=$userid&sign=$sign
func doSearch(query string, userid string, sign string) {
	fmt.Println("http://api.totalhash.com/search/" + query + "&id=" + userid + "&sign=" + sign)
	ro := &grequests.RequestOptions{InsecureSkipVerify: true}
	resp, err := grequests.Get("http://api.totalhash.com/search/"+query+"&id="+userid+"&sign="+sign, ro)

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
	// fmt.Println("http://api.totalhash.com/analysis/" + sha1 + "&id=" + userid + "&sign=" + sign)
	tha := TotalHashAnalysis{}

	ro := &grequests.RequestOptions{InsecureSkipVerify: true}
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
	// utils.Assert(ioutil.WriteFile(sha1+".xml", resp.Bytes(), 0644))

	err = xml.Unmarshal(resp.Bytes(), &tha)
	utils.Assert(err)

	tha.Found = true

	return tha
}

// http://api.totalhash.com/usage/id=<userid>&signsig=<sign>
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

// http://api.totalhash.com/upload/id=<user>&sign=<digest>
func uploadSample(path string, userid string, sign string) {
	fd, err := grequests.FileUploadFromDisk(path)

	if err != nil {
		log.Println("Unable to open file: ", err)
	}

	// This will upload the file as a multipart mime request
	resp, err := grequests.Post("https://api.totalhash.com/upload/id="+userid+"&sign="+sign,
		&grequests.RequestOptions{
			InsecureSkipVerify: true,
			Files:              fd,
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
	fmt.Println(body)
}

func printMarkDownTable(tha TotalHashAnalysis) {
	fmt.Println("#### totalhash")
}

func main() {

	var (
		thuser  string
		thkey   string
		elastic string
	)

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "totalhash"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice totalhash Plugin"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:        "elasitcsearch",
			Value:       "",
			Usage:       "elasitcsearch address for Malice to store results",
			EnvVar:      "MALICE_ELASTICSEARCH",
			Destination: &elastic,
		},
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
	app.Action = func(c *cli.Context) error {

		// Check for valid thkey
		if thkey == "" {
			log.Fatal(fmt.Errorf("Please supply a valid #totalhash user/key with the flags '--user' and '--key'."))
		}

		if c.Args().Present() {

			if c.GlobalBool("verbose") {
				log.SetLevel(log.DebugLevel)
			}

			hash := c.Args().First()
			thashReport := getAnalysis(hash, thuser, getHmac256Signature(hash, thkey))

			// upsert into Database
			elasticsearch.InitElasticSearch(elastic)
			elasticsearch.WritePluginResultsToDatabase(elasticsearch.PluginResults{
				ID:       utils.Getopt("MALICE_SCANID", hash),
				Name:     name,
				Category: category,
				Data:     structs.Map(thashReport),
			})

			if c.Bool("table") {
				printMarkDownTable(thashReport)
			} else {
				if thashReport.Found {
					thashJSON, err := json.Marshal(thashReport)
					utils.Assert(err)

					if c.GlobalBool("post") {
						request := gorequest.New()
						if c.GlobalBool("proxy") {
							request = gorequest.New().Proxy(os.Getenv("MALICE_PROXY"))
						}
						request.Post(os.Getenv("MALICE_ENDPOINT")).
							Set("X-Malice-ID", utils.Getopt("MALICE_SCANID", hash)).
							Send(string(thashJSON)).
							End(printStatus)

						return nil
					}
					fmt.Println(string(thashJSON))
				} else {
					notfoundJSON, err := json.Marshal(notFound{
						Found: false,
						SHA1:  c.Args().First(),
					})
					utils.Assert(err)
					fmt.Println(string(notfoundJSON))
				}
			}
		} else {
			log.Fatal(fmt.Errorf("Please supply a SHA1 hash to query."))
		}
		return nil
	}

	err := app.Run(os.Args)
	utils.Assert(err)
}
