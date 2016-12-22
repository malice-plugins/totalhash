package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	clitable "github.com/crackcomm/go-clitable"
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

// TotalHash json object
type TotalHash struct {
	Results ResultsData `json:"totalhash"`
}

// ResultsData json object
type ResultsData struct {
	Found            bool
	XMLName          xml.Name         `xml:"analysis" json:"analysis"`
	Version          string           `xml:"version,attr" json:"version"`
	SHA1             string           `xml:"sha1,attr" json:"sha1"`
	MD5              string           `xml:"md5,attr" json:"md5"`
	Time             string           `xml:"time,attr" json:"time"`
	Static           static           `xml:"static" json:"static"`
	Calltree         calltree         `xml:"calltree" json:"calltree"`
	Processes        processes        `xml:"processes" json:"processes"`
	RunningProcesses runningProcesses `xml:"running_processes" json:"running_processes"`
	NetworkPcap      networkPcap      `xml:"network_pcap" json:"network_pcap"`
}
type static struct {
	StringsSHA1 string    `xml:"strings_sha1,attr"`
	StringsMD5  string    `xml:"strings_md5,attr"`
	Magic       magic     `xml:"magic" json:"magic"`
	Sections    []section `xml:"section" json:"section"`
	Imports     []imports `xml:"imports" json:"imports"`
	PEHash      pehash    `xml:"pehash" json:"pehash"`
	Imphash     imphash   `xml:"imphash" json:"imphash"`
	Pdb         pdb       `xml:"pdb" json:"pdb"`
	Version     version   `xml:"version" json:"version"`
	Language    language  `xml:"language" json:"language"`
	Timestamp   timestamp `xml:"timestamp" json:"timestamp"`
	Packer      packer    `xml:"packer" json:"packer"`
	AVs         []av      `xml:"av" json:"av"`
}
type imports struct {
	Dll string `xml:"dll,attr" json:"dll"`
}
type pehash struct {
	Value string `xml:"value,attr" json:"value"`
}
type imphash struct {
	Value string `xml:"value,attr" json:"value"`
}
type pdb struct {
	Value string `xml:"value,attr" json:"value"`
}
type version struct {
	Value string `xml:"value,attr" json:"value"`
}
type language struct {
	Value string `xml:"value,attr" json:"value"`
}
type timestamp struct {
	Value string `xml:"value,attr" json:"value"`
}
type packer struct {
	Value string `xml:"value,attr" json:"value"`
}
type magic struct {
	Value string `xml:"value,attr" json:"value"`
}
type section struct {
	Name string `xml:"name,attr" json:"name"`
	MD5  string `xml:"md5,attr" json:"md5"`
	SHA1 string `xml:"sha1,attr" json:"sha1"`
	Size string `xml:"size,attr" json:"size"`
}
type av struct {
	Scanner   string `xml:"scanner,attr" json:"scanner"`
	Timestamp string `xml:"timestamp,attr" json:"timestamp"`
	AVProduct string `xml:"av_product,attr" json:"av_product"`
	Version   string `xml:"version,attr" json:"version"`
	Update    string `xml:"update,attr" json:"update"`
	Info      string `xml:"info,attr" json:"info"`
	Signature string `xml:"signature,attr" json:"signature"`
}
type calltree struct {
	ProcessCall []processCall `xml:"process_call" json:"process_call"`
}
type processCall struct {
	Index       string `xml:"index,attr" json:"index"`
	Filename    string `xml:"filename,attr" json:"filename"`
	Pid         string `xml:"pid,attr" json:"pid"`
	StartReason string `xml:"startreason,attr" json:"start_reason"`
}
type processes struct {
	ScrShotSHA1 string    `xml:"scr_shot_sha1,attr" json:"scr_shot_sha1"`
	ScrShotMD5  string    `xml:"scr_shot_md5,attr" json:"scr_shot_md5"`
	Process     []process `xml:"process" json:"process"`
}
type process struct {
	Index              string             `xml:"index,attr" json:"index"`
	Pid                string             `xml:"pid,attr" json:"pid"`
	Filename           string             `xml:"filename,attr" json:"filename"`
	Executionstatus    string             `xml:"executionstatus,attr" json:"executionstatus"`
	RegistrySection    registrySection    `xml:"registry_section" json:"registry_section"`
	MutexSection       mutexSection       `xml:"mutex_section" json:"mutex_section"`
	DllHandlingSection dllHandlingSection `xml:"dll_handling_section" json:"dll_handling_section"`
	FilesystemSection  filesystemSection  `xml:"filesystem_section" json:"filesystem_section"`
	// system_info_section  system_info_section  `xml:"system_info_section" json:"packer"`
	// service_section  service_section  `xml:"service_section" json:"packer"`
	// windows_hook_section  windows_hook_section  `xml:"windows_hook_section" json:"packer"`
}
type registrySection struct {
	SetValues []setValue `xml:"set_value" json:"set_value"`
}
type setValue struct {
	Key   string `xml:"key,attr" json:"key"`
	Value string `xml:"value,attr" json:"value"`
}
type mutexSection struct {
	CreateMutex []createMutex `xml:"create_mutex" json:"create_mutex"`
}
type createMutex struct {
	Name string `xml:"name,attr" json:"name"`
}
type dllHandlingSection struct {
	LoadDlls []loadDll `xml:"load_dll" json:"load_dll"`
}
type loadDll struct {
	Filename string `xml:"filename,attr" json:"filename"`
}
type filesystemSection struct {
	CreateFile []secFile `xml:"create_file" json:"create_file"`
	DeleteFile []secFile `xml:"delete_file" json:"delete_file"`
}
type secFile struct {
	FileType string `xml:"filetype,attr" json:"filetype"`
	SrcFile  string `xml:"srcfile,attr" json:"srcfile"`
}
type runningProcesses struct {
	RunningProcess []runningProcess `xml:"running_process" json:"running_process"`
}
type runningProcess struct {
	Pid      string `xml:"pid,attr" json:"pid"`
	Filename string `xml:"filename,attr" json:"filename"`
	PPid     string `xml:"ppid,attr" json:"ppid"`
}
type networkPcap struct {
	SHA1 string `xml:"sha1,attr" json:"sha1"`
	MD5  string `xml:"md5,attr" json:"md5"`
}
type notFound struct {
	Found bool   `json:"found"`
	SHA1  string `json:"sha1"`
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
func getAnalysis(sha1 string, userid string, sign string) ResultsData {
	// fmt.Println("http://api.totalhash.com/analysis/" + sha1 + "&id=" + userid + "&sign=" + sign)
	tha := ResultsData{}

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

func printMarkDownTable(th TotalHash) {
	fmt.Println("#### #totalhash")
	if !th.Results.Found {
		fmt.Println(" - Not found")
	} else {
		table := clitable.New([]string{"Found", "URL"})
		table.AddRow(map[string]interface{}{
			"Found": ":white_check_mark:",
			"URL":   fmt.Sprintf("[link](%s)", "https://totalhash.cymru.com/analysis/?"+th.Results.SHA1),
		})
		table.Markdown = true
		table.Print()
	}
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

			hashTyp, err := utils.GetHashType(hash)
			utils.Assert(err)

			if !strings.EqualFold(hashTyp, "sha1") {
				log.Fatal(fmt.Errorf("Please supply a valid 'sha1' hash."))
			}

			th := TotalHash{Results: getAnalysis(hash, thuser, getHmac256Signature(hash, thkey))}

			if elastic != "" {
				// upsert into Database
				elasticsearch.InitElasticSearch(elastic)
				elasticsearch.WritePluginResultsToDatabase(elasticsearch.PluginResults{
					ID:       utils.Getopt("MALICE_SCANID", hash),
					Name:     name,
					Category: category,
					Data:     structs.Map(th.Results),
				})
			}

			if c.Bool("table") {
				printMarkDownTable(th)
			} else {
				if th.Results.Found {
					thashJSON, err := json.Marshal(th)
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
						SHA1:  hash,
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
