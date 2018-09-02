package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fatih/structs"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"

	"github.com/levigross/grequests"
	"github.com/malice-plugins/pkgs/database"
	"github.com/malice-plugins/pkgs/database/elasticsearch"
	"github.com/malice-plugins/pkgs/utils"
	"github.com/parnurzeal/gorequest"
	"github.com/urfave/cli"
)

const (
	name     = "totalhash"
	category = "intel"
)

var (
	// Version stores the plugin's version
	Version string
	// BuildTime stores the plugin's build time
	BuildTime string
	// es is the elasticsearch database object
	es elasticsearch.Database
	// #totalhash creds
	thuser string
	thkey  string
)

// TotalHash json object
type TotalHash struct {
	Results  THanalysis `json:"totalhash" structs:"results,omitempty"`
	MarkDown string     `json:"markdown,omitempty" structs:"markdown,omitempty"`
}

// IsEmpty checks if THanalysis is empty
func (r THanalysis) IsEmpty() bool {
	return reflect.DeepEqual(r, THanalysis{})
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
func getAnalysis(sha1 string, userid string, sign string) THanalysis {
	// fmt.Println("http://api.totalhash.com/analysis/" + sha1 + "&id=" + userid + "&sign=" + sign)
	tha := THanalysis{}

	ro := &grequests.RequestOptions{InsecureSkipVerify: true}
	resp, err := grequests.Get("http://api.totalhash.com/analysis/"+sha1+"&id="+userid+"&sign="+sign, ro)

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.StatusCode == 404 {
		// log.Println("Request did not return OK")
		// log.Println("StatusCode: ", resp.StatusCode)
		return tha
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		log.Fatal(fmt.Errorf("BAD user/key - Please supply a valid credentials"))
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
		log.Println("StatusCode: ", resp.StatusCode)
	}

	// fmt.Println(resp.String())
	// utils.Assert(ioutil.WriteFile(sha1+".xml", resp.Bytes(), 0644))

	err = xml.Unmarshal(resp.Bytes(), &tha)
	utils.Assert(err)

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

func generateMarkDownTable(th TotalHash) string {
	var tplOut bytes.Buffer

	t := template.Must(template.New("").Parse(tpl))

	err := t.Execute(&tplOut, th)
	if err != nil {
		log.Println("executing template:", err)
	}

	return tplOut.String()
}

func webService() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/lookup/{hash}", webLookUp)
	log.Info("web service listening on port :3993")
	log.Fatal(http.ListenAndServe(":3993", router))
}

func webLookUp(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hash := vars["hash"]

	hashType, _ := utils.GetHashType(hash)
	if !strings.EqualFold(hashType, "sha1") {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Please supply a proper SHA1 hash to query")
		return
	}

	analysis := getAnalysis(hash, thuser, getHmac256Signature(hash, thkey))
	th := TotalHash{Results: analysis}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	// if nsrl.Results.Found {
	// 	w.WriteHeader(http.StatusOK)
	// } else {
	// 	w.WriteHeader(http.StatusNotFound)
	// }

	if err := json.NewEncoder(w).Encode(th); err != nil {
		panic(err)
	}
}

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(body)
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "totalhash"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice #totalhash Plugin"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:        "user",
			Value:       "",
			Usage:       "#totalhash user",
			EnvVar:      "MALICE_TH_USER",
			Destination: &thuser,
		},
		cli.StringFlag{
			Name:        "key",
			Value:       "",
			Usage:       "#totalhash key",
			EnvVar:      "MALICE_TH_KEY",
			Destination: &thkey,
		},
	}
	app.Commands = []cli.Command{
		{
			Name:    "web",
			Aliases: []string{"w"},
			Usage:   "Create a NSRL lookup web service",
			Action: func(c *cli.Context) error {
				webService()
				return nil
			},
		},
		{
			Name:      "lookup",
			Aliases:   []string{"l"},
			Usage:     "Query #totalhash for SHA1 hash",
			ArgsUsage: "SHA1 to query #totalhash with",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "elasticsearch",
					Value:       "",
					Usage:       "elasticsearch url for Malice to store results",
					EnvVar:      "MALICE_ELASTICSEARCH_URL",
					Destination: &es.URL,
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
				cli.IntFlag{
					Name:   "timeout",
					Value:  10,
					Usage:  "malice plugin timeout (in seconds)",
					EnvVar: "MALICE_TIMEOUT",
				},
				cli.BoolFlag{
					Name:  "table, t",
					Usage: "output as Markdown table",
				},
			},
			Action: func(c *cli.Context) error {
				// Check for valid thkey
				if thkey == "" {
					log.Fatal(fmt.Errorf("Please supply a valid #totalhash user/key with the flags '--user' and '--key'"))
				}

				if c.Args().Present() {

					if c.GlobalBool("verbose") {
						log.SetLevel(log.DebugLevel)
					}

					hash := c.Args().First()

					hashTyp, err := utils.GetHashType(hash)
					utils.Assert(err)

					if !strings.EqualFold(hashTyp, "sha1") {
						log.Fatal(fmt.Errorf("please supply a valid 'sha1' hash"))
					}
					analysis := getAnalysis(hash, thuser, getHmac256Signature(hash, thkey))
					th := TotalHash{Results: analysis}
					th.MarkDown = generateMarkDownTable(th)

					// upsert into Database
					if len(c.String("elasticsearch")) > 0 {
						err := es.Init()
						if err != nil {
							return errors.Wrap(err, "failed to initalize elasticsearch")
						}
						err = es.StorePluginResults(database.PluginResults{
							ID:       utils.Getopt("MALICE_SCANID", hash),
							Name:     name,
							Category: category,
							Data:     structs.Map(th),
						})
						if err != nil {
							return errors.Wrapf(err, "failed to index malice/%s results", name)
						}
					}

					if c.Bool("table") {
						fmt.Println(th.MarkDown)
					} else {
						if th.Results.IsEmpty() {
							notfoundJSON, err := json.Marshal(map[string]string{
								"found": "false",
								"sha1":  hash,
							})
							utils.Assert(err)
							fmt.Println(string(notfoundJSON))
						} else {
							th.MarkDown = ""
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
						}
					}
				} else {
					log.Fatal(fmt.Errorf("Please supply a SHA1 hash to query"))
				}
				return nil
			},
		},
	}

	err := app.Run(os.Args)
	utils.Assert(err)
}
