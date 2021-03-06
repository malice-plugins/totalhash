

package main

/////////////////////////////////////////////////////////////////
//Code generated by chidley https://github.com/gnewton/chidley //
/////////////////////////////////////////////////////////////////

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
)

const (
	JsonOut = iota
	XmlOut
	CountAll
)

var toJson bool = false
var toXml bool = false
var oneLevelDown bool = false
var countAll bool = false
var musage bool = false

var uniqueFlags = []*bool{
	&toJson,
	&toXml,
	&countAll}

var filename = "/Users/user/src/go/src/github.com/maliceio/malice-totalhash/sample-xml/total2.xml"



func init() {
	flag.BoolVar(&toJson, "j", toJson, "Convert to JSON")
	flag.BoolVar(&toXml, "x", toXml, "Convert to XML")
	flag.BoolVar(&countAll, "c", countAll, "Count each instance of XML tags")
	flag.BoolVar(&oneLevelDown, "s", oneLevelDown, "Stream XML by using XML elements one down from the root tag. Good for huge XML files (see http://blog.davidsingleton.org/parsing-huge-xml-files-with-go/")
	flag.BoolVar(&musage, "h", musage, "Usage")
	flag.StringVar(&filename, "f", filename, "XML file or URL to read in")
}

var out int = -1

var counters map[string]*int

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()

	if musage {
		flag.Usage()
		return
	}

	numSetBools, outFlag := numberOfBoolsSet(uniqueFlags)
	if numSetBools == 0 {
		flag.Usage()
                return
	}

	if numSetBools != 1 {
		flag.Usage()
		log.Fatal("Only one of ", uniqueFlags, " can be set at once")
	}

	reader, xmlFile, err := genericReader(filename)
	if err != nil {
		log.Fatal(err)
		return
	}

	decoder := xml.NewDecoder(reader)
	counters = make(map[string]*int)
	for {
		token, _ := decoder.Token()
		if token == nil {
			break
		}
		switch se := token.(type) {
		case xml.StartElement:
			handleFeed(se, decoder, outFlag)
		}
	}
        if xmlFile != nil{
	    defer xmlFile.Close()
        }
	if countAll {
		for k, v := range counters {
			fmt.Println(*v, k)
		}
	}
}

func handleFeed(se xml.StartElement, decoder *xml.Decoder, outFlag *bool) {
	if outFlag == &countAll {
		incrementCounter(se.Name.Space, se.Name.Local)
	} else {
                if !oneLevelDown{
        		if se.Name.Local == "analysis" && se.Name.Space == "" {
	        	      var item Chianalysis
			      decoder.DecodeElement(&item, &se)
			      switch outFlag {
			      case &toJson:
				      writeJson(item)
			      case &toXml:
				      writeXml(item)
			      }
		      }
                }else{
                   
        		if se.Name.Local == "static" && se.Name.Space == "" {
	        	      var item Chistatic
			      decoder.DecodeElement(&item, &se)
			      switch outFlag {
			      case &toJson:
				      writeJson(item)
			      case &toXml:
				      writeXml(item)
			      }
		      }
                   
        		if se.Name.Local == "calltree" && se.Name.Space == "" {
	        	      var item Chicalltree
			      decoder.DecodeElement(&item, &se)
			      switch outFlag {
			      case &toJson:
				      writeJson(item)
			      case &toXml:
				      writeXml(item)
			      }
		      }
                   
        		if se.Name.Local == "processes" && se.Name.Space == "" {
	        	      var item Chiprocesses
			      decoder.DecodeElement(&item, &se)
			      switch outFlag {
			      case &toJson:
				      writeJson(item)
			      case &toXml:
				      writeXml(item)
			      }
		      }
                   
        		if se.Name.Local == "running_processes" && se.Name.Space == "" {
	        	      var item Chirunning_processes
			      decoder.DecodeElement(&item, &se)
			      switch outFlag {
			      case &toJson:
				      writeJson(item)
			      case &toXml:
				      writeXml(item)
			      }
		      }
                   
        		if se.Name.Local == "network_pcap" && se.Name.Space == "" {
	        	      var item Chinetwork_pcap
			      decoder.DecodeElement(&item, &se)
			      switch outFlag {
			      case &toJson:
				      writeJson(item)
			      case &toXml:
				      writeXml(item)
			      }
		      }
                   
               }
	}
}

func makeKey(space string, local string) string {
	if space == "" {
		space = "_"
	}
	return space + ":" + local
}

func incrementCounter(space string, local string) {
	key := makeKey(space, local)

	counter, ok := counters[key]
	if !ok {
		n := 1
		counters[key] = &n
	} else {
		newv := *counter + 1
		counters[key] = &newv
	}
}

func writeJson(item interface{}) {
	b, err := json.MarshalIndent(item, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(b))
}

func writeXml(item interface{}) {
	output, err := xml.MarshalIndent(item, "  ", "    ")
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}
	os.Stdout.Write(output)
}

func genericReader(filename string) (io.Reader, *os.File, error) {
	if filename == "" {
		return bufio.NewReader(os.Stdin), nil, nil
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	if strings.HasSuffix(filename, "bz2") {
		return bufio.NewReader(bzip2.NewReader(bufio.NewReader(file))), file, err
	}

	if strings.HasSuffix(filename, "gz") {
		reader, err := gzip.NewReader(bufio.NewReader(file))
		if err != nil {
			return nil, nil, err
		}
		return bufio.NewReader(reader), file, err
	}
	return bufio.NewReader(file), file, err
}

func numberOfBoolsSet(a []*bool) (int, *bool) {
	var setBool *bool
	counter := 0
	for i := 0; i < len(a); i++ {
		if *a[i] {
			counter += 1
			setBool = a[i]
		}
	}
	return counter, setBool
}


///////////////////////////
/// structs
///////////////////////////

type Chianalysis struct {
	Attr_md5 string `xml:" md5,attr"  json:",omitempty"`
	Attr_sha1 string `xml:" sha1,attr"  json:",omitempty"`
	Attr_time string `xml:" time,attr"  json:",omitempty"`
	Attr_version string `xml:" version,attr"  json:",omitempty"`
	Chicalltree *Chicalltree `xml:" calltree,omitempty" json:"calltree,omitempty"`
	Chinetwork_pcap *Chinetwork_pcap `xml:" network_pcap,omitempty" json:"network_pcap,omitempty"`
	Chiprocesses *Chiprocesses `xml:" processes,omitempty" json:"processes,omitempty"`
	Chirunning_processes *Chirunning_processes `xml:" running_processes,omitempty" json:"running_processes,omitempty"`
	Chistatic *Chistatic `xml:" static,omitempty" json:"static,omitempty"`
}

type Chiav struct {
	Attr_av_product string `xml:" av_product,attr"  json:",omitempty"`
	Attr_info string `xml:" info,attr"  json:",omitempty"`
	Attr_scanner string `xml:" scanner,attr"  json:",omitempty"`
	Attr_signature string `xml:" signature,attr"  json:",omitempty"`
	Attr_timestamp string `xml:" timestamp,attr"  json:",omitempty"`
	Attr_update string `xml:" update,attr"  json:",omitempty"`
	Attr_version string `xml:" version,attr"  json:",omitempty"`
}

type Chicalltree struct {
}

type Chicreate_file struct {
	Attr_filetype string `xml:" filetype,attr"  json:",omitempty"`
	Attr_srcfile string `xml:" srcfile,attr"  json:",omitempty"`
}

type Chicreate_mutex struct {
	Attr_name string `xml:" name,attr"  json:",omitempty"`
}

type Chidll_handling_section struct {
	Chiload_dll []*Chiload_dll `xml:" load_dll,omitempty" json:"load_dll,omitempty"`
}

type Chifilesystem_section struct {
	Chicreate_file []*Chicreate_file `xml:" create_file,omitempty" json:"create_file,omitempty"`
}

type Chiimphash struct {
	Attr_value string `xml:" value,attr"  json:",omitempty"`
}

type Chilanguage struct {
	Attr_value string `xml:" value,attr"  json:",omitempty"`
}

type Chiload_dll struct {
	Attr_filename string `xml:" filename,attr"  json:",omitempty"`
}

type Chimagic struct {
	Attr_value string `xml:" value,attr"  json:",omitempty"`
}

type Chimutex_section struct {
	Chicreate_mutex *Chicreate_mutex `xml:" create_mutex,omitempty" json:"create_mutex,omitempty"`
}

type Chinetwork_pcap struct {
	Attr_md5 string `xml:" md5,attr"  json:",omitempty"`
	Attr_sha1 string `xml:" sha1,attr"  json:",omitempty"`
}

type Chipacker struct {
	Attr_value string `xml:" value,attr"  json:",omitempty"`
}

type Chipehash struct {
	Attr_value string `xml:" value,attr"  json:",omitempty"`
}

type Chiprocess struct {
	Attr_filename string `xml:" filename,attr"  json:",omitempty"`
	Attr_index string `xml:" index,attr"  json:",omitempty"`
	Attr_pid string `xml:" pid,attr"  json:",omitempty"`
	Chidll_handling_section *Chidll_handling_section `xml:" dll_handling_section,omitempty" json:"dll_handling_section,omitempty"`
	Chifilesystem_section *Chifilesystem_section `xml:" filesystem_section,omitempty" json:"filesystem_section,omitempty"`
	Chimutex_section *Chimutex_section `xml:" mutex_section,omitempty" json:"mutex_section,omitempty"`
	Chiregistry_section *Chiregistry_section `xml:" registry_section,omitempty" json:"registry_section,omitempty"`
}

type Chiprocesses struct {
	Attr_scr_shot_md5 string `xml:" scr_shot_md5,attr"  json:",omitempty"`
	Attr_scr_shot_sha1 string `xml:" scr_shot_sha1,attr"  json:",omitempty"`
	Chiprocess []*Chiprocess `xml:" process,omitempty" json:"process,omitempty"`
}

type Chiregistry_section struct {
	Chiset_value []*Chiset_value `xml:" set_value,omitempty" json:"set_value,omitempty"`
}

type Chiroot struct {
	Chianalysis *Chianalysis `xml:" analysis,omitempty" json:"analysis,omitempty"`
}

type Chirunning_process struct {
	Attr_filename string `xml:" filename,attr"  json:",omitempty"`
	Attr_pid string `xml:" pid,attr"  json:",omitempty"`
	Attr_ppid string `xml:" ppid,attr"  json:",omitempty"`
}

type Chirunning_processes struct {
	Chirunning_process []*Chirunning_process `xml:" running_process,omitempty" json:"running_process,omitempty"`
}

type Chisection struct {
	Attr_md5 string `xml:" md5,attr"  json:",omitempty"`
	Attr_name string `xml:" name,attr"  json:",omitempty"`
	Attr_sha1 string `xml:" sha1,attr"  json:",omitempty"`
	Attr_size string `xml:" size,attr"  json:",omitempty"`
}

type Chiset_value struct {
	Attr_key string `xml:" key,attr"  json:",omitempty"`
	Attr_value string `xml:" value,attr"  json:",omitempty"`
}

type Chistatic struct {
	Attr_strings_md5 string `xml:" strings_md5,attr"  json:",omitempty"`
	Attr_strings_sha1 string `xml:" strings_sha1,attr"  json:",omitempty"`
	Chiav []*Chiav `xml:" av,omitempty" json:"av,omitempty"`
	Chiimphash *Chiimphash `xml:" imphash,omitempty" json:"imphash,omitempty"`
	Chilanguage *Chilanguage `xml:" language,omitempty" json:"language,omitempty"`
	Chimagic *Chimagic `xml:" magic,omitempty" json:"magic,omitempty"`
	Chipacker *Chipacker `xml:" packer,omitempty" json:"packer,omitempty"`
	Chipehash *Chipehash `xml:" pehash,omitempty" json:"pehash,omitempty"`
	Chisection []*Chisection `xml:" section,omitempty" json:"section,omitempty"`
	Chitimestamp *Chitimestamp `xml:" timestamp,omitempty" json:"timestamp,omitempty"`
	Chiversion *Chiversion `xml:" version,omitempty" json:"version,omitempty"`
}

type Chitimestamp struct {
	Attr_value string `xml:" value,attr"  json:",omitempty"`
}

type Chiversion struct {
	Attr_value string `xml:" value,attr"  json:",omitempty"`
}


///////////////////////////

