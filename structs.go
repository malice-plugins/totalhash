package main

type THanalysis struct {
	Md5                 string               `xml:" md5,attr"  json:"md5,omitempty"`
	Sha1                string               `xml:" sha1,attr"  json:"sha1,omitempty"`
	Time                string               `xml:" time,attr"  json:"time,omitempty"`
	Version             string               `xml:" version,attr"  json:"version,omitempty"`
	THcalltree          *THcalltree          `xml:" calltree,omitempty" json:"calltree,omitempty"`
	THnetwork_pcap      *THnetwork_pcap      `xml:" network_pcap,omitempty" json:"network_pcap,omitempty"`
	THprocesses         *THprocesses         `xml:" processes,omitempty" json:"processes,omitempty"`
	THrunning_processes *THrunning_processes `xml:" running_processes,omitempty" json:"running_processes,omitempty"`
	THstatic            *THstatic            `xml:" static,omitempty" json:"static,omitempty"`
}

type THav struct {
	Av_product string `xml:" av_product,attr"  json:"av_product,omitempty"`
	Info       string `xml:" info,attr"  json:"info,omitempty"`
	Scanner    string `xml:" scanner,attr"  json:"scanner,omitempty"`
	Signature  string `xml:" signature,attr"  json:"signature,omitempty"`
	Timestamp  string `xml:" timestamp,attr"  json:"timestamp,omitempty"`
	Update     string `xml:" update,attr"  json:"update,omitempty"`
	Version    string `xml:" version,attr"  json:"version,omitempty"`
}

type THcalltree struct {
	THprocess_call []*THprocess_call `xml:" process_call,omitempty" json:"process_call,omitempty"`
}

type THcreate_file struct {
	Filetype string `xml:" filetype,attr"  json:"filetype,omitempty"`
	Srcfile  string `xml:" srcfile,attr"  json:"srcfile,omitempty"`
}

type THcreate_mutex struct {
	Name string `xml:" name,attr"  json:"name,omitempty"`
}

type THcreate_process struct {
	Apifunction string `json:"apifunction,omitempty" xml:" apifunction,attr"`
	Cmdline     string `json:"cmdline,omitempty" xml:" cmdline,attr"`
	Targetpid   string `json:"targetpid,omitempty" xml:" targetpid,attr"`
}

type THdelete_file struct {
	Filetype string `xml:" filetype,attr"  json:"filetype,omitempty"`
	Srcfile  string `xml:" srcfile,attr"  json:"srcfile,omitempty"`
}

type THdll_handling_section struct {
	THload_dll []*THload_dll `xml:" load_dll,omitempty" json:"load_dll,omitempty"`
}

type THdns struct {
	IP   string `xml:" ip,attr"  json:"ip,omitempty"`
	RR   string `xml:" rr,attr"  json:"rr,omitempty"`
	Type string `xml:" type,attr"  json:"type,omitempty"`
}

type THfilesystem_section struct {
	THcreate_file []*THcreate_file `xml:" create_file,omitempty" json:"create_file,omitempty"`
	THdelete_file []*THdelete_file `xml:" delete_file,omitempty" json:"delete_file,omitempty"`
}

type THflows struct {
	Bytes    string `xml:" bytes,attr"  json:"bytes,omitempty"`
	DstIP    string `xml:" dst_ip,attr"  json:"dst_ip,omitempty"`
	DstPort  string `xml:" dst_port,attr"  json:"dst_port,omitempty"`
	Protocol string `xml:" protocol,attr"  json:"protocol,omitempty"`
	SrcIP    string `xml:" src_ip,attr"  json:"src_ip,omitempty"`
	SrcPort  string `xml:" src_port,attr"  json:"src_port,omitempty"`
}

type THgetaddrinfo struct {
	RequestedHost string `xml:" requested_host,attr"  json:"requested_host,omitempty"`
}

type THimphash struct {
	Value string `xml:" value,attr"  json:"value,omitempty"`
}

type THimports struct {
	DLL string `xml:" dll,attr"  json:"dll,omitempty"`
}

type THlanguage struct {
	Value string `xml:" value,attr"  json:"value,omitempty"`
}

type THload_dll struct {
	Filename string `xml:" filename,attr"  json:"filename,omitempty"`
}

type THmagic struct {
	Value string `xml:" value,attr"  json:"value,omitempty"`
}

type THmutex_section struct {
	THcreate_mutex []*THcreate_mutex `xml:" create_mutex,omitempty" json:"create_mutex,omitempty"`
}

type THnetwork_pcap struct {
	Md5     string     `xml:" md5,attr"  json:"md5,omitempty"`
	Sha1    string     `xml:" sha1,attr"  json:"sha1,omitempty"`
	THdns   []*THdns   `xml:" dns,omitempty" json:"dns,omitempty"`
	THflows []*THflows `xml:" flows,omitempty" json:"flows,omitempty"`
}

type THopen_process struct {
	ApiFunction string `xml:" apifunction,attr"  json:"apifunction,omitempty"`
	TargetPid   string `xml:" targetpid,attr"  json:"targetpid,omitempty"`
}
type THpacker struct {
	Value string `xml:" value,attr"  json:"value,omitempty"`
}

type THpdb struct {
	Value string `xml:" value,attr"  json:"value,omitempty"`
}

type THpehash struct {
	Value string `xml:" value,attr"  json:"value,omitempty"`
}

type THprocess struct {
	Executionstatus        string                  `xml:" executionstatus,attr"  json:"executionstatus,omitempty"`
	Filename               string                  `xml:" filename,attr"  json:"filename,omitempty"`
	Index                  string                  `xml:" index,attr"  json:"index,omitempty"`
	Pid                    string                  `xml:" pid,attr"  json:"pid,omitempty"`
	THdll_handling_section *THdll_handling_section `xml:" dll_handling_section,omitempty" json:"dll_handling_section,omitempty"`
	THfilesystem_section   *THfilesystem_section   `xml:" filesystem_section,omitempty" json:"filesystem_section,omitempty"`
	THmutex_section        *THmutex_section        `xml:" mutex_section,omitempty" json:"mutex_section,omitempty"`
	THprocess_section      *THprocess_section      `xml:" process_section,omitempty" json:"process_section,omitempty"`
	THregistry_section     *THregistry_section     `xml:" registry_section,omitempty" json:"registry_section,omitempty"`
	THwindows_hook_section *THwindows_hook_section `xml:" windows_hook_section,omitempty" json:"windows_hook_section,omitempty"`
	THwinsock_section      *THwinsock_section      `xml:" winsock_section,omitempty" json:"winsock_section,omitempty"`
}

type THprocess_call struct {
	Filename    string `xml:" filename,attr"  json:"filename,omitempty"`
	Index       string `xml:" index,attr"  json:"index,omitempty"`
	Pid         string `xml:" pid,attr"  json:"pid,omitempty"`
	Startreason string `xml:" startreason,attr"  json:"startreason,omitempty"`
}

type THprocess_section struct {
	THcreate_process *THcreate_process `xml:" create_process,omitempty" json:"create_process,omitempty"`
	THopen_process   []*THopen_process `xml:" open_process,omitempty" json:"open_process,omitempty"`
}

type THprocesses struct {
	Scr_shot_md5  string       `xml:" scr_shot_md5,attr"  json:"scr_shot_md5,omitempty"`
	Scr_shot_sha1 string       `xml:" scr_shot_sha1,attr"  json:"scr_shot_sha,omitempty"`
	THprocess     []*THprocess `xml:" process,omitempty" json:"process,omitempty"`
}

type THregistry_section struct {
	THset_value []*THset_value `xml:" set_value,omitempty" json:"set_value,omitempty"`
}

type THroot struct {
	Analysis THanalysis `xml:" analysis,omitempty" json:"analysis,omitempty"`
}

type THrunning_process struct {
	Filename string `xml:" filename,attr"  json:"filename,omitempty"`
	Pid      string `xml:" pid,attr"  json:"pid,omitempty"`
	Ppid     string `xml:" ppid,attr"  json:"ppid,omitempty"`
}

type THrunning_processes struct {
	THrunning_process []*THrunning_process `xml:" running_process,omitempty" json:"running_process,omitempty"`
}

type THsection struct {
	Md5  string `xml:" md5,attr"  json:"md3,omitempty"`
	Name string `xml:" name,attr"  json:"name,omitempty"`
	Sha1 string `xml:" sha1,attr"  json:"sha1,omitempty"`
	Size string `xml:" size,attr"  json:"size,omitempty"`
}

type THset_value struct {
	Key   string `xml:" key,attr"  json:"key,omitempty"`
	Value string `xml:" value,attr"  json:"value,omitempty"`
}

type THset_windows_hook struct {
	Hook_address string `xml:" hook_address,attr"  json:"hook_address,omitempty"`
	Hookid       string `xml:" hookid,attr"  json:"hookid,omitempty"`
	Threadid     string `xml:" threadid,attr"  json:"threadid,omitempty"`
}

type THstatic struct {
	Strings_md5  string       `xml:" strings_md5,attr"  json:"strings_md5,omitempty"`
	Strings_sha1 string       `xml:" strings_sha1,attr"  json:"strings_sha1,omitempty"`
	THav         []*THav      `xml:" av,omitempty" json:"av,omitempty"`
	THimphash    *THimphash   `xml:" imphash,omitempty" json:"imphash,omitempty"`
	THimports    []*THimports `xml:" imports,omitempty" json:"imports,omitempty"`
	THlanguage   *THlanguage  `xml:" language,omitempty" json:"language,omitempty"`
	THmagic      *THmagic     `xml:" magic,omitempty" json:"magic,omitempty"`
	THpacker     *THpacker    `xml:" packer,omitempty" json:"packer,omitempty"`
	THpdb        *THpdb       `xml:" pdb,omitempty" json:"pdb,omitempty"`
	THpehash     *THpehash    `xml:" pehash,omitempty" json:"pehash,omitempty"`
	THsection    []*THsection `xml:" section,omitempty" json:"section,omitempty"`
	THtimestamp  *THtimestamp `xml:" timestamp,omitempty" json:"timestamp,omitempty"`
	THversion    *THversion   `xml:" version,omitempty" json:"version,omitempty"`
}

type THtimestamp struct {
	Value string `xml:" value,attr"  json:"value,omitempty"`
}

type THversion struct {
	Value string `xml:" value,attr"  json:"value,omitempty"`
}

type THwindows_hook_section struct {
	THset_windows_hook *THset_windows_hook `xml:" set_windows_hook,omitempty" json:"set_windows_hook,omitempty"`
}

type THwinsock_section struct {
	THgetaddrinfo []*THgetaddrinfo `xml:" getaddrinfo,omitempty" json:"getaddrinfo,omitempty"`
}
