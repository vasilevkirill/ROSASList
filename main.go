package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/go-routeros/routeros"
	"github.com/jessevdk/go-flags"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Opts struct {
	Router    string `long:"router" description:"IP or DNS name router RouterOS" required:"true"`
	User      string `long:"user" description:"User for router RouterOS" required:"true"`
	Password  string `long:"password" description:"Password for router RouterOS" required:"true"`
	Port      string `long:"port" description:"Port API" default:"8728"`
	SSL       bool   `long:"ssl" description:"Required SSL user for API"`
	List      string `long:"list" description:"Address-List Name" required:"true"`
	ASN       string `long:"ASN" description:"ASN list one or more, delimeter(,)" required:"true"`
	Verbose   bool   `long:"verbose" description:"Show verbose debug information"`
	Cachettl  int    `logn:"cachettl" description:"Time To live cache for ASN" default:"86400"`
	Cachepath string `long:"cachepath" description:"Path to save cache" default:"./tmp"`
	Author    bool   `long:"author" description:"Vasilev Kirill\nhttps://mikrotik.me"`
}

var options Opts

var parser = flags.NewParser(&options, flags.Default)

type ASjson struct {
	Status         string      `json:"status"`
	Status_message string      `json:"status_message"`
	Data           ASjson_data `json:"data"`
}
type ASjson_data struct {
	Ipv4_prefixes []Prefix_IPv4 `json:"ipv4_prefixes"`
}
type Prefix_IPv4 struct {
	Ip   string `json:"ip"`
	Cidr int    `json:"cidr"`
}

func main() {
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}
	if options.Cachettl == 0 {
		options.Cachettl = 86400
	}
	CheckCashPath(options.Cachepath)
	asns := strings.Split(options.ASN, ",")

	for _, as := range asns {
		Verb("Start for ASN: " + as)
		c := CacheLive(as)
		if c == false {
			if UpdateCache(as) == false {
				Verb("ASN " + as + "Update False")
				continue
			}
		}
		err := ROSUpdate(as)
		if err != nil {
			Verb("ASN " + as + "Update False")
			Verb("ASN " + as + err.Error())
			continue
		}

	}

}
func ROSUpdate(as string) (err error) {
	Verb("Connect to Router")
	c, err := dial()
	if err != nil {
		return err
	}
	defer c.Close()
	namelist := "ASN" + as
	Verb("Get Current list " + namelist)
	reply, err := c.Run("/ip/firewall/address-list/print", "?list="+options.List, "?comment="+namelist, "=.proplist=address")
	if err != nil {
		return err
	}
	var curentlist []string
	for _, re := range reply.Re {
		curentlist = append(curentlist, re.List[0].Value)
	}
	file, err := os.Open(options.Cachepath + "/" + as + ".asn")
	if err != nil {
		return err
	}
	defer file.Close()
	var needlist []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		needlist = append(needlist, scanner.Text())
	}
	needremove := compare(curentlist, needlist)
	needadd := compare(needlist, curentlist)
	Verb("Need Remove count: " + strconv.Itoa(len(needremove)))
	Verb("Need Add count: " + strconv.Itoa(len(needadd)))
	for _, l := range needremove {
		r, err := c.Run("/ip/firewall/address-list/print", "?list="+options.List, "?comment="+namelist, "?address="+l, "=.proplist=.id")
		if err != nil {
			return err
		}

		_, err = c.Run("/ip/firewall/address-list/remove", "=.id="+r.Re[0].List[0].Value)
		if err != nil {
			return err
		}
		Verb("Remove address " + l + " From List " + namelist)
	}
	for _, l := range needadd {
		_, err := c.Run("/ip/firewall/address-list/add", "=list="+options.List, "=address="+l, "=comment="+namelist)
		if err != nil {
			return err
		}
		Verb("Add address " + l + " To List " + namelist)
	}
	return nil
}
func dial() (*routeros.Client, error) {
	adr := options.Router + ":" + options.Port
	if options.SSL == true {
		return routeros.DialTLS(adr, options.User, options.Password, nil)
	}
	return routeros.Dial(adr, options.User, options.Password)
}

func CacheLive(asn string) bool {
	file := options.Cachepath + "/" + asn + ".asn"
	if fileExists(file) == false {
		Verb("File Not Exist: " + file)
		return false
	}
	filet, err := os.Stat(file)
	if err != nil {
		Verb("Error get info file: " + file)
		fmt.Println(err)
		return false
	}
	modifiedtime := filet.ModTime()
	Verb("ASN " + asn + " Cache File Time Info: " + modifiedtime.String())
	now := time.Now()
	secNow := now.Unix()
	secF := modifiedtime.Unix()
	ageseccach := secNow - secF
	Verb("ASN " + asn + " CacheTTL: " + strconv.Itoa(options.Cachettl) + " Second ")
	if ageseccach > int64(options.Cachettl) {
		Verb("ASN " + asn + " Cache old, need Update")
		return false
	}
	Verb("ASN " + asn + " Cache Good")
	return true
}

func UpdateCache(asn string) bool {
	url := "https://api.bgpview.io/asn/" + asn + "/prefixes"
	spaceClient := http.Client{
		Timeout: time.Second * 5,
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {

		log.Fatal(err)
		return false
	}
	req.Header.Set("User-Agent", "spacecount-tutorial")
	res, getErr := spaceClient.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
		return false
	}
	Verb("ASN " + asn + " Get Info From " + url)
	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
		return false
	}
	js := ASjson{}
	jsonErr := json.Unmarshal(body, &js)
	if jsonErr != nil {
		log.Fatal(jsonErr)
		return false
	}
	fln := options.Cachepath + "/" + asn + ".asn"
	if fileExists(fln) == false {
		emptyFile, err := os.Create(fln)
		if err != nil {
			log.Fatal(err)
			return false
		}
		Verb("ASN " + asn + " Create file " + fln)
		err = emptyFile.Close()
		if err != nil {
			log.Fatal(err)
			return false
		}
	}
	fo, _ := os.OpenFile(fln, os.O_WRONLY, 0644)
	err = fo.Truncate(0)
	if err != nil {
		log.Fatal(err)
		return false
	}
	defer fo.Close()
	for _, s := range js.Data.Ipv4_prefixes {
		str := s.Ip + "/" + strconv.Itoa(s.Cidr)
		fmt.Fprintln(fo, str)
	}
	return true
}

//CheckCashPath Проверка существования директории и при необходимости создаём её.
func CheckCashPath(path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		Verb("Directory for cache not exist")
		Verb("Create Directory " + path)
		err := os.Mkdir(path, 0777)
		if err != nil {
			Verb("Fatal error not create directory " + path)
			log.Fatal("MkdirAll %q: %s", path, err)
		}
	}
}
func Verb(str string) {
	if options.Verbose {
		log.Printf(str)
	}
}
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func compare(a, b []string) []string {
	for i := len(a) - 1; i >= 0; i-- {
		for _, vD := range b {
			if a[i] == vD {
				a = append(a[:i], a[i+1:]...)
				break
			}
		}
	}
	return a
}
