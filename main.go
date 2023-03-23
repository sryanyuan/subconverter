package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"
)

type SubItem struct {
	Name           string
	Type           string
	Server         string
	Port           int
	Password       string
	Udp            bool
	Sni            string
	SkipCertVerify bool
	Network        string
}

func (s *SubItem) fromLine(line string) error {
	lines := strings.Split(line, ":")
	if len(lines) != 3 {
		return fmt.Errorf("invalid line")
	}
	s.Type = lines[0]

	subs := strings.Split(strings.TrimPrefix(lines[1], "//"), "@")
	if len(subs) != 2 {
		return errors.New("invalid line")
	}
	s.Password = subs[0]
	s.Server = subs[1]

	subs = strings.Split(lines[2], "?")
	s.Port, _ = strconv.Atoi(subs[0])

	u, err := url.ParseQuery(subs[1])
	if err != nil {
		return err
	}
	s.Sni = u.Get("sni")
	s.Name = strings.Split(s.Sni, "#")[1]
	s.Sni = strings.Split(s.Sni, "#")[0]

	return nil
}

func readUntil(r io.Reader, term byte) ([]byte, error) {
	var data []byte
	for {
		var bd [1]byte
		b, err := r.Read(bd[:])
		if err != nil {
			return data, err
		}
		if b != 1 {
			return data, io.EOF
		}
		if bd[0] == term {
			return data, nil
		}
		data = append(data, bd[0])
	}
}

func (s *SubItem) fromLineSmart(line string) error {
	reader := bytes.NewReader([]byte(line))
	protocol, err := readUntil(reader, ':')
	if err != nil {
		return err
	}
	s.Type = string(protocol)

	password, err := readUntil(reader, '@')
	if err != nil {
		return err
	}
	s.Password = strings.TrimPrefix(string(password), "//")

	server, err := readUntil(reader, ':')
	if err != nil {
		return err
	}
	s.Server = string(server)

	port, err := readUntil(reader, '?')
	if err != nil {
		return err
	}
	s.Port, err = strconv.Atoi(string(port))
	if err != nil {
		return err
	}

	args, err := readUntil(reader, '#')
	if err != nil {
		return err
	}
	u, err := url.ParseQuery(string(args))
	if err != nil {
		return err
	}
	s.Sni = u.Get("sni")
	s.Network = u.Get("type")
	s.SkipCertVerify = u.Get("allowInsecure") == "1"
	s.Udp = true

	name, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	s.Name, _ = url.QueryUnescape(string(name))

	return nil
}

func renderTemplate(tplFile string, items []SubItem) (string, error) {
	tpl := template.Must(template.ParseFiles(tplFile))
	buf := bytes.NewBuffer(nil)
	if err := tpl.Execute(buf, items); nil != err {
		return "", err
	}
	return buf.String(), nil
}

func main() {
	var flagLink string
	var flagAddress string
	var flagTpl string
	var flagToken string

	flag.StringVar(&flagLink, "link", "", "subscribe link")
	flag.StringVar(&flagAddress, "address", ":8080", "listen address")
	flag.StringVar(&flagTpl, "tpl", "", "template path")
	flag.StringVar(&flagToken, "token", "", "invoke token")
	flag.Parse()

	if flagLink == "" || flagTpl == "" {
		flag.PrintDefaults()
		return
	}
	if flagToken == "" {
		fmt.Printf("token is empty\r\n")
		return
	}

	http.HandleFunc("/subscribe", func(response http.ResponseWriter, request *http.Request) {
		request.ParseForm()
		token := request.Form.Get("token")
		if token != flagToken {
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte("permission denied"))
			return
		}

		rsp, err := http.Get(flagLink)
		if err != nil {
			log.Printf("[ERROR] %v", err)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}

		defer rsp.Body.Close()
		r := base64.NewDecoder(base64.StdEncoding, rsp.Body)
		data, err := ioutil.ReadAll(r)
		if err != nil {
			log.Printf("[ERROR] %v", err)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}

		nodeStr := string(data)
		nodes := strings.Split(nodeStr, "\n")
		var items []SubItem
		for i, v := range nodes {
			nodes[i] = strings.TrimSpace(v)
			if nodes[i] == "" {
				continue
			}
			var item SubItem
			if err = item.fromLineSmart(nodes[i]); nil != err {
				response.WriteHeader(http.StatusInternalServerError)
				response.Write([]byte(err.Error()))
				return
			}
			items = append(items, item)
		}

		rspData, err := renderTemplate(flagTpl, items)
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(err.Error()))
			return
		}
		response.Write([]byte(rspData))
	})
	http.ListenAndServe(flagAddress, nil)
}
