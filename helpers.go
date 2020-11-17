package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
)

func indexTxtDateToHumanReadable(datetime string) string {
	layout := "060102150405Z"
	t, err := time.Parse(layout, datetime)
	if err != nil {
		log.Println(err)
	}
	return t.Format("2006-01-02 15:04:05")
}

func runBash(script string) string {
	fmt.Println(script)
	cmd := exec.Command("bash", "-c", script)
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		return (fmt.Sprint(err) + " : " + string(stdout))
	}
	return string(stdout)
}

func fExist(path string) bool {
	var _, err = os.Stat(path)

	if os.IsNotExist(err) {
		return false
	} else if err != nil {
		log.Fatal(err)
		return false
	}

	return true
}

func fRead(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	return string(content)
}

func fCreate(path string) bool {
	var _, err = os.Stat(path)
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if err != nil {
			log.Println(err)
			return false
		}
		defer file.Close()
	}
	return true
}

func fWrite(path, content string) {
	err := ioutil.WriteFile(path, []byte(content), 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func fDelete(path string) {
	err := os.Remove(path)
	if err != nil {
		log.Fatal(err)
	}
}

func fDownload(path, url string, basicAuth bool) error {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if basicAuth {
		req.SetBasicAuth(*masterBasicAuthUser, *masterBasicAuthPassword)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		log.Printf("WARNING: Download file operation for url %s finished with status code %d", url, resp.StatusCode  )
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fCreate(path)
	fWrite(path, string(body))

	return nil
}
