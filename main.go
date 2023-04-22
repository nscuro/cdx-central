package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

func main() {
	var (
		minComponents int
		outputDir     string
	)
	flag.IntVar(&minComponents, "min-components", 10, "Minimum number of components in an SBOM")
	flag.StringVar(&outputDir, "output", ".", "Output directory")
	flag.Parse()

	gavs, err := collectGAVs()
	if err != nil {
		log.Fatalf("failed to collect artifacts: %v", err)
	}

	for _, gav := range gavs {
		err = downloadSBOM(gav, minComponents, outputDir)
		if err != nil {
			log.Printf("failed to download sbom for %#v: %v", gav, err)
		}
	}
}

type SearchResponse struct {
	Response struct {
		Docs []struct {
			GroupID       string `json:"g"`
			ArtifactID    string `json:"a"`
			LatestVersion string `json:"latestVersion"`
		} `json:"docs"`
	} `json:"response"`
}

type GAV struct {
	GroupID    string
	ArtifactID string
	Version    string
}

func collectGAVs() ([]GAV, error) {
	log.Println("searching for artifacts with cdx sbom")
	start := 0
	gavs := make([]GAV, 0)
	for {
		g, err := searchGAVs(150, start)
		if err != nil {
			log.Fatalf("failed to search for artifacts: %v", err)
		}
		if len(g) == 0 {
			break
		}
		gavs = append(gavs, g...)
		start += len(g)
	}
	fmt.Printf("no more search results")
	return gavs, nil
}

func searchGAVs(rows, start int) ([]GAV, error) {
	log.Printf("fetching search results %d - %d", start, start+rows)
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://search.maven.org/solrsearch/select?q=cyclonedx.json&rows=%d&start=%d&wt=json", rows, start), nil)
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	var resJSON SearchResponse
	err = json.NewDecoder(res.Body).Decode(&resJSON)
	if err != nil {
		return nil, err
	}

	gavs := make([]GAV, len(resJSON.Response.Docs))
	for i := 0; i < len(resJSON.Response.Docs); i++ {
		gavs[i] = GAV{
			GroupID:    resJSON.Response.Docs[i].GroupID,
			ArtifactID: resJSON.Response.Docs[i].ArtifactID,
			Version:    resJSON.Response.Docs[i].LatestVersion,
		}
	}

	return gavs, nil
}

func downloadSBOM(gav GAV, minComponents int, outputDir string) error {
	log.Printf("downloading sbom for %#v", gav)
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s-cyclonedx.json", strings.ReplaceAll(gav.GroupID, ".", "/"), gav.ArtifactID, gav.Version, gav.ArtifactID, gav.Version), nil)
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var sbom cyclonedx.BOM
	err = cyclonedx.NewBOMDecoder(bytes.NewReader(resBytes), cyclonedx.BOMFileFormatJSON).Decode(&sbom)
	if err != nil {
		return err
	}

	if sbom.Components == nil || len(*sbom.Components) < minComponents {
		log.Printf("discarding sbom for %#v because it has too few components", gav)
		return nil
	}

	fileName := fmt.Sprintf("%s_%s_%s.cdx.json", gav.GroupID, gav.ArtifactID, gav.Version)
	f, err := os.Create(filepath.Join(outputDir, fileName))
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(resBytes)
	if err != nil {
		return err
	}

	return nil
}
