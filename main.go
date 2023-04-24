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
	"sync"

	"github.com/CycloneDX/cyclonedx-go"
)

func main() {
	var (
		concurrency   int
		minComponents int
		outputDir     string
	)
	flag.IntVar(&concurrency, "concurrency", 5, "How many artifacts to process concurrently")
	flag.IntVar(&minComponents, "min-components", 10, "Minimum number of components in an SBOM")
	flag.StringVar(&outputDir, "output", ".", "Output directory")
	flag.Parse()

	wg := sync.WaitGroup{}
	artifactsChan := make(chan Artifact, 1)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()

			for artifact := range artifactsChan {
				versions, err := collectVersions(artifact)
				if err != nil {
					log.Fatalf("failed to collect versions for %s: %v", artifact, err)
				}

				for _, version := range versions {
					err = downloadSBOM(version, minComponents, outputDir)
					if err != nil {
						log.Printf("failed to download sbom for %s: %v", version, err)
					}
				}
			}
		}()
	}

	artifacts, err := collectArtifacts()
	if err != nil {
		log.Fatalf("failed to collect artifacts: %v", err)
	}

	for _, artifact := range artifacts {
		artifactsChan <- artifact
	}

	close(artifactsChan)
	wg.Wait()
}

type ArtifactSearchResponse struct {
	Response struct {
		Docs []struct {
			GroupID       string `json:"g"`
			ArtifactID    string `json:"a"`
			LatestVersion string `json:"latestVersion"`
		} `json:"docs"`
	} `json:"response"`
}

type VersionSearchResponse struct {
	Response struct {
		Docs []struct {
			GroupID    string   `json:"g"`
			ArtifactID string   `json:"a"`
			Version    string   `json:"v"`
			Packaging  string   `json:"p"`  // "jar", "pom", etc.
			EC         []string `json:"ec"` // "-sources.jar", ".jar", "-cyclonedx.json", etc.
		}
	} `json:"response"`
}

type Artifact struct {
	GroupID       string
	ArtifactID    string
	LatestVersion string
}

func (a Artifact) String() string {
	return fmt.Sprintf("%s:%s", a.GroupID, a.ArtifactID)
}

type GAV struct {
	GroupID    string
	ArtifactID string
	Version    string
}

func (g GAV) String() string {
	return fmt.Sprintf("%s:%s:%s", g.GroupID, g.ArtifactID, g.Version)
}

func collectArtifacts() ([]Artifact, error) {
	log.Println("searching for artifacts with cdx sbom")
	start := 0
	artifacts := make([]Artifact, 0)
	for {
		g, err := searchArtifacts(150, start)
		if err != nil {
			log.Fatalf("failed to search for artifacts: %v", err)
		}
		if len(g) == 0 {
			break
		}
		artifacts = append(artifacts, g...)
		start += len(g)
	}
	log.Printf("no more search results")
	return artifacts, nil
}

func searchArtifacts(rows, start int) ([]Artifact, error) {
	log.Printf("fetching artifact search results %d - %d", start, start+rows)
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

	var resJSON ArtifactSearchResponse
	err = json.NewDecoder(res.Body).Decode(&resJSON)
	if err != nil {
		return nil, err
	}

	artifacts := make([]Artifact, len(resJSON.Response.Docs))
	for i := 0; i < len(resJSON.Response.Docs); i++ {
		artifacts[i] = Artifact{
			GroupID:       resJSON.Response.Docs[i].GroupID,
			ArtifactID:    resJSON.Response.Docs[i].ArtifactID,
			LatestVersion: resJSON.Response.Docs[i].LatestVersion,
		}
	}

	return artifacts, nil
}

func collectVersions(artifact Artifact) ([]GAV, error) {
	log.Printf("searching for versions of %s with cdx sbom", artifact)
	start := 0
	gavs := make([]GAV, 0)
	for {
		g, err := searchVersions(artifact, 150, start)
		if err != nil {
			log.Fatalf("failed to search for versions of %s: %v", artifact, err)
		}
		if len(g) == 0 {
			break
		}
		gavs = append(gavs, g...)
		start += len(g)
	}
	log.Printf("no more versions of %s", artifact)
	return gavs, nil
}

func searchVersions(artifact Artifact, rows, start int) ([]GAV, error) {
	log.Printf("fetching version search results for %s: %d - %d", artifact, start, start+rows)
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://search.maven.org/solrsearch/select?q=g:%s+AND+a:%s&core=gav&rows=%d&start=%d&wt=json", artifact.GroupID, artifact.ArtifactID, rows, start), nil)
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

	var resJSON VersionSearchResponse
	err = json.NewDecoder(res.Body).Decode(&resJSON)
	if err != nil {
		return nil, err
	}

	gavs := make([]GAV, 0)
	for i := 0; i < len(resJSON.Response.Docs); i++ {
		doc := resJSON.Response.Docs[i]
		if contains(doc.EC, "-cyclonedx.json") {
			gavs = append(gavs, GAV{
				GroupID:    doc.GroupID,
				ArtifactID: doc.ArtifactID,
				Version:    doc.Version,
			})
		}
	}

	return gavs, nil
}

func downloadSBOM(gav GAV, minComponents int, outputDir string) error {
	log.Printf("downloading sbom for %s", gav)
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

	componentCount := 0
	if sbom.Components != nil {
		componentCount = len(*sbom.Components)
	}
	if componentCount < minComponents {
		log.Printf("discarding sbom for %s because it has too few components (%d/%d)", gav, componentCount, minComponents)
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

func contains(haystack []string, needle string) bool {
	for _, candidate := range haystack {
		if candidate == needle {
			return true
		}
	}

	return false
}
