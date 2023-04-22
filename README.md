# cdx-central

*CLI utility to download public CycloneDX SBOMs from Maven Central*

## Installation

```shell
go install -v github.com/nscuro/cdx-central@latest
```

## Usage

```
Usage of cdx-central:
  -min-components int
        Minimum number of components in an SBOM (default 10)
  -output string
        Output directory (default ".")
```

> **Note**  
> Currently only the SBOM for each artifact's *latest* version will be downloaded.

### Example

```shell
mkdir -p sboms
cdx-central -min-components 50 -output ./sboms
```
