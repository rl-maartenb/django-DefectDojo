---
title: "ReversingLabs Spectra Assure"
toc_hide: true
---

# ReversingLabs Spectra Assure Parser

The Spectra Assure platform is a set of [ReversingLabs](https://www.reversinglabs.com/) solutions
primarily designed for software assurance and software supply chain security use-cases.
Spectra Assure products analyze compiled software packages,
their components and third-party dependencies to detect exposures,
reduce vulnerabilities, and eliminate threats before reaching production.

Every Spectra Assure analysis (software scan) produces a set of reports
and the overall CI status (pass or fail) for the analyzed software package.
The reports are created in multiple different formats,
with different level of detail and scope of information about the analysis results.
The official documentation describes all
[supported report formats](https://docs.secure.software/concepts/analysis-reports)
 in Spectra Assure.

**The primary purpose of this parser is extracting known vulnerabilities (CVEs/GHSA) that are present in the `components` and `dependencies` sections of the `rl-json` report.**

It also flags **secrets** flagged as fail and **malware threats**.


### File Types

The parser accepts only `report.rl.json` files
(the Spectra Assure [rl-json report](https://docs.secure.software/concepts/analysis-reports#rl-json)).

You can find instructions for exporting the `rl-json` report in the documentation of the Spectra Assure product you're using.

- [Spectra Assure CLI](https://docs.secure.software/cli/commands/report).
- [Spectra Assure Portal](https://docs.secure.software/api-reference/#tag/Version/operation/getVersionReport).
- [docker:rl-scanner](https://hub.docker.com/r/reversinglabs/rl-scanner).
- [docker:rl-scanner-cloud](https://hub.docker.com/r/reversinglabs/rl-scanner-cloud).


### Total Fields in Reversinglabs Spectra Assure rl-json

For the specification of the `rl-json` report, consult the official Spectra Assure documentation:

- [rl-json report schema](https://docs.secure.software/cli/rl-json-schema)
- [Analysis reports: rl-json](https://docs.secure.software/concepts/analysis-reports#rl-json).


### Field Mapping Details


#### Title

##### Component

For a component, the title includes:

- the type: `Component`
- the `purl` of the `Component` if present; otherwise name and version
- the first 8 characters of the component's sha256


##### Dependency

For a dependency, the title includes:

- the type: `Dependency`
- the `purl` of the `Dependency` if present; otherwise name and version
- the first 8 characters of the sha256 of the component the dependency was found in

The short sha256 is there because one name can stand for several different binaries:
an installer may ship a build per language, all with the same name and the same install path.
Without it those findings would be identical rows in the findings list.



#### Description

##### Component

For a component, the description repeats the information from the [title](#title) and includes the SHA256 hash of the component.

The SHA256 is included because sometimes a file scan may have multiple items with the same name and version,
but with different hashes.
Typically this happens with multi-language Windows installer packages.


##### Dependency

For a dependency, the description repeats the information from the [title](#title)
and includes the component path, `component-name` and `component-hash`.
For duplicates, the description includes an additional line showing the title and component of each duplicate.



#### Vulnerabilities

For vulnerabilities, the following information is retrieved:

- the CVE unique ID
- CVSS version
- CVSS base score

From the CVSS base score, we map the severity into:

- Info
- Low
- Medium
- High
- Critical

If no mapping is matched, the default severity is `Info`.


##### Notes

- No endpoints are created.
- With `V3_FEATURE_LOCATIONS` enabled, each CVE finding whose package has a purl gets one `dependency` location
  naming the vulnerable package (for a vulnerable dependency, the dependency itself, not the component containing it)
  and the path of the component it was found in. Policy violation findings carry no package, so they get no location.
- Deduplication uses the `hash_code` algorithm on `unique_id_from_tool`, `component_name` and `component_version`.
  `unique_id_from_tool` is the CVE (or `<category>-<rule_id>` for a policy violation) plus the sha256 of the
  component file it was found in, e.g. `CVE-2016-9840/sha256:0c0d54b2...`. A different sha256 is a different binary,
  so it is a different finding, even under the same name and path. Without a sha256 the component path is used.
- Within one report, the same issue on the same binary at a second path is merged into one finding:
  the number of occurrences is incremented and the extra path is listed in the description.


### Sample Scan Data or Unit Tests

- [Sample Scan Data Folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/reversinglabs_spectraassure)


### Link To Tool

- [Spectra Assure Cli](https://docs.secure.software/cli/)
- [Spectra Assure Portal](https://docs.secure.software/portal/)
- [docker:rl-scanner](https://docs.secure.software/cli/integrations/docker-image)
- [docker:rl-scanner-cloud](https://docs.secure.software/portal/docker-image)
