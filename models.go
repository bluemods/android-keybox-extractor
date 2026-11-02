package main

import "encoding/xml"

type AndroidAttestation struct {
	XMLName          xml.Name        `xml:"AndroidAttestation"`
	NumberOfKeyboxes int             `xml:"NumberOfKeyboxes"`
	Keyboxes         []AndroidKeybox `xml:"Keybox"`
}

type AndroidKeybox struct {
	DeviceID string       `xml:"DeviceID,attr"`
	Keys     []AndroidKey `xml:"Key"`
}

type AndroidKey struct {
	Algorithm        string                  `xml:"algorithm,attr"`
	PrivateKey       AndroidPrivateKey       `xml:"PrivateKey"`
	CertificateChain AndroidCertificateChain `xml:"CertificateChain"`
}

type AndroidPrivateKey struct {
	Format string `xml:"format,attr"`
	Data   string `xml:",innerxml"`
}

type AndroidCertificateChain struct {
	NumberOfCertificates int                  `xml:"NumberOfCertificates"`
	Certificates         []AndroidCertificate `xml:"Certificate"`
}

type AndroidCertificate struct {
	Format string `xml:"format,attr"`
	Data   string `xml:",innerxml"`
}

type AndroidCRLList struct {
	Entries map[string]struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	} `json:"entries"`
}
