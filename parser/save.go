// Copyright (c) 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

package parser

import (
	"fmt"
	"io"
	"os"

	spdx_json "github.com/spdx/tools-golang/json"
	spdx_common "github.com/spdx/tools-golang/spdx/common"
	"github.com/spdx/tools-golang/spdx/v2_2"
	spdx "github.com/spdx/tools-golang/spdx/v2_2"
	"golang.org/x/exp/slices"

	"github.com/spdx/tools-golang/tvsaver"
)

func Save(doc *Document, composableDocs []*Document, output string, outFormat string) error {
	output = updateFileExtension(output, outFormat)

	w, err := os.Create(output)
	if err != nil {
		fmt.Printf("error while opening %v for writing: %v\n", output, err)
		return err
	}
	defer w.Close()

	// It's not necessary for the composed doc to
	// contain all merged documents as Files
	doc = cleanDocumentFileData(doc)

	updateRelationships(doc, composableDocs)

	for _, cdoc := range composableDocs {
		if cdoc != nil {
			AppendComposableDocument(doc, cdoc, w, outFormat)
		}
	}

	switch outFormat {
	case "tv":
		err = tvsaver.Save2_2(doc.SPDXDocRef, w)
	case "json":
		err = spdx_json.Save2_2(doc.SPDXDocRef, w)
	default:
		fmt.Printf("warn: %s is not proper output format; saving to default\n", outFormat)
		err = tvsaver.Save2_2(doc.SPDXDocRef, w)
	}
	if err != nil {
		fmt.Printf("error while saving %v: %v\n", output, err)
		return err
	}
	return nil
}

// RenderComposableDocument processes a composable document
// and renders it to the composed document
func AppendComposableDocument(res *Document, cdoc *Document, w io.Writer, outFormat string) {

	res.SPDXDocRef.Annotations = append(res.SPDXDocRef.Annotations, cdoc.SPDXDocRef.Annotations...)
	res.SPDXDocRef.ExternalDocumentReferences = append(res.SPDXDocRef.ExternalDocumentReferences, cdoc.SPDXDocRef.ExternalDocumentReferences...)
	res.SPDXDocRef.Files = append(res.SPDXDocRef.Files, cdoc.SPDXDocRef.Files...)
	res.SPDXDocRef.OtherLicenses = append(res.SPDXDocRef.OtherLicenses, cdoc.SPDXDocRef.OtherLicenses...)
	res.SPDXDocRef.Packages = append(res.SPDXDocRef.Packages, cdoc.SPDXDocRef.Packages...)
	res.SPDXDocRef.Relationships = append(res.SPDXDocRef.Relationships, cdoc.SPDXDocRef.Relationships...)
	res.SPDXDocRef.Reviews = append(res.SPDXDocRef.Reviews, cdoc.SPDXDocRef.Reviews...)
	res.SPDXDocRef.Snippets = append(res.SPDXDocRef.Snippets, cdoc.SPDXDocRef.Snippets...)
}

func cleanDocumentFileData(doc *Document) *Document {
	doc.SPDXDocRef.Files = []*spdx.File{}

	for i := range doc.SPDXDocRef.Packages {
		doc.SPDXDocRef.Packages[i].Files = []*spdx.File{}
	}

	return doc
}

// Note: different generators mark the root package differently. for some, the document itself is the root package
// for others, it is defined by a relationship of DESCRIBES, also there should be a match between the documentName/name to a package
// This is also defined differently, some put the name only, others put name+version.
func getRootPackageIndex(doc *Document) (int, int) {
	j := -1

	// TODO: add documentDescribes on root
	// Note: only available on 0.5.0-rc spdx/tools-golang
	rls := doc.SPDXDocRef.Relationships
	reID := spdx_common.ElementID("DOCUMENT") // by default, if no DESCRIBES relationship exist, the document is the root package
	for i, r := range rls {
		if r.Relationship == "DESCRIBES" && r.RefA.ElementRefID == "DOCUMENT" {
			reID = r.RefB.ElementRefID
			j = i
		}
	}

	var i int
	if reID == "DOCUMENT" {
		name := doc.SPDXDocRef.DocumentName
		i = slices.IndexFunc(doc.SPDXDocRef.Packages, func(p *v2_2.Package) bool {
			// exact match
			if p.PackageName == name {
				return true
			}
			// filesystem added /
			if p.PackageName == fmt.Sprintf("%s/", name) {
				return true
			}
			// name-version
			if fmt.Sprintf("%s-%s", p.PackageName, p.PackageVersion) == name {
				return true
			}

			return false
		})

	} else {
		i = slices.IndexFunc(doc.SPDXDocRef.Packages, func(p *v2_2.Package) bool {
			return p.PackageSPDXIdentifier == reID
		})
	}

	return i, j
}

func updateRelationships(doc *Document, composableDocs []*Document) (*Document, []*Document) {
	for _, cdoc := range composableDocs {
		i, j := getRootPackageIndex(cdoc)
		var rootPkg *spdx.Package
		if i >= 0 {
			rootPkg = cdoc.SPDXDocRef.Packages[i]
		}
		if rootPkg == nil {
			rootPkg = &spdx.Package{
				PackageName:           cdoc.SPDXDocRef.DocumentName,
				PackageSPDXIdentifier: spdx_common.MakeDocElementID("", cdoc.SPDXDocRef.DocumentName).ElementRefID,
			}
			cdoc.SPDXDocRef.Packages = append([]*spdx.Package{rootPkg}, cdoc.SPDXDocRef.Packages...)

			for _, p := range cdoc.SPDXDocRef.Packages {
				newRelationship := &spdx.Relationship{
					RefA:         spdx_common.MakeDocElementID("", string(rootPkg.PackageSPDXIdentifier)),
					RefB:         spdx_common.MakeDocElementID("", string(p.PackageSPDXIdentifier)),
					Relationship: "DEPENDS_ON",
				}
				doc.SPDXDocRef.Relationships = append(doc.SPDXDocRef.Relationships, newRelationship)
			}
		}

		if cdoc != nil && len(cdoc.SPDXDocRef.Packages) > 0 {
			elId := spdx_common.MakeDocElementID("", string(rootPkg.PackageSPDXIdentifier))
			newRelationship := &spdx.Relationship{
				RefA:         spdx_common.MakeDocElementID("", fmt.Sprintf("Package-%s", doc.SPDXDocRef.Packages[0].PackageName)),
				RefB:         elId,
				Relationship: "DEPENDS_ON",
			}
			doc.SPDXDocRef.Relationships = append(doc.SPDXDocRef.Relationships, newRelationship)
		}
		if cdoc != nil && len(cdoc.SPDXDocRef.Relationships) > 0 && j >= 0 {
			cdoc.SPDXDocRef.Relationships = slices.Delete(cdoc.SPDXDocRef.Relationships, j, j+1)
		}
	}

	return doc, composableDocs
}
