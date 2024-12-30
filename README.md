

# example

```go

package main

import (
	"context"
	"fmt"
	"github.com/hq0101/go-opencve"
)

func main() {
	const baseURL = "http://192.168.127.131"

	client, err := go-opencve.NewClient(baseURL, "admin", "1234567")
	if err != nil {
		panic(err)
	}

	resp, err := client.ListCVEs(context.Background(), map[string]string{"page": "10"})
	//resp, err := client.ListCVEs(context.Background(), nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("ListCVEs: ", resp.Results[0].CveID)

	cve, err := client.GetCVE(context.Background(), "CVE-2020-36703")
	if err != nil {
		panic(err)
	}
	fmt.Println("GetCVE: ", cve.CveID, cve.Title)

	organResp, err := client.ListOrganizations(context.Background(), map[string]string{"page": "1"})
	if err != nil {
		panic(err)
	}

	fmt.Println("ListOrganizations: ", organResp.Results[0].Name)

	organInfo, err := client.GetOrganization(context.Background(), "admin")
	if err != nil {
		panic(err)
	}
	fmt.Println("GetOrganization", organInfo.Name)

	projects, err := client.ListProjects(context.Background(), "admin", map[string]string{"page": "1"})
	if err != nil {
		panic(err)
	}
	fmt.Println("ListProjects", projects.Results[0].Name)

	projectInfo, err := client.GetProject(context.Background(), "admin", "default")
	if err != nil {
		panic(err)
	}
	fmt.Println("GetProject", projectInfo.Name)

	cves, err := client.ListProjectCVEs(context.Background(), "admin", "default", map[string]string{"page": "1"})
	if err != nil {
		panic(err)
	}
	fmt.Println("ListProjectCVEs", cves.Results[0].CveID)

	vendors, err := client.ListVendors(context.Background(), map[string]string{"page": "1"})
	if err != nil {
		panic(err)
	}
	fmt.Println("ListVendors", vendors.Results[0].Name)

	vendorInfo, err := client.GetVendor(context.Background(), "wordpress")
	if err != nil {
		panic(err)
	}

	fmt.Println("GetVendor", vendorInfo.Name)

	vendorCVES, err := client.ListVendorCVEs(context.Background(), "wordpress", map[string]string{"page": "1"})
	if err != nil {
		panic(err)
	}
	fmt.Println("ListVendorCVEs", vendorCVES.Results[0].CveID)

	products, err := client.ListProducts(context.Background(), "wordpress", map[string]string{"page": "1"})
	if err != nil {
		panic(err)
	}
	fmt.Println("ListProducts", products.Results[1].Name)

	productInfo, err := client.GetProduct(context.Background(), "wordpress", "adserve")
	if err != nil {
		panic(err)
	}
	fmt.Println("GetProduct", productInfo.Name)

	productCVES, err := client.ListProductCVEs(context.Background(), "wordpress", "adserve", map[string]string{"page": "1"})
	if err != nil {
		panic(err)
	}
	fmt.Println("ListProductCVEs", productCVES.Results[0].CveID)

	weaknesses, err := client.ListWeaknesses(context.Background(), map[string]string{"page": "1"})
	if err != nil {
		panic(err)
	}
	fmt.Println("ListWeaknesses", weaknesses.Results[0].CWEID)

	weaknessInfo, err := client.GetWeakness(context.Background(), weaknesses.Results[0].CWEID)
	if err != nil {
		panic(err)
	}
	fmt.Println("GetWeakness", weaknessInfo.CWEID)

	weaknessCVES, err := client.ListWeaknessCVEs(context.Background(), weaknesses.Results[0].CWEID, map[string]string{"page": "1"})
	if err != nil {
		panic(err)
	}
	fmt.Println("ListWeaknessCVEs", weaknessCVES.Results[0].CveID)
}


```